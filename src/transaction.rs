// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::DetourError;
use crate::HookKind;
use crate::alloc::{Trampoline, TrampolineAlloc};
use crate::disasm;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::{CONTEXT, GetThreadContext, SetThreadContext};
use windows_sys::Win32::System::Threading::*;

/// Stack slots per tracked thread a commit reserves for redirected return
/// addresses, before any thread is suspended. A commit needing more fails.
const STACK_REDIRECTS_PER_THREAD: usize = 512;

/// Upper bound on the stack bytes read per thread when redirecting return
/// addresses.
const MAX_STACK_SCAN_BYTES: usize = 32 * 1024 * 1024;

#[cfg(target_arch = "x86_64")]
const CONTEXT_FLAGS: u32 = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_ALL_AMD64;

#[cfg(target_arch = "x86")]
const CONTEXT_FLAGS: u32 = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_ALL_X86;

#[cfg(target_arch = "x86_64")]
const MANAGED_GATEWAY_LEN: usize = 14;

#[cfg(target_arch = "x86")]
const MANAGED_GATEWAY_LEN: usize = 5;

/// Main struct to manage a detour transaction, which can include multiple hooks
/// - `Relative5` is a 5-byte relative jump `E9 xx xx xx xx` that can be used when the detour target is within +/- 2GB of the hook site.
/// - `Absolute14` is a 14-byte absolute jump `FF 25 00 00 00 00 [8-byte address]` that can be used when the detour target is further than +/- 2GB away from the hook site __(x64 only)__.
#[derive(Clone, Copy, Debug)]
pub enum JumpType {
    Relative5,
    Absolute14,
}

#[derive(Debug)]
struct RedirectMap {
    old_instruction_offsets: Vec<u32>,
    new_instruction_offsets: Vec<u32>,
}

/// Describes what kind of code location an inline hook is attached to.
///
/// This is used to keep managed gateway registration in sync across
/// hook, rehook, and unhook operations.
#[derive(Debug)]
enum TargetKind {
    /// A regular inline hook target.
    ///
    /// Normal targets are patched by stealing and relocating instructions
    /// from the original code region.
    Normal,

    /// A managed gateway stub created by NeoHook.
    ///
    /// Managed gateways act as chainable jump stubs. When such a target is
    /// hooked again, the old gateway must be removed from the managed gateway
    /// registry and restored on unhook.
    ManagedGateway,
}

/// Prepared metadata for a pending inline hook.
///
/// This contains everything needed to install an inline hook during
/// [`TransactionCore::commit`], including the target and detour addresses,
/// trampoline allocation, stolen byte information, and the original bytes
/// required for rollback or unhook.
pub struct InlineData {
    pub target: *mut u8,
    pub detour: *const u8,
    pub trampoline: Trampoline,
    pub redirect_base: *mut u8,
    pub stolen_len: usize,
    pub jump_type: JumpType,
    pub orig_bytes: Vec<u8>,
    target_kind: TargetKind,
    redirect_map: Option<RedirectMap>,
}

/// Enum used internally by [`TransactionCore`] to represent hooks that are
/// queued but not yet installed.
pub enum PendingHook {
    Inline(InlineData),
    Iat {
        module: HMODULE,
        target_dll: String,
        target_func: String,
        detour: *const u8,
        /// Address of the import slot, resolved by `attach_iat`.
        slot: usize,
    },
    Eat {
        module: HMODULE,
        target_func: String,
        detour: *const u8,
        /// Address of the export slot, resolved by `attach_eat`.
        slot: usize,
    },
    Vtable {
        vtable: *mut *mut u8,
        index: usize,
        detour: *const u8,
    },
    VtableInstance {
        object_vptr: *mut *mut u8,
        vtable_len: usize,
        index: usize,
        detour: *const u8,
    },
    Detach(DetachTarget),
}

#[derive(Clone, Copy)]
pub enum DetachTarget {
    HookPtr(*mut Hook),
    HandleIndex {
        handle: *mut core::ffi::c_void,
        index: usize,
    },
}

#[derive(Clone, Copy)]
struct AppliedDetach {
    target: DetachTarget,
    was_enabled: bool,
}

/// Represents an installed detour managed by NeoHook.
///
/// A hook is returned from [`TransactionCore::commit`] and stays active until
/// it is explicitly unhooked or dropped.
#[derive(Debug)]
pub enum Hook {
    Inline(InlineHook),
    Iat(IatHook),
    Eat(EatHook),
    Vtable(VtableHook),
    VtableInstance(VtableInstanceHook),
}

impl Hook {
    /// Returns the original function pointer associated with this hook.
    ///
    /// For inline hooks, this is the trampoline entry managed by NeoHook.
    /// For IAT hooks, this is the original imported function pointer that was
    /// stored in the import table before patching.
    pub fn original_ptr(&self) -> *const u8 {
        match self {
            Hook::Inline(h) => h.original_ptr(),
            Hook::Iat(h) => h.original_ptr,
            Hook::Eat(h) => h.original_ptr(),
            Hook::Vtable(h) => h.original_ptr(),
            Hook::VtableInstance(h) => h.original_ptr(),
        }
    }

    /// Unhooks this detour restoring the original bytes or original ptr
    pub fn unhook(self) -> Result<(), DetourError> {
        match self {
            Hook::Inline(h) => h.unhook(),
            Hook::Iat(h) => h.unhook(),
            Hook::Eat(h) => h.unhook(),
            Hook::Vtable(h) => h.unhook(),
            Hook::VtableInstance(h) => h.unhook(),
        }
    }

    /// Returns whether the detour is currently active for this hook.
    pub fn is_enabled(&self) -> bool {
        match self {
            Hook::Inline(h) => h.is_enabled(),
            Hook::Iat(h) => h.is_enabled(),
            Hook::Eat(h) => h.is_enabled(),
            Hook::Vtable(h) => h.is_enabled(),
            Hook::VtableInstance(h) => h.is_enabled(),
        }
    }

    /// Re-installs the detour after a [`Self::disable`], without rebuilding the
    /// hook. Cheaper than a full unhook/rehook cycle.
    pub fn enable(&mut self) -> Result<(), DetourError> {
        match self {
            Hook::Inline(h) => h.enable(),
            Hook::Iat(h) => h.enable(),
            Hook::Eat(h) => h.enable(),
            Hook::Vtable(h) => h.enable(),
            Hook::VtableInstance(h) => h.enable(),
        }
    }

    /// Temporarily restores the original code/pointer while keeping the hook
    /// installed, so it can be re-enabled later with [`Self::enable`].
    pub fn disable(&mut self) -> Result<(), DetourError> {
        match self {
            Hook::Inline(h) => h.disable(),
            Hook::Iat(h) => h.disable(),
            Hook::Eat(h) => h.disable(),
            Hook::Vtable(h) => h.disable(),
            Hook::VtableInstance(h) => h.disable(),
        }
    }

    pub(crate) fn detach_prepare(&mut self) -> Result<bool, DetourError> {
        let was_enabled = self.is_enabled();
        if was_enabled {
            self.disable()?;
        }
        Ok(was_enabled)
    }

    pub(crate) fn detach_rollback(&mut self, was_enabled: bool) -> Result<(), DetourError> {
        if was_enabled {
            self.enable()?;
        }
        Ok(())
    }

    pub(crate) fn detach_finalize(&mut self) {
        match self {
            Hook::Inline(h) => h.detach_finalize(),
            Hook::Iat(h) => h.detach_finalize(),
            Hook::Eat(h) => h.detach_finalize(),
            Hook::Vtable(h) => h.detach_finalize(),
            Hook::VtableInstance(h) => h.detach_finalize(),
        }
    }
}

/// Helper struct to manage the allocation of trampolines, which are used for inline hooks.
///
/// Hooks chained on this hook's gateway may outlive it. Dropping it first
/// restores the target, so calls run the original function and bypass the
/// chained hooks; its gateway memory stays allocated until the last of them is
/// dropped, so their unhook never writes into released memory.
#[derive(Debug)]
pub struct InlineHook {
    pub target: *mut u8,
    pub trampoline: Trampoline,
    pub stolen_len: usize,
    pub orig_bytes: Vec<u8>,
    pub jump_type: JumpType,
    active: bool,
    target_kind: TargetKind,
    /// The exact bytes written into the target to install the jump to the
    /// detour. Kept so the hook can be re-enabled after [`Self::disable`].
    patch_bytes: Vec<u8>,
    /// Whether the detour jump is currently installed at the target.
    enabled: bool,
    /// Whether the commit published this hook's patched range, which
    /// [`Self::release`] withdraws again once the target is restored.
    published: bool,
}

impl InlineHook {
    /// Returns the original function pointer for this inline hook, which is the address of the trampoline.
    pub fn original_ptr(&self) -> *const u8 {
        // .ptr is  *mut u8, we cast to *const u8
        self.trampoline.ptr as *const u8
    }

    /// Returns whether the detour is currently installed at the target.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Temporarily restores the original bytes at the target without releasing
    /// the trampoline, so the hook can later be re-enabled with [`Self::enable`].
    ///
    /// This rewrites the target in place and does **not** suspend or redirect
    /// other threads, so it should be toggled at a point where the target is not
    /// concurrently executing its first instructions.
    pub fn disable(&mut self) -> Result<(), DetourError> {
        if !self.enabled {
            return Ok(());
        }
        Self::patch_target(self.target, &self.orig_bytes)?;
        self.enabled = false;
        Ok(())
    }

    /// Re-installs the detour jump at the target after a [`Self::disable`].
    ///
    /// Like [`Self::disable`], this rewrites the target in place without thread
    /// redirection. Fails with [`DetourError::InvalidParameter`] once the hook
    /// has been detached.
    pub fn enable(&mut self) -> Result<(), DetourError> {
        if !self.active {
            return Err(DetourError::InvalidParameter);
        }
        if self.enabled {
            return Ok(());
        }
        Self::patch_target(self.target, &self.patch_bytes)?;
        self.enabled = true;
        Ok(())
    }

    fn patch_target(target: *mut u8, bytes: &[u8]) -> Result<(), DetourError> {
        if target.is_null() || bytes.is_empty() {
            return Err(DetourError::InvalidParameter);
        }
        // Also runs inside a commit's suspend window (detach, rollback), so it
        // must not allocate; the lock is already held there.
        if with_code_lock(|| unsafe {
            crate::mem::write_code_bytes(target, bytes.as_ptr(), bytes.len())
        }) {
            Ok(())
        } else {
            Err(DetourError::RelocationFailed)
        }
    }

    /// Unhooks this inline hook by restoring the original bytes at the target address.
    pub fn unhook(mut self) -> Result<(), DetourError> {
        if !self.active {
            return Ok(());
        }
        with_code_lock(|| {
            self.perform_unhook()?;
            self.release();
            unregister_managed_gateway(self.trampoline.ptr);
            Ok::<(), DetourError>(())
        })?;
        self.active = false;

        Ok(())
    }

    fn perform_unhook(&self) -> Result<(), DetourError> {
        // parameter validation
        if self.target.is_null() || self.orig_bytes.len() != self.stolen_len {
            return Err(DetourError::InvalidParameter);
        }

        // Per-page protection save/restore, cache flush, no allocation.
        let written = unsafe {
            crate::mem::write_code_bytes(self.target, self.orig_bytes.as_ptr(), self.stolen_len)
        };
        if !written {
            return Err(DetourError::RelocationFailed);
        }
        Ok(())
    }

    /// Withdraws what the commit published for this hook once its target holds
    /// the original bytes again. Runs under the transaction lock, never inside
    /// a suspend window.
    fn release(&mut self) {
        if !self.published {
            return;
        }
        self.published = false;
        unregister_live_patch(self.target);

        // Restoring a managed gateway makes it chainable again, unless its
        // owner was dropped meanwhile; the last dependent of such a gateway
        // releases its memory.
        if matches!(self.target_kind, TargetKind::ManagedGateway) {
            let (owner_alive, orphan) = remove_gateway_dependent(self.target);
            if owner_alive {
                register_managed_gateway(self.target);
            }
            if let Some((ptr, size)) = orphan {
                crate::reclaim::retire(ptr as *mut u8, size);
            }
        }
    }

    fn detach_finalize(&mut self) {
        with_code_lock(|| {
            if self.enabled {
                let _ = self.disable();
            }
            self.release();
            unregister_managed_gateway(self.trampoline.ptr);
        });
        self.active = false;
        self.enabled = false;
    }
}

impl Drop for InlineHook {
    fn drop(&mut self) {
        with_code_lock(|| {
            if self.active {
                // auto unhook when dropped, best effort, ignore errors
                let _ = self.perform_unhook();
            }
            self.release();
            unregister_managed_gateway(self.trampoline.ptr);

            // Hooks chained on the gateway still restore their bytes into it,
            // so it is retired by the last of them instead of here.
            if orphan_chained_gateway(self.trampoline.ptr, self.trampoline.size) {
                self.trampoline.ptr = std::ptr::null_mut();
            }
        });
    }
}

#[derive(Debug)]
pub struct IatHook {
    pub module: HMODULE,
    pub dll_name: String,
    pub func_name: String,
    pub original_ptr: *mut u8,
    /// The import slot this hook claimed (see [`claim_table_slot`]).
    slot: usize,
    /// Whether the claim on `slot` is still held.
    claimed: bool,
    active: bool,
    /// Detour pointer currently written into the import slot when enabled.
    detour: *mut u8,
    /// Whether the import slot currently points at the detour.
    enabled: bool,
}

impl IatHook {
    pub fn unhook(mut self) -> Result<(), DetourError> {
        if !self.active {
            return Ok(());
        }
        self.perform_unhook()?;
        self.active = false;

        Ok(())
    }

    /// Returns whether the import slot currently points at the detour.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Restores the original import pointer without forgetting the detour, so
    /// the hook can be re-enabled later.
    pub fn disable(&mut self) -> Result<(), DetourError> {
        if !self.enabled {
            return Ok(());
        }
        unsafe {
            crate::iat::IatHook::hook_import(
                self.module,
                &self.dll_name,
                &self.func_name,
                self.original_ptr,
            )?;
        }
        self.enabled = false;
        Ok(())
    }

    /// Re-points the import slot at the detour after a [`Self::disable`].
    /// Fails with [`DetourError::InvalidParameter`] once the hook has been
    /// detached.
    pub fn enable(&mut self) -> Result<(), DetourError> {
        if !self.active {
            return Err(DetourError::InvalidParameter);
        }
        if self.enabled {
            return Ok(());
        }
        unsafe {
            crate::iat::IatHook::hook_import(
                self.module,
                &self.dll_name,
                &self.func_name,
                self.detour,
            )?;
        }
        self.enabled = true;
        Ok(())
    }

    fn perform_unhook(&self) -> Result<(), DetourError> {
        unsafe {
            crate::iat::IatHook::hook_import(
                self.module,
                &self.dll_name,
                &self.func_name,
                self.original_ptr,
            )?;
            Ok(())
        }
    }

    fn detach_finalize(&mut self) {
        let restored = !self.enabled || self.disable().is_ok();
        self.active = false;
        self.enabled = false;
        // A detached hook frees its slot for the next hook right away.
        if restored && self.claimed {
            release_table_slot(self.slot);
            self.claimed = false;
        }
    }
}

impl Drop for IatHook {
    fn drop(&mut self) {
        // auto unhook when dropped, best effort. A slot still pointing at the
        // detour stays claimed, so no later hook stacks on it.
        if self.claimed && (!self.active || self.perform_unhook().is_ok()) {
            release_table_slot(self.slot);
        }
    }
}

/// Installed Export Address Table (EAT) hook.
///
/// Patches a single export slot in a module's EAT so consumers that resolve the
/// export *after* installation (e.g. via `GetProcAddress`) are redirected to the
/// detour. Like [`IatHook`], it changes a lookup table rather than the function
/// body, so code that already cached the resolved address is unaffected.
///
/// On x86_64 an out-of-range detour is reached through a small owned jump stub,
/// which is released when the hook is dropped or unhooked.
#[derive(Debug)]
pub struct EatHook {
    pub module: HMODULE,
    pub func_name: String,
    slot_ptr: *mut u32,
    original_rva: u32,
    detour_rva: u32,
    original_ptr: *mut u8,
    /// Jump stub keeping an out-of-range detour reachable. Only held so its
    /// `Drop` releases the allocation when the hook goes away.
    #[allow(dead_code)]
    stub: Option<crate::alloc::Trampoline>,
    /// Whether this hook still holds the claim on its export slot (see
    /// [`claim_table_slot`]).
    claimed: bool,
    active: bool,
    /// Whether the export slot currently points at the detour.
    enabled: bool,
}

impl EatHook {
    /// Returns the resolved address of the original export.
    pub fn original_ptr(&self) -> *const u8 {
        self.original_ptr
    }

    /// Returns whether the export slot currently points at the detour.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Restores the original export RVA without releasing the stub, so the hook
    /// can be re-enabled later.
    pub fn disable(&mut self) -> Result<(), DetourError> {
        if !self.enabled {
            return Ok(());
        }
        unsafe { crate::eat::EatHook::write_export_rva(self.slot_ptr, self.original_rva)? };
        self.enabled = false;
        Ok(())
    }

    /// Re-points the export slot at the detour after a [`Self::disable`].
    /// Fails with [`DetourError::InvalidParameter`] once the hook has been
    /// detached.
    pub fn enable(&mut self) -> Result<(), DetourError> {
        if !self.active {
            return Err(DetourError::InvalidParameter);
        }
        if self.enabled {
            return Ok(());
        }
        unsafe { crate::eat::EatHook::write_export_rva(self.slot_ptr, self.detour_rva)? };
        self.enabled = true;
        Ok(())
    }

    /// Unhooks this EAT hook by restoring the original export RVA. The jump stub
    /// (if any) is released when the guard is dropped.
    pub fn unhook(mut self) -> Result<(), DetourError> {
        if !self.active {
            return Ok(());
        }
        self.perform_unhook()?;
        self.active = false;
        Ok(())
    }

    fn perform_unhook(&self) -> Result<(), DetourError> {
        unsafe { crate::eat::EatHook::write_export_rva(self.slot_ptr, self.original_rva)? };
        Ok(())
    }

    fn detach_finalize(&mut self) {
        let restored = !self.enabled || self.disable().is_ok();
        self.active = false;
        self.enabled = false;
        // A detached hook frees its slot for the next hook right away.
        if restored && self.claimed {
            release_table_slot(self.slot_ptr as usize);
            self.claimed = false;
        }
    }
}

impl Drop for EatHook {
    fn drop(&mut self) {
        // auto unhook when dropped, best effort. A slot still pointing at the
        // detour stays claimed, so no later hook stacks on it.
        if self.claimed && (!self.active || self.perform_unhook().is_ok()) {
            release_table_slot(self.slot_ptr as usize);
        }
        // `stub` is released here via its own Drop, after the slot no longer
        // points at it.
    }
}

/// Installed VTable hook type used by transaction commits.
pub type VtableHook = crate::vtable::VTableHook;
/// Installed per-instance VTable hook type used by transaction commits.
pub type VtableInstanceHook = crate::vtable::VTableInstanceHook;

/// A diagnostic event recorded while the transaction may hold threads suspended.
///
/// The commit path cannot log as it goes: between the first `SuspendThread` and
/// the matching `ResumeThread`, taking the stdout lock can deadlock against a
/// suspended holder, and *formatting* is no safer - `format!` allocates, so it
/// can block on the heap lock or re-enter a hook the caller placed on the
/// allocator itself.
///
/// So the window records plain `Copy` data into a buffer whose capacity is
/// reserved before any thread is suspended, and [`TransactionCore::flush_debug_events`]
/// does the formatting and writing once every thread is running again.
#[cfg(feature = "debug-log")]
#[derive(Clone, Copy)]
enum DebugEvent {
    CommitStart {
        hooks: usize,
        threads: usize,
    },
    ContextReadFailed {
        thread: HANDLE,
    },
    IpRedirected {
        tid: u32,
        from: usize,
        to: usize,
    },
    StackRedirected {
        tid: u32,
        slot: usize,
        from: usize,
        to: usize,
    },
    RollbackIp {
        thread: HANDLE,
        to: u64,
    },
    CommitDone {
        hooks: usize,
    },
}

/// Events buffered per transaction before recording starts dropping them.
///
/// Sized for a redirect-heavy commit (one instruction-pointer event per thread
/// plus a handful of stack slots each); past that the count is reported instead,
/// because growing the buffer would allocate inside the suspend window.
#[cfg(feature = "debug-log")]
const DEBUG_EVENT_CAPACITY: usize = 512;

pub struct TransactionCore {
    // Threads tracked by `update_thread`. They are opened right away but only
    // suspended by `commit`, see `suspend_threads`.
    threads: Vec<HANDLE>,
    // Whether every handle in `threads` is currently suspended by us.
    threads_suspended: bool,
    pending_hooks: Vec<PendingHook>,
    is_pending: bool,
    redirected_threads: Vec<(HANDLE, u64)>, // for safety, we store the original RIP of redirected threads so we can restore it if needed
    redirected_stacks: Vec<(HANDLE, usize, usize)>, // for safety, we store the original stack pointer and size of redirected threads so we can restore it if needed
    // Process-wide transaction lock guard. Held from the first thread
    // suspension (or the start of commit) until threads are resumed, so two
    // transactions on different threads cannot suspend each other or patch
    // code concurrently. `None` while the transaction holds no lock.
    global_lock: Option<TransactionGuard>,
    // Diagnostics captured while threads may be suspended, flushed once they are
    // resumed. See `DebugEvent` for why nothing is formatted in the window.
    #[cfg(feature = "debug-log")]
    debug_events: Vec<DebugEvent>,
    #[cfg(feature = "debug-log")]
    debug_events_dropped: usize,
}

impl TransactionCore {
    /// Creates a new pending detour transaction.
    ///
    /// The transaction can collect inline and IAT hooks, suspend threads,
    /// and later apply all queued hooks atomically with [`Self::commit`].
    ///
    /// Any tracked resources are cleaned up automatically if the transaction
    /// is dropped while still pending.
    pub fn begin() -> Self {
        Self {
            threads: Vec::new(),
            threads_suspended: false,
            pending_hooks: Vec::new(),
            is_pending: true,
            redirected_threads: Vec::new(),
            redirected_stacks: Vec::new(),
            global_lock: None,
            // Reserved here, before the first suspension, so recording an event
            // later never has to allocate.
            #[cfg(feature = "debug-log")]
            debug_events: Vec::with_capacity(DEBUG_EVENT_CAPACITY),
            #[cfg(feature = "debug-log")]
            debug_events_dropped: 0,
        }
    }

    /// Acquires the process-wide transaction lock if this transaction does not
    /// already hold it.
    ///
    /// This is idempotent: calling it multiple times during a transaction keeps
    /// the single guard that was acquired first. The lock must be taken *before*
    /// any thread is suspended, otherwise two transactions could suspend each
    /// other and deadlock.
    fn acquire_global_lock(&mut self) {
        // A thread already inside `with_transaction_lock` keeps that hold.
        if self.global_lock.is_none() && !owns_transaction_lock() {
            self.global_lock = Some(lock_transaction());
        }
    }

    /// Opens and tracks the thread identified by `thread_id`. The thread is
    /// suspended while [`Self::commit`] patches code and resumed afterwards.
    ///
    /// Note: `thread_id` must be a Win32 thread ID, not a `HANDLE`.
    ///
    /// NeoHook opens the thread handle internally and owns it for the remainder of the transaction.
    ///
    /// The calling thread is ignored and will never be suspended. Invalid or
    /// inaccessible thread IDs are also ignored so they do not abort the
    /// transaction.
    ///
    /// # Errors
    ///
    /// Returns `Err(DetourError::NotStarted)` if the transaction is no longer
    /// pending.
    pub fn update_thread(&mut self, thread_id: u32) -> Result<(), DetourError> {
        if !self.is_pending {
            return Err(DetourError::NotStarted);
        }
        unsafe {
            if thread_id == 0 || thread_id == GetCurrentThreadId() {
                return Ok(());
            }

            let access_flags = THREAD_SUSPEND_RESUME
                | THREAD_GET_CONTEXT
                | THREAD_SET_CONTEXT
                | THREAD_QUERY_INFORMATION;

            let h_thread = OpenThread(access_flags, 0, thread_id);
            if h_thread.is_null() {
                // Ignore invalid thread IDs or inaccessible threads
                return Ok(());
            }

            // Take the process-wide lock before any thread can be suspended, so
            // a concurrent transaction can never freeze the thread that holds
            // the lock (which would deadlock).
            self.acquire_global_lock();

            self.threads.push(h_thread);
            Ok(())
        }
    }

    /// Tracks all threads in the current process except the calling thread, so
    /// [`Self::commit`] suspends them while it patches code.
    ///
    /// Thread IDs are collected, then each thread is opened internally. Threads
    /// that cannot be opened or suspended are skipped so that a single
    /// inaccessible thread does not abort the transaction.
    pub fn update_all_threads(&mut self) {
        let thread_ids = crate::threads::ThreadEnumerator::enumerate_process_threads();
        for tid in thread_ids {
            // Ignore per-thread failures so one inaccessible thread does not
            // abort the whole transaction.
            let _ = self.update_thread(tid);
        }
    }

    /// Queues an inline hook.
    ///
    /// On success, returns a trampoline pointer that can be used to call the
    /// original function.
    ///
    /// If the target is a managed gateway created by NeoHook, the hook is prepared
    /// using gateway chaining instead of normal instruction stealing and
    /// relocation.
    ///
    /// # Parameters
    ///
    /// - `target`: Address of the function or managed gateway to hook.
    /// - `detour`: Address of the detour function.
    ///
    /// # Errors
    ///
    /// Returns `Err(DetourError::NotStarted)` if the transaction is no longer
    /// pending.
    ///
    /// Returns an error if the target or detour pointer is invalid, if the stolen
    /// instruction sequence cannot be determined, or if trampoline allocation or
    /// relocation fails.
    ///
    /// Returns `Err(DetourError::InvalidParameter)` if the target function is
    /// shorter than the jump patch (it ends with `ret`, `jmp`, `ud2`, ... before
    /// the patch size is reached) and is not followed by enough `int3` / `nop`
    /// padding. Patching it would overwrite the code that follows, typically
    /// the next function.
    ///
    /// Returns `Err(DetourError::InvalidParameter)` if `target` is a managed
    /// gateway that an installed hook is already chained on; chain onto that
    /// hook's gateway instead.
    ///
    /// # Safety
    /// The caller must ensure that `target` and `detour` are valid pointers. NeoHook performs basic validation but does not guarantee that the pointers are valid or that the memory they point to is properly aligned or accessible. Invalid pointers may cause undefined behavior, including crashes.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn attach(&mut self, target: *mut u8, detour: *const u8) -> Result<*mut u8, DetourError> {
        self.attach_inner(target, detour, true)
    }

    /// Queues an inline hook at the **exact** `target` address, without first
    /// resolving leading jump stubs / import thunks.
    ///
    /// Entry-point hooking ([`Self::attach`]) follows thunks so a stub address
    /// resolves to the real function body. Mid-function / arbitrary-address
    /// detours must instead patch precisely where the caller asked, even if the
    /// bytes there happen to look like a jump. Used by [`crate::midhook`].
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub(crate) fn attach_exact(
        &mut self,
        target: *mut u8,
        detour: *const u8,
    ) -> Result<*mut u8, DetourError> {
        self.attach_inner(target, detour, false)
    }

    /// Applies the same-target rule to an inline hook already queued on
    /// `target`: the same detour reuses it, a different one is rejected.
    fn queued_inline(
        &self,
        target: *mut u8,
        detour: *const u8,
    ) -> Option<Result<*mut u8, DetourError>> {
        self.pending_hooks.iter().find_map(|pending| match pending {
            PendingHook::Inline(existing) if existing.target == target => {
                Some(if existing.detour == detour {
                    Ok(existing.trampoline.ptr)
                } else {
                    Err(DetourError::InvalidParameter)
                })
            }
            _ => None,
        })
    }

    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn attach_inner(
        &mut self,
        mut target: *mut u8,
        detour: *const u8,
        follow_thunks: bool,
    ) -> Result<*mut u8, DetourError> {
        if !self.is_pending {
            return Err(DetourError::NotStarted);
        }

        if target.is_null() || detour.is_null() {
            return Err(DetourError::InvalidParameter);
        }

        // If the target function is a managed gateway, we use a special hooking method that does not require disassembly or stolen bytes, as the gateway is designed to be overwritten with a jump to the trampoline. This allows us to hook methods that would otherwise be difficult or impossible to hook.
        // The trampoline will contain a stub that jumps to the original target after executing the detour, allowing for proper chaining of hooks
        //
        // A gateway carries at most one chained hook: once one is installed the
        // gateway holds its jump, and a second hook would either patch it again
        // or follow that jump into the chained detour. Chain onto the installed
        // hook's own gateway instead. Within one transaction the same-target
        // rule below applies.
        if follow_thunks && is_chained_gateway(target) {
            return Err(DetourError::InvalidParameter);
        }
        if follow_thunks && is_managed_gateway(target) {
            if let Some(queued) = self.queued_inline(target, detour) {
                return queued;
            }

            let previous_target = unsafe {
                read_managed_gateway_target(target as *const u8)
                    .ok_or(DetourError::InvalidParameter)?
            };

            let jump_type = {
                #[cfg(target_arch = "x86_64")]
                {
                    let rel = (detour as i64) - (target as i64) - 5;
                    if (i32::MIN as i64..=i32::MAX as i64).contains(&rel) {
                        JumpType::Relative5
                    } else {
                        JumpType::Absolute14
                    }
                }
                #[cfg(target_arch = "x86")]
                {
                    JumpType::Relative5
                }
            };

            let trampoline_handle = unsafe {
                TrampolineAlloc::alloc_nearby_trampoline(target, MANAGED_GATEWAY_LEN.max(64))
                    .ok_or(DetourError::AllocationFailed)?
            };

            let gateway = trampoline_handle.ptr;

            unsafe {
                write_managed_gateway_stub(gateway, previous_target);
            }

            let _ = trampoline_handle.make_rx();

            let data = InlineData {
                target,
                detour,
                trampoline: trampoline_handle,
                stolen_len: MANAGED_GATEWAY_LEN,
                jump_type,
                orig_bytes: unsafe {
                    std::slice::from_raw_parts(target as *const u8, MANAGED_GATEWAY_LEN).to_vec()
                },
                redirect_base: gateway,
                target_kind: TargetKind::ManagedGateway,
                redirect_map: None,
            };

            self.pending_hooks.push(PendingHook::Inline(data));
            return Ok(gateway);
        }

        // Entry-point hooks resolve leading jump stubs to the real function;
        // exact (mid-function) hooks must patch precisely where requested.
        if follow_thunks {
            target = unsafe { crate::detour_code_from_pointer(target.cast_const()) };
            if target.is_null() {
                return Err(DetourError::InvalidParameter);
            }
        }

        // Collision handling against hooks already queued in this transaction.
        //
        // Following jump thunks (above) can collapse several distinct entry
        // points onto one implementation - e.g. a CRT function and its `_o_*`
        // forwarder both resolve to the same body. Patching that one site twice
        // in a single commit overwrites the live code a second time and corrupts
        // it, so a duplicate must be caught here rather than queued.
        //
        // - Same resolved target *and* same detour: the second request is
        //   redundant. Return the existing gateway and skip the duplicate, so the
        //   site is patched exactly once. The caller still gets a usable
        //   original/gateway pointer and `commit` simply yields one hook for the
        //   pair (the returned `Vec` can therefore be shorter than the number of
        //   `attach` calls).
        // - Same target but a *different* detour: ambiguous within one
        //   transaction. Reject it - stacking several detours on one function is
        //   done by chaining onto the returned gateway, not by re-attaching the
        //   same target.
        if let Some(queued) = self.queued_inline(target, detour) {
            return queued;
        }

        // --- architecture ---

        // case A: 64-Bit (x86_64)
        // We check if the target is < 2GB away (Relative5) or further (Absolute14).
        #[cfg(target_arch = "x86_64")]
        let (jump_type, required_space) = {
            let rel = (detour as i64) - (target as i64) - 5;
            if (i32::MIN as i64..=i32::MAX as i64).contains(&rel) {
                (JumpType::Relative5, 5)
            } else {
                (JumpType::Absolute14, 14)
            }
        };

        // case B: 32-Bit (x86)
        // We can directly set the jump type to Relative5 for x86, because the address space is limited to 4GB.
        #[cfg(target_arch = "x86")]
        let (jump_type, required_space) = (JumpType::Relative5, 5);

        // ------------------------------------------

        let stolen_len = unsafe {
            disasm::Disassembler::get_instruction_len(target, required_space)
                .map_err(|_| DetourError::InvalidParameter)
        }?;

        // The stolen bytes must not overlap another inline hook, queued here or
        // already installed: one jump would be written over the other, or the
        // live jump relocated into this trampoline. `commit` checks installed
        // hooks again under the transaction lock.
        let overlaps_pending = self.pending_hooks.iter().any(|pending| {
            matches!(pending, PendingHook::Inline(existing)
                if ranges_overlap(existing.target as usize, existing.stolen_len, target as usize, stolen_len))
        });
        if overlaps_pending || overlaps_live_patch(target, stolen_len) {
            return Err(DetourError::InvalidParameter);
        }

        // MANAGED GATEWAYS FOR HOOK CHAINING
        let tramp_capacity: usize = 128;
        // The unwind data follows the code (see crate::unwind).
        let alloc_size = tramp_capacity + crate::unwind::UNWIND_AREA;
        let trampoline_handle = unsafe {
            // Allocate memory. rwx is required for the trampoline, we switch to rx later
            TrampolineAlloc::alloc_nearby_trampoline(target, alloc_size)
                .ok_or(DetourError::AllocationFailed)?
        };

        let gateway = trampoline_handle.ptr;
        let body = unsafe { gateway.add(MANAGED_GATEWAY_LEN) };

        let relocation = unsafe {
            disasm::Disassembler::relocate(target, body, stolen_len)
                .map_err(|_| DetourError::RelocationFailed)
        }?;

        let body_len = relocation.written_len;

        if MANAGED_GATEWAY_LEN + body_len > tramp_capacity {
            return Err(DetourError::RelocationFailed);
        }

        unsafe {
            write_managed_gateway_stub(gateway, body as *const u8);
            crate::unwind::register_relocated(
                target,
                gateway,
                tramp_capacity,
                MANAGED_GATEWAY_LEN,
                &relocation,
                stolen_len,
            );
        }

        let _ = trampoline_handle.make_rx();

        let data = InlineData {
            target,
            detour,
            trampoline: trampoline_handle,
            stolen_len,
            jump_type,
            orig_bytes: unsafe {
                std::slice::from_raw_parts(target as *const u8, stolen_len).to_vec()
            },
            redirect_base: body,
            target_kind: TargetKind::Normal,
            redirect_map: Some(RedirectMap {
                old_instruction_offsets: relocation.old_instruction_offsets,
                new_instruction_offsets: relocation.new_instruction_offsets,
            }),
        };

        self.pending_hooks.push(PendingHook::Inline(data));
        Ok(gateway)
    }

    /// Queues an IAT hook.
    ///
    /// The matching import entry is resolved immediately during preparation so the
    /// transaction can fail early if the requested import does not exist.
    ///
    /// The original imported function pointer becomes available through the
    /// installed [`Hook`] returned by [`Self::commit`].
    ///
    /// # Parameters
    ///
    /// - `h_module`: Base handle of the module whose import table should be patched.
    /// - `target_dll`: Name of the imported DLL to match.
    /// - `target_func`: Name of the imported function to match.
    /// - `detour`: Address of the detour function.
    ///
    /// # Errors
    ///
    /// Returns `Err(DetourError::NotStarted)` if the transaction is no longer
    /// pending.
    ///
    /// Returns an error if the module is invalid, if the import cannot be found,
    /// or if the IAT hook cannot be prepared.
    ///
    /// # Safety
    /// The caller must ensure that `h_module` is a valid module handle, that `target_dll` and `target_func` are valid strings corresponding to an import in the module's IAT, and that `detour` is a valid function pointer. NeoHook performs basic validation but does not guarantee that the parameters are valid or that the memory they point to is properly aligned or accessible. Invalid parameters may cause undefined behavior, including crashes.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn attach_iat(
        &mut self,
        h_module: HMODULE,
        target_dll: &str,
        target_func: &str,
        detour: *const u8,
    ) -> Result<(), DetourError> {
        if !self.is_pending {
            return Err(DetourError::NotStarted);
        }

        // Pointer validity checks
        unsafe {
            let mut mbi: windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION =
                std::mem::zeroed();
            let res = windows_sys::Win32::System::Memory::VirtualQuery(
                h_module as *const _,
                &mut mbi,
                std::mem::size_of::<windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION>(),
            );

            // If VirtualQuery fails, we return an error or if memory is not readable
            if res == 0
                || (mbi.Protect
                    & (windows_sys::Win32::System::Memory::PAGE_READONLY
                        | windows_sys::Win32::System::Memory::PAGE_READWRITE
                        | windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ
                        | windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE))
                    == 0
            {
                return Err(DetourError::InvalidParameter);
            }
        }

        // Check if we can find the import
        // if find_import_address returns None it means there is no such dll or function in the IAT, so we return an error

        let slot =
            unsafe { crate::iat::IatHook::find_import_address(h_module, target_dll, target_func)? }
                as usize;
        if self.table_slot_taken(slot) {
            return Err(DetourError::InvalidParameter);
        }

        // NOW WE CAN SAFELY PUSH THE HOOK TO THE PENDING LIST, THE COMMIT FUNCTION WILL TAKE CARE OF INSTALLING IT

        self.pending_hooks.push(PendingHook::Iat {
            module: h_module,
            target_dll: target_dll.to_string(),
            target_func: target_func.to_string(),
            detour,
            slot,
        });
        Ok(())
    }

    /// Registers an EAT (Export Address Table) hook to be installed when the
    /// transaction is committed.
    ///
    /// Redirects the named export of `h_module` to `detour`. Unlike an IAT hook,
    /// which only affects one caller module, this redirects every consumer that
    /// resolves the export *after* commit (e.g. through `GetProcAddress`).
    ///
    /// # Errors
    ///
    /// Returns `Err(DetourError::NotStarted)` if the transaction is no longer
    /// pending.
    ///
    /// Returns an error if the module is invalid, the export cannot be found, or
    /// the export is a forwarder (which has no code slot to redirect).
    ///
    /// # Safety
    /// The caller must ensure that `h_module` is a valid module handle, that
    /// `target_func` names an export of that module, and that `detour` is a
    /// valid function pointer with an ABI/signature compatible with the export.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn attach_eat(
        &mut self,
        h_module: HMODULE,
        target_func: &str,
        detour: *const u8,
    ) -> Result<(), DetourError> {
        if !self.is_pending {
            return Err(DetourError::NotStarted);
        }

        if h_module.is_null() || detour.is_null() {
            return Err(DetourError::InvalidParameter);
        }

        // Pointer validity check (mirrors attach_iat): the module base must be
        // readable before we attempt to parse its headers.
        unsafe {
            let mut mbi: windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION =
                std::mem::zeroed();
            let res = windows_sys::Win32::System::Memory::VirtualQuery(
                h_module as *const _,
                &mut mbi,
                std::mem::size_of::<windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION>(),
            );

            if res == 0
                || (mbi.Protect
                    & (windows_sys::Win32::System::Memory::PAGE_READONLY
                        | windows_sys::Win32::System::Memory::PAGE_READWRITE
                        | windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ
                        | windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE))
                    == 0
            {
                return Err(DetourError::InvalidParameter);
            }
        }

        // Validate up front that the export exists and is hookable (not a
        // forwarder), so we fail before any thread is suspended.
        let slot =
            unsafe { crate::eat::EatHook::find_export_address(h_module, target_func)? } as usize;
        if self.table_slot_taken(slot) {
            return Err(DetourError::InvalidParameter);
        }

        self.pending_hooks.push(PendingHook::Eat {
            module: h_module,
            target_func: target_func.to_string(),
            detour,
            slot,
        });
        Ok(())
    }

    /// Queues a VTable hook for a specific slot.
    ///
    /// The slot is validated and patched during commit. The previous slot value
    /// is returned through the installed [`Hook`] and can be used to restore
    /// the original method.
    ///
    /// # Errors
    ///
    /// Returns `Err(DetourError::NotStarted)` if the transaction is not pending.
    ///
    /// Returns `Err(DetourError::InvalidParameter)` if `vtable`/`detour` is
    /// null or if the slot address cannot be queried as readable memory.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `vtable.add(index)` points to a valid slot
    /// and that `detour` has a compatible ABI/signature for that virtual method.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn attach_vtable(
        &mut self,
        vtable: *mut *mut u8,
        index: usize,
        detour: *const u8,
    ) -> Result<*mut u8, DetourError> {
        if !self.is_pending {
            return Err(DetourError::NotStarted);
        }

        if vtable.is_null() || detour.is_null() {
            return Err(DetourError::InvalidParameter);
        }

        let slot = unsafe { vtable.add(index) };

        unsafe {
            let mut mbi: windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION =
                std::mem::zeroed();
            let res = windows_sys::Win32::System::Memory::VirtualQuery(
                slot as *const _,
                &mut mbi,
                std::mem::size_of::<windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION>(),
            );

            if res == 0
                || (mbi.Protect
                    & (windows_sys::Win32::System::Memory::PAGE_READONLY
                        | windows_sys::Win32::System::Memory::PAGE_READWRITE
                        | windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ
                        | windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE))
                    == 0
            {
                return Err(DetourError::InvalidParameter);
            }
        }

        if self.table_slot_taken(slot as usize) {
            return Err(DetourError::InvalidParameter);
        }

        let original_ptr = unsafe { *slot };

        self.pending_hooks.push(PendingHook::Vtable {
            vtable,
            index,
            detour,
        });

        Ok(original_ptr)
    }

    /// Queues a per-instance VTable hook.
    ///
    /// The object's VTable is cloned and the clone is patched so only this
    /// instance observes the detour.
    ///
    /// # Errors
    ///
    /// Returns `Err(DetourError::NotStarted)` if the transaction is no longer
    /// pending.
    ///
    /// Returns an error if the object pointer, slot index, VTable length, or
    /// detour pointer is invalid, or if allocating the cloned VTable fails.
    ///
    /// # Safety
    /// The caller must ensure `object_vptr` points to the object's vptr field
    /// and that `vtable_len` covers the complete VTable.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn attach_vtable_instance(
        &mut self,
        object_vptr: *mut *mut u8,
        index: usize,
        vtable_len: usize,
        detour: *const u8,
    ) -> Result<*mut u8, DetourError> {
        if !self.is_pending {
            return Err(DetourError::NotStarted);
        }

        if object_vptr.is_null() || detour.is_null() || vtable_len == 0 || index >= vtable_len {
            return Err(DetourError::InvalidParameter);
        }

        let original_vtable = unsafe { *object_vptr };
        if original_vtable.is_null() {
            return Err(DetourError::InvalidParameter);
        }

        let queued = self.pending_hooks.iter().any(|hook| {
            matches!(hook, PendingHook::VtableInstance { object_vptr: queued, index: queued_index, .. }
                if *queued == object_vptr && *queued_index == index)
        });
        if queued || crate::vtable::instance_slot_hooked(object_vptr, index) {
            return Err(DetourError::InvalidParameter);
        }

        let original_ptr = unsafe { *(original_vtable as *mut *mut u8).add(index) };

        self.pending_hooks.push(PendingHook::VtableInstance {
            object_vptr,
            vtable_len,
            index,
            detour,
        });

        Ok(original_ptr)
    }

    /// Whether a live hook or one queued in this transaction already redirects
    /// the table slot at `slot`.
    fn table_slot_taken(&self, slot: usize) -> bool {
        let queued = self.pending_hooks.iter().any(|hook| match hook {
            PendingHook::Iat { slot: queued, .. } | PendingHook::Eat { slot: queued, .. } => {
                *queued == slot
            }
            PendingHook::Vtable { vtable, index, .. } => {
                vtable.wrapping_add(*index) as usize == slot
            }
            _ => false,
        });
        queued || table_slot_claimed(slot)
    }

    /// Queues an installed hook to be detached when the transaction commits.
    ///
    /// The hook is only disabled during the commit phase. If a later operation
    /// in the same transaction fails, the hook is re-enabled before the error is
    /// returned. On successful commit the hook guard is made inert, so dropping
    /// it afterwards is a no-op.
    ///
    /// # Safety
    ///
    /// Only a pointer to `hook` is queued. It must stay alive and must not be
    /// moved until this transaction is committed or aborted.
    /// [`crate::DetourTransaction::detach`] enforces this with a borrow.
    pub unsafe fn detach(&mut self, hook: &mut Hook) -> Result<(), DetourError> {
        if !self.is_pending {
            return Err(DetourError::NotStarted);
        }

        let hook_ptr = hook as *mut Hook;
        if hook_ptr.is_null() || self.pending_detach_exists(DetachTarget::HookPtr(hook_ptr)) {
            return Err(DetourError::InvalidParameter);
        }

        self.pending_hooks
            .push(PendingHook::Detach(DetachTarget::HookPtr(hook_ptr)));
        Ok(())
    }

    /// Queues a hook stored inside an FFI handle to be detached on commit.
    ///
    /// The handle remains valid. On success, the selected slot is emptied and
    /// every other hook keeps its index.
    ///
    /// # Safety
    ///
    /// `handle` must be a valid handle previously returned by
    /// `detours_transaction_commit()`.
    pub unsafe fn detach_handle_index(
        &mut self,
        handle: *mut core::ffi::c_void,
        index: usize,
    ) -> Result<(), DetourError> {
        if !self.is_pending {
            return Err(DetourError::NotStarted);
        }
        if handle.is_null()
            || self.pending_detach_exists(DetachTarget::HandleIndex { handle, index })
        {
            return Err(DetourError::InvalidParameter);
        }

        let hooks = handle as *const crate::api::HandleSlots;
        if !with_code_lock(|| matches!(unsafe { &*hooks }.get(index), Some(Some(_)))) {
            return Err(DetourError::InvalidParameter);
        }

        self.pending_hooks
            .push(PendingHook::Detach(DetachTarget::HandleIndex {
                handle,
                index,
            }));
        Ok(())
    }

    // Commits the current detour transaction and returns the installed hooks.
    ///
    /// Pending inline hooks are installed after tracked threads have been checked
    /// and, if necessary, redirected from the overwritten instruction range to the
    /// trampoline. Pending IAT hooks are then applied by replacing the matching
    /// import entry with the detour function.
    ///
    /// If any step fails, all hooks installed during this call are rolled back and
    /// tracked threads are resumed before returning the error.
    ///
    /// # Errors
    ///
    /// - `DetourError::NotStarted` if the transaction is no longer pending.
    /// - Any error produced while redirecting threads or applying hooks.
    ///
    /// On success, all tracked threads are resumed and the transaction is finalized.
    pub fn commit(&mut self) -> Result<Vec<Hook>, DetourError> {
        if !self.is_pending {
            return Err(DetourError::NotStarted);
        }

        // Serialize the patch phase against other transactions. If threads were
        // tracked earlier this is a no-op, since the lock is already held.
        self.acquire_global_lock();

        #[cfg(feature = "debug-log")]
        self.record_debug(DebugEvent::CommitStart {
            hooks: self.pending_hooks.len(),
            threads: self.threads.len(),
        });

        // Suspend window rule: between `suspend_threads` and the resume, a
        // suspended thread may own the heap lock or one of neohook's own mutexes
        // (gateway registry, stub quarantine), so this thread must take neither.
        // Everything that allocates is done up front, pending hooks are consumed
        // in place and only dropped after the resume, and the registry is
        // updated once every thread runs again.
        let mut pending = std::mem::take(&mut self.pending_hooks);
        let mut reserved: Vec<Reserved> = Vec::with_capacity(pending.len());
        let mut inline_count = 0;
        let mut detach_count = 0;
        for (index, hook) in pending.iter().enumerate() {
            let slot = match hook {
                PendingHook::Inline(data) => {
                    inline_count += 1;
                    // Another transaction may have hooked these bytes since
                    // `attach`; the lock held now keeps the answer current.
                    // Two queued hooks must not patch the same bytes either.
                    let overlaps_queued = pending[..index].iter().any(|earlier| {
                        matches!(earlier, PendingHook::Inline(other)
                            if ranges_overlap(other.target as usize, other.stolen_len, data.target as usize, data.stolen_len))
                    });
                    if overlaps_queued || overlaps_live_patch(data.target, data.stolen_len) {
                        Err((HookKind::Inline, DetourError::InvalidParameter))
                    } else {
                        inline_patch_bytes(data)
                            .map(Reserved::Patch)
                            .map_err(|e| (HookKind::Inline, e))
                    }
                }
                PendingHook::VtableInstance { vtable_len, .. } => {
                    crate::vtable::ClonedVtable::new(*vtable_len)
                        .map(|table| Reserved::Table(Some(table)))
                        .map_err(|e| (HookKind::VtableInstance, e.into()))
                }
                // Resolving the export allocates, and so may building its jump
                // stub; the stub also stays here until after the resume if the
                // slot write fails.
                PendingHook::Eat {
                    module,
                    target_func,
                    detour,
                    ..
                } => unsafe { crate::eat::EatHook::prepare_export(*module, target_func, *detour) }
                    .map(Reserved::Eat)
                    .map_err(|e| (HookKind::Eat, e.into())),
                PendingHook::Detach(_) => {
                    detach_count += 1;
                    Ok(Reserved::Nothing)
                }
                _ => Ok(Reserved::Nothing),
            };
            match slot {
                Ok(slot) => reserved.push(slot),
                Err((kind, e)) => {
                    self.cleanup_threads();
                    return Err(DetourError::CommitFailed {
                        index,
                        kind,
                        source: Box::new(e),
                    });
                }
            }
        }

        let mut installed: Vec<Hook> = Vec::with_capacity(pending.len());
        let mut detached: Vec<AppliedDetach> = Vec::with_capacity(detach_count);
        if inline_count > 0 {
            // An instruction pointer or stack slot is redirected at most once:
            // afterwards it points into a fresh trampoline, which no other hook
            // in this commit can target.
            self.redirected_threads.reserve(self.threads.len());
            self.redirected_stacks
                .reserve(self.threads.len() * STACK_REDIRECTS_PER_THREAD);
        }
        crate::cfg::prepare();

        // Writers outside the transaction wait only for the patch phase. Taken
        // before the first suspension, so no frozen thread can hold it.
        let code_guard = hold_code_lock();

        // Table hooks claim their slot and VTable instance hooks may register a
        // clone inside the suspend window; make room now, while allocating is
        // still safe. Nothing else inserts while the code lock is held.
        reserve_table_slots(
            pending
                .iter()
                .filter(|hook| {
                    matches!(
                        hook,
                        PendingHook::Iat { .. }
                            | PendingHook::Eat { .. }
                            | PendingHook::Vtable { .. }
                    )
                })
                .count(),
        );
        crate::vtable::reserve_instance_clones(
            pending
                .iter()
                .filter(|hook| matches!(hook, PendingHook::VtableInstance { .. }))
                .count(),
        );

        // A gateway queued for chaining may have lost its owner since `attach`
        // (dropping a hook only waits for this lock, not for the transaction):
        // it is retired and will be freed, so it must not be patched. Checked
        // under the code lock, which every drop takes, and before any thread is
        // suspended, since the registry is a mutex.
        let orphaned = pending.iter().position(|hook| {
            matches!(hook, PendingHook::Inline(data)
                if matches!(data.target_kind, TargetKind::ManagedGateway)
                    && !is_managed_gateway(data.target))
        });
        if let Some(index) = orphaned {
            drop(code_guard);
            self.cleanup_threads();
            return Err(DetourError::CommitFailed {
                index,
                kind: HookKind::Inline,
                source: Box::new(DetourError::InvalidParameter),
            });
        }

        let freeze_guard = crate::threads::hold_freeze_lock();

        self.suspend_threads();

        let mut failure = None;
        for (index, hook) in pending.iter_mut().enumerate() {
            let step = match hook {
                PendingHook::Inline(data) => self
                    .install_inline(data, &mut reserved[index])
                    .map(Some)
                    .map_err(|e| (HookKind::Inline, e)),
                PendingHook::Iat {
                    module,
                    target_dll,
                    target_func,
                    detour,
                    slot,
                } => {
                    if claim_table_slot(*slot) {
                        unsafe {
                            crate::iat::IatHook::hook_import(
                                *module,
                                target_dll,
                                target_func,
                                *detour,
                            )
                        }
                        .map(|original| {
                            Some(Hook::Iat(IatHook {
                                module: *module,
                                // Moved out rather than cloned: the empty
                                // `String` left behind owns no allocation.
                                dll_name: std::mem::take(target_dll),
                                func_name: std::mem::take(target_func),
                                original_ptr: original,
                                slot: *slot,
                                claimed: true,
                                active: true,
                                detour: *detour as *mut u8,
                                enabled: true,
                            }))
                        })
                        .map_err(|err| {
                            release_table_slot(*slot);
                            (HookKind::Iat, err.into())
                        })
                    } else {
                        Err((HookKind::Iat, DetourError::InvalidParameter))
                    }
                }
                PendingHook::Eat {
                    module,
                    target_func,
                    ..
                } => install_eat(*module, target_func, &mut reserved[index])
                    .map(Some)
                    .map_err(|err| (HookKind::Eat, err)),
                PendingHook::Vtable {
                    vtable,
                    index,
                    detour,
                } => unsafe {
                    // Install as RAII hook object so rollback/drop can restore.
                    crate::vtable::VTableHook::install(*vtable, *index, *detour)
                        .map(|inst| Some(Hook::Vtable(inst)))
                        .map_err(|err| (HookKind::Vtable, err.into()))
                },
                PendingHook::VtableInstance {
                    object_vptr,
                    index: slot,
                    detour,
                    ..
                } => {
                    let Reserved::Table(table) = &mut reserved[index] else {
                        unreachable!("clone storage is reserved for every VTable instance hook");
                    };
                    unsafe {
                        crate::vtable::VTableInstanceHook::install_into(
                            *object_vptr,
                            *slot,
                            *detour,
                            table,
                        )
                    }
                    .map(|inst| Some(Hook::VtableInstance(inst)))
                    .map_err(|err| (HookKind::VtableInstance, err.into()))
                }
                PendingHook::Detach(target) => match unsafe { prepare_detach(*target) } {
                    Ok(was_enabled) => {
                        detached.push(AppliedDetach {
                            target: *target,
                            was_enabled,
                        });
                        Ok(None)
                    }
                    Err(e) => Err((HookKind::Detach, e)),
                },
            };
            match step {
                Ok(Some(hook)) => installed.push(hook),
                Ok(None) => {}
                Err((kind, source)) => {
                    failure = Some((index, kind, source));
                    break;
                }
            }
        }

        if let Some((index, kind, source)) = failure {
            rollback_detaches(&mut detached);
            self.rollback(&mut installed);
            self.cleanup_threads();
            drop(freeze_guard);
            // Threads run again: dismantle what the failed commit built.
            drop(installed);
            drop(pending);
            drop(reserved);
            drop(code_guard);
            return Err(DetourError::CommitFailed {
                index,
                kind,
                source: Box::new(source),
            });
        }

        // CPU Cache flush after all hooks installed
        unsafe {
            windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache(
                GetCurrentProcess(),
                std::ptr::null(),
                0,
            );
        }

        #[cfg(feature = "debug-log")]
        self.record_debug(DebugEvent::CommitDone {
            hooks: installed.len(),
        });

        self.resume_threads();
        drop(freeze_guard);

        // Publish the new gateways while the transaction lock is still held, so
        // the next transaction already sees them.
        for hook in &mut installed {
            if let Hook::Inline(inline) = hook {
                if matches!(inline.target_kind, TargetKind::ManagedGateway) {
                    unregister_managed_gateway(inline.target);
                    add_gateway_dependent(inline.target);
                }
                register_managed_gateway(inline.trampoline.ptr);
                register_live_patch(inline.target, inline.stolen_len);
                inline.published = true;
            }
        }

        self.cleanup_threads();
        finalize_detaches(&mut detached);
        drop(code_guard);
        self.is_pending = false;
        Ok(installed)
    }

    /// This function inspects the thread's instruction pointer and a portion of its
    /// stack to detect addresses that still point into the overwritten instruction
    /// range of `data.target`.
    ///
    /// If the current instruction pointer lies within the stolen byte range, it is
    /// updated to point to the corresponding offset inside `data.trampoline`.
    ///
    /// The stack is also scanned for potential return addresses that still point
    /// into the stolen range. Matching addresses are rewritten so execution returns
    /// into the trampoline instead of the patched original code.
    ///
    /// Any successful instruction-pointer or stack redirection is recorded in
    /// `self.redirected_threads` or `self.redirected_stacks` so it can later be
    /// restored if needed.
    ///
    /// # Parameters
    ///
    /// - `h_thread`: A handle to the suspended thread whose context should be
    ///   inspected and adjusted.
    /// - `data`: Metadata describing the inline hook, including the target address,
    ///   trampoline address, and stolen instruction length.
    ///
    /// # Errors
    ///
    /// Returns `Err(DetourError::RelocationFailed)` if the thread context could be
    /// updated after modifying the instruction pointer.
    ///
    /// If the thread context cannot be read via `GetThreadContext`, the function
    /// does **not** fail and instead returns `Ok(())`, treating the thread as
    /// skipped.
    ///
    /// # Notes
    ///
    /// - The whole committed stack above the stack pointer is scanned, up to
    ///   the end of the stack reservation; uncommitted and guard pages are
    ///   skipped. A return address can sit arbitrarily deep below a call chain.
    /// - This function assumes the thread is already suspended before being passed
    ///   in.
    /// - On x86_64, the instruction pointer and stack pointer are taken from `Rip`
    ///   and `Rsp`; on x86, `Eip` and `Esp` are used instead.
    fn redirect_rip_relative_threads(
        &mut self,
        h_thread: HANDLE,
        data: &InlineData,
    ) -> Result<(), DetourError> {
        unsafe {
            #[repr(align(16))]
            struct AlignedContext(CONTEXT);
            let mut ctx_wrapper: AlignedContext = std::mem::zeroed();
            let context = &mut ctx_wrapper.0;
            context.ContextFlags = CONTEXT_FLAGS;

            // fill context struct with current thread
            if GetThreadContext(h_thread, context) == 0 {
                #[cfg(feature = "debug-log")]
                self.record_debug(DebugEvent::ContextReadFailed { thread: h_thread });
                // Skip if we can't get the context
                return Ok(());
            }

            #[cfg(feature = "debug-log")]
            let tid = windows_sys::Win32::System::Threading::GetThreadId(h_thread);

            #[cfg(target_arch = "x86_64")]
            let original_rip = context.Rip as usize;
            #[cfg(target_arch = "x86")]
            let original_rip = context.Eip as usize;

            let target_start = data.target as usize;
            let target_end = target_start + data.stolen_len;

            // 1. RIP Redirection
            if original_rip >= target_start && original_rip < target_end {
                let redirected_ip = Self::map_redirect_address_exact(data, original_rip)?
                    .ok_or(DetourError::RelocationFailed)?;

                // Capacity is reserved before any thread is suspended; growing
                // here would allocate inside the suspend window.
                if self.redirected_threads.len() == self.redirected_threads.capacity() {
                    return Err(DetourError::RelocationFailed);
                }
                self.redirected_threads
                    .push((h_thread, original_rip as u64));

                #[cfg(feature = "debug-log")]
                self.record_debug(DebugEvent::IpRedirected {
                    tid,
                    from: original_rip,
                    to: redirected_ip,
                });

                #[cfg(target_arch = "x86_64")]
                {
                    context.Rip = redirected_ip as u64;
                }

                #[cfg(target_arch = "x86")]
                {
                    context.Eip = redirected_ip as u32;
                }

                if SetThreadContext(h_thread, context) == 0 {
                    return Err(DetourError::RelocationFailed);
                }
            }

            // 2. STACK Redirection
            #[cfg(target_arch = "x86_64")]
            let stack_ptr = context.Rsp as usize;
            #[cfg(target_arch = "x86")]
            let stack_ptr = context.Esp as usize;

            use windows_sys::Win32::System::Memory::{
                MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualQuery,
            };
            const WORD: usize = std::mem::size_of::<usize>();
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
            if VirtualQuery(stack_ptr as *const _, &mut mbi, mbi_size) == 0 {
                return Ok(());
            }
            let stack_allocation = mbi.AllocationBase as usize;
            let mut scanned = 0usize;
            let mut region = stack_ptr;
            loop {
                if VirtualQuery(region as *const _, &mut mbi, mbi_size) == 0
                    || mbi.AllocationBase as usize != stack_allocation
                {
                    break;
                }
                let region_end = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
                if region_end <= region {
                    break;
                }
                let readable =
                    mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0;
                let mut next_slot = region.next_multiple_of(WORD);
                region = region_end;
                if !readable {
                    continue;
                }

                while next_slot + WORD <= region_end {
                    let current_stack_addr = next_slot;
                    next_slot += WORD;
                    scanned += WORD;
                    if scanned > MAX_STACK_SCAN_BYTES {
                        // A return address deeper than this would be missed.
                        return Err(DetourError::RelocationFailed);
                    }

                    let mut stack_value: usize = 0;
                    std::ptr::copy_nonoverlapping(
                        current_stack_addr as *const usize,
                        &mut stack_value,
                        1,
                    );

                    if !Self::is_plausible_return_address(data, stack_value) {
                        continue;
                    }

                    if let Some(new_return_addr) =
                        Self::map_redirect_address_exact(data, stack_value)?
                    {
                        if self.redirected_stacks.len() == self.redirected_stacks.capacity() {
                            return Err(DetourError::RelocationFailed);
                        }

                        #[cfg(feature = "debug-log")]
                        self.record_debug(DebugEvent::StackRedirected {
                            tid,
                            slot: current_stack_addr,
                            from: stack_value,
                            to: new_return_addr,
                        });

                        self.redirected_stacks
                            .push((h_thread, current_stack_addr, stack_value));

                        std::ptr::copy_nonoverlapping(
                            &new_return_addr,
                            current_stack_addr as *mut usize,
                            1,
                        );
                    }
                }
            }
            Ok(())
        }
    }

    /// Aborts the transaction and discards all pending hooks.
    ///
    /// Any tracked threads are resumed and all temporary transaction state is
    /// cleared. Calling this on a finished transaction has no effect.
    pub fn abort(&mut self) {
        if !self.is_pending {
            return;
        }
        self.pending_hooks.clear();
        self.cleanup_threads();
        self.is_pending = false;
    }

    /// Rollback function to undo all installed hooks in case of an error during commit. It takes a mutable reference to the list of installed hooks and unhooks each one.
    fn rollback(&mut self, installed: &mut [Hook]) {
        // restore threads first before unhook.
        //
        // Indexed rather than `drain(..)`/`mem::take`: draining would keep
        // `self` borrowed for the whole body, so recording a diagnostic event
        // inside it would not compile, and `mem::take` would drop the old
        // buffer here - a `free()` inside the suspend window, the very hazard
        // the deferred logging exists to avoid. The entries are `Copy`, so
        // indexing them out and clearing afterwards keeps the allocation.
        for idx in 0..self.redirected_threads.len() {
            let (h_thread, original_rip) = self.redirected_threads[idx];
            unsafe {
                #[repr(align(16))]
                struct AlignedContext(CONTEXT);
                let mut ctx_wrapper: AlignedContext = std::mem::zeroed();
                let context = &mut ctx_wrapper.0;
                context.ContextFlags = CONTEXT_FLAGS;

                // Get context, restore original RIP, set context
                if GetThreadContext(h_thread, context) != 0 {
                    #[cfg(target_arch = "x86_64")]
                    {
                        context.Rip = original_rip;
                    }
                    #[cfg(target_arch = "x86")]
                    {
                        context.Eip = original_rip as u32;
                    }

                    SetThreadContext(h_thread, context);

                    #[cfg(feature = "debug-log")]
                    self.record_debug(DebugEvent::RollbackIp {
                        thread: h_thread,
                        to: original_rip,
                    });
                }
            }
        }
        self.redirected_threads.clear();

        for (_h_thread, stack_addr, original_value) in self.redirected_stacks.drain(..) {
            unsafe {
                std::ptr::copy_nonoverlapping(&original_value, stack_addr as *mut usize, 1);
            }
        }

        // Restore the original bytes or pointers in place. Dropping the hooks
        // would also free memory and update the gateway registry and stub
        // quarantine, which must wait until the threads are resumed; the caller
        // drops them then, and that unhook is idempotent.
        for hook in installed.iter_mut().rev() {
            let _ = hook.disable();
        }
    }

    /// Records a diagnostic event for later output.
    ///
    /// Safe to call with threads suspended: it only copies plain data into the
    /// buffer reserved by [`Self::begin`]. Once that buffer is full the event is
    /// counted rather than stored, since pushing past the reserved capacity
    /// would reallocate - an allocation inside the suspend window is exactly
    /// what this whole mechanism exists to avoid.
    #[cfg(feature = "debug-log")]
    fn record_debug(&mut self, event: DebugEvent) {
        if self.debug_events.len() < self.debug_events.capacity() {
            self.debug_events.push(event);
        } else {
            self.debug_events_dropped += 1;
        }
    }

    /// Formats and writes every buffered event, then empties the buffer.
    ///
    /// Called from [`Self::cleanup_threads`] once every thread has been resumed,
    /// so formatting and locking the output stream are safe again. Draining
    /// makes repeat calls harmless.
    ///
    /// Writes to stderr with a fallible `writeln!` rather than `println!`, for
    /// the same reason [`crate::trace`] does: diagnostics must never panic the
    /// host process over a failed write.
    #[cfg(feature = "debug-log")]
    fn flush_debug_events(&mut self) {
        use std::io::Write;

        if self.debug_events.is_empty() && self.debug_events_dropped == 0 {
            return;
        }

        let mut err = std::io::stderr().lock();
        for event in self.debug_events.drain(..) {
            let _ = match event {
                DebugEvent::CommitStart { hooks, threads } => writeln!(
                    err,
                    "[Commit] Starting transaction with {hooks} Hooks and {threads} threads..."
                ),
                DebugEvent::ContextReadFailed { thread } => {
                    writeln!(err, "[Debug] Couldn't read context for thread {thread:?}")
                }
                DebugEvent::IpRedirected { tid, from, to } => writeln!(
                    err,
                    "[Redirect] Thread {tid} instruction pointer 0x{from:X} -> 0x{to:X}"
                ),
                DebugEvent::StackRedirected {
                    tid,
                    slot,
                    from,
                    to,
                } => writeln!(
                    err,
                    "[Stack] Thread {tid} return address at 0x{slot:X}: 0x{from:X} -> 0x{to:X}"
                ),
                DebugEvent::RollbackIp { thread, to } => writeln!(
                    err,
                    "[Rollback] Thread {thread:?} restored to original IP 0x{to:X}"
                ),
                DebugEvent::CommitDone { hooks } => writeln!(
                    err,
                    "[Commit] transaction successfully committed with {hooks} hooks installed."
                ),
            };
        }

        if self.debug_events_dropped > 0 {
            let _ = writeln!(
                err,
                "[Debug] {} further event(s) dropped: buffer full",
                self.debug_events_dropped
            );
            self.debug_events_dropped = 0;
        }
    }

    /// Suspends every tracked thread, dropping the ones that cannot be
    /// suspended (e.g. because they already exited).
    ///
    /// Suspension is deferred from [`Self::update_thread`] to the commit so the
    /// frozen window covers only the patching itself: anything that runs while
    /// other threads are suspended must not allocate or take a lock one of them
    /// might hold, and `attach` and the caller's own code between `update_thread`
    /// and `commit` cannot promise that.
    fn suspend_threads(&mut self) {
        if self.threads_suspended {
            return;
        }
        let mut i = 0;
        while i < self.threads.len() {
            let h = self.threads[i];
            if unsafe { SuspendThread(h) } == u32::MAX {
                unsafe { CloseHandle(h) };
                // Removing in place never reallocates.
                self.threads.swap_remove(i);
            } else {
                i += 1;
            }
        }
        self.threads_suspended = true;
    }

    /// Resumes the tracked threads if they are suspended, keeping the handles
    /// and the transaction lock.
    fn resume_threads(&mut self) {
        if self.threads_suspended {
            for &h in &self.threads {
                unsafe { ResumeThread(h) };
            }
            self.threads_suspended = false;
        }
    }

    fn cleanup_threads(&mut self) {
        self.resume_threads();
        for &h in &self.threads {
            unsafe { CloseHandle(h) };
        }
        self.threads.clear();
        // All threads have been resumed; release the process-wide transaction
        // lock (if this transaction holds it) so another transaction can run.
        self.global_lock = None;

        // Only now is it safe to format and write: nothing is suspended, so the
        // stdout and heap locks cannot be held by a frozen thread.
        #[cfg(feature = "debug-log")]
        self.flush_debug_events();
    }

    /// Redirects the suspended threads away from `data`'s stolen bytes and writes
    /// the prebuilt jump in `reserved` over them.
    ///
    /// Runs inside the suspend window, so it allocates and frees nothing: the
    /// hook's parts are moved out of `data` (which is dropped after the resume)
    /// and the patch is taken from `reserved` only on success. The gateway
    /// registry is updated by `commit` once the threads run again.
    fn install_inline(
        &mut self,
        data: &mut InlineData,
        reserved: &mut Reserved,
    ) -> Result<Hook, DetourError> {
        // check if any thread is executing in the range of the original bytes, and if so, redirect them to the trampoline before we overwrite the code
        for i in 0..self.threads.len() {
            let h_thread = self.threads[i];
            self.redirect_rip_relative_threads(h_thread, data)?;
        }

        let Reserved::Patch(patch) = reserved else {
            return Err(DetourError::InvalidParameter);
        };
        if patch.len() != data.stolen_len
            || !unsafe { crate::mem::write_code_bytes(data.target, patch.as_ptr(), patch.len()) }
        {
            // The commit rolls back the hooks that were already installed.
            return Err(DetourError::RelocationFailed);
        }

        Ok(Hook::Inline(InlineHook {
            target: data.target,
            trampoline: std::mem::replace(
                &mut data.trampoline,
                Trampoline {
                    ptr: std::ptr::null_mut(),
                    size: 0,
                },
            ),
            stolen_len: data.stolen_len,
            orig_bytes: std::mem::take(&mut data.orig_bytes),
            jump_type: data.jump_type,
            active: true,
            target_kind: std::mem::replace(&mut data.target_kind, TargetKind::Normal),
            patch_bytes: std::mem::take(patch),
            enabled: true,
            published: false,
        }))
    }

    /// Prints a human-readable snapshot of this transaction to standard output:
    /// its status, the threads it has suspended, every pending hook, the thread
    /// and stack redirections recorded so far, and whether the process-wide
    /// transaction lock is held.
    ///
    /// Writes to the host process's stdout, so call it only from a process you
    /// control - and never while threads are suspended, where taking the stdout
    /// lock can deadlock against a suspended holder.
    pub fn dump_state(&self) {
        println!("\n--- [DETOUR TRANSACTION DEBUG] ---");
        println!(
            "Status: {}",
            if self.is_pending {
                "PENDING"
            } else {
                "COMMITTED/ABORTED"
            }
        );

        println!("Threads ({}):", self.threads.len());
        for &h in &self.threads {
            let tid = unsafe { windows_sys::Win32::System::Threading::GetThreadId(h) };
            println!("  [Thread] TID: {} (Handle: {:?})", tid, h);
        }

        println!("Planned Hooks ({}):", self.pending_hooks.len());
        for (i, hook) in self.pending_hooks.iter().enumerate() {
            match hook {
                PendingHook::Inline(data) => {
                    println!(
                        "  [{}] INLINE: Target {:p} -> Detour {:p} (Type: {:?})",
                        i, data.target, data.detour, data.jump_type
                    );
                }
                PendingHook::Iat {
                    target_dll,
                    target_func,
                    ..
                } => {
                    println!("  [{}] IAT: {}!{}", i, target_dll, target_func);
                }
                PendingHook::Eat { target_func, .. } => {
                    println!("  [{}] EAT: {}", i, target_func);
                }
                PendingHook::Vtable { vtable, index, .. } => {
                    println!("  [{}] VTABLE: {:p}[{}]", i, vtable, index);
                }
                PendingHook::VtableInstance {
                    object_vptr,
                    vtable_len,
                    index,
                    ..
                } => {
                    println!(
                        "  [{}] VTABLE-INSTANCE: {:p} len={} slot={}",
                        i, object_vptr, vtable_len, index
                    );
                }
                PendingHook::Detach(target) => match target {
                    DetachTarget::HookPtr(hook) => {
                        println!("  [{}] DETACH: Hook {:p}", i, hook);
                    }
                    DetachTarget::HandleIndex { handle, index } => {
                        println!("  [{}] DETACH: Handle {:p}[{}]", i, handle, index);
                    }
                },
            }
        }

        println!("RIP-Redirections: {}", self.redirected_threads.len());
        for (h, original_rip) in &self.redirected_threads {
            println!(
                "  [Thread] Handle: {:?} original IP: 0x{:X}",
                h, original_rip
            );
        }

        println!("Stack-Redirections: {}", self.redirected_stacks.len());
        for (h, stack_addr, original_value) in &self.redirected_stacks {
            println!(
                "  [Thread] Handle: {:?} slot 0x{:X} original: 0x{:X}",
                h, stack_addr, original_value
            );
        }

        println!(
            "Global lock: {}",
            if self.global_lock.is_some() {
                "HELD"
            } else {
                "not held"
            }
        );

        println!("----------------------------------\n");
    }

    /// Returns whether a stack word pointing into `data`'s stolen range can be a
    /// return address: it must not be the entry itself, and the original bytes
    /// must hold a `call` (`E8 rel32` or `FF /2`) ending exactly at it.
    ///
    /// Runs inside the suspend window and allocates nothing. Bytes inside the
    /// stolen range come from the saved original bytes; bytes before the target
    /// are read live, but only from the target's own (committed) page.
    fn is_plausible_return_address(data: &InlineData, value: usize) -> bool {
        const MAX_CALL_LEN: usize = 7;

        let target_start = data.target as usize;
        if value <= target_start || value >= target_start + data.stolen_len {
            return false;
        }

        // window[k] is the byte at value - k, for k in 1..=available.
        let mut window = [0u8; MAX_CALL_LEN + 1];
        let mut available = 0;
        let page_start = target_start & !0xFFF;
        for (k, byte) in window.iter_mut().enumerate().skip(1) {
            let Some(addr) = value.checked_sub(k) else {
                break;
            };
            *byte = if addr >= target_start {
                match data.orig_bytes.get(addr - target_start) {
                    Some(&b) => b,
                    None => break,
                }
            } else if addr >= page_start {
                unsafe { std::ptr::read_volatile(addr as *const u8) }
            } else {
                break;
            };
            available = k;
        }

        // call rel32
        if available >= 5 && window[5] == 0xE8 {
            return true;
        }

        // call r/m (FF /2): the opcode at value - len, ModRM (and SIB) after it.
        for len in 2..=available {
            if window[len] != 0xFF {
                continue;
            }
            let modrm = window[len - 1];
            if (modrm >> 3) & 7 != 2 {
                continue;
            }
            let rm = modrm & 7;
            let encoded_len = match modrm >> 6 {
                0b11 => 2,
                0b00 if rm == 5 => 6,
                0b00 if rm == 4 => {
                    if len < 3 {
                        continue;
                    }
                    if window[len - 2] & 7 == 5 { 7 } else { 3 }
                }
                0b00 => 2,
                0b01 if rm == 4 => 4,
                0b01 => 3,
                _ if rm == 4 => 7,
                _ => 6,
            };
            if encoded_len == len {
                return true;
            }
        }

        false
    }

    fn map_redirect_address_exact(
        data: &InlineData,
        old_addr: usize,
    ) -> Result<Option<usize>, DetourError> {
        let target_start = data.target as usize;
        let target_end = target_start + data.stolen_len;

        if old_addr < target_start || old_addr >= target_end {
            return Ok(None);
        }

        match data.target_kind {
            TargetKind::ManagedGateway => {
                // alter und neuer Stub sind bytegleich
                let offset = old_addr - target_start;
                Ok(Some(data.redirect_base as usize + offset))
            }
            TargetKind::Normal => {
                let map = data
                    .redirect_map
                    .as_ref()
                    .ok_or(DetourError::RelocationFailed)?;
                let old_rel = u32::try_from(old_addr - target_start)
                    .map_err(|_| DetourError::RelocationFailed)?;

                let Some(index) = map
                    .old_instruction_offsets
                    .iter()
                    .position(|&off| off == old_rel)
                else {
                    return Ok(None);
                };

                let new_rel = map.new_instruction_offsets[index];
                if new_rel == u32::MAX {
                    return Err(DetourError::RelocationFailed);
                }

                Ok(Some(data.redirect_base as usize + new_rel as usize))
            }
        }
    }

    fn pending_detach_exists(&self, needle: DetachTarget) -> bool {
        self.pending_hooks.iter().any(|hook| {
            let PendingHook::Detach(existing) = hook else {
                return false;
            };

            detach_targets_equal(*existing, needle)
        })
    }
}

impl Drop for TransactionCore {
    fn drop(&mut self) {
        // If the transaction is still pending when the DetourTransaction struct is dropped, we call abort() to clean up any pending hook
        if self.is_pending {
            self.abort();
        }

        // Backstop: a transaction that recorded events without ever suspending a
        // thread never reaches `cleanup_threads`. Draining makes this a no-op
        // when the flush already happened.
        #[cfg(feature = "debug-log")]
        self.flush_debug_events();
    }
}

/// Process-wide transaction lock.
///
/// NeoHook serializes transactions so concurrent transactions on different
/// threads cannot suspend each other or patch overlapping code at the same
/// time. This mirrors the "one transaction at a time" model used by Microsoft
/// Detours. It is held from the first tracked thread until the commit or abort,
/// so code that is not itself a transaction never waits for it: writers outside
/// a transaction only take [`CODE_LOCK`].
///
/// Lock order: this lock, then the delay-hook manager, then [`CODE_LOCK`],
/// then any other crate mutex (gateway registry, stub quarantine, INT3 slot
/// manager), never the reverse.
///
/// A transaction started on a thread that already holds the lock (inside
/// [`with_transaction_lock`]) runs under that hold instead of taking it again.
static TRANSACTION_LOCK: Mutex<()> = Mutex::new(());

/// Thread id of the current [`TRANSACTION_LOCK`] holder, or 0 while it is free.
/// Lets a code write made by the holder itself (a detach or rollback inside a
/// commit) run without taking the lock again.
static TRANSACTION_OWNER: AtomicU32 = AtomicU32::new(0);

/// A held [`TRANSACTION_LOCK`] that records its owning thread.
pub(crate) struct TransactionGuard {
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl TransactionGuard {
    fn new(guard: std::sync::MutexGuard<'static, ()>) -> Self {
        TRANSACTION_OWNER.store(unsafe { GetCurrentThreadId() }, Ordering::Release);
        Self { _guard: guard }
    }
}

impl Drop for TransactionGuard {
    fn drop(&mut self) {
        // Cleared before the mutex itself is released.
        TRANSACTION_OWNER.store(0, Ordering::Release);
    }
}

/// Whether the calling thread holds [`TRANSACTION_LOCK`]. Only the holder ever
/// stores its own id, so seeing it means this thread owns the lock.
fn owns_transaction_lock() -> bool {
    TRANSACTION_OWNER.load(Ordering::Acquire) == unsafe { GetCurrentThreadId() }
}

/// Acquires the process-wide transaction lock, recovering from poisoning.
///
/// If another transaction panicked while holding the lock, the underlying data
/// is `()` and carries no invariant, so recovering the guard keeps NeoHook
/// usable instead of permanently wedging every future transaction.
fn lock_transaction() -> TransactionGuard {
    TransactionGuard::new(
        TRANSACTION_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
    )
}

/// Runs `body` under the transaction lock, for setup that starts transactions
/// of its own and must order its other locks after this one (delay hooks).
/// Runs directly on a thread that already holds it.
pub(crate) fn with_transaction_lock<R>(body: impl FnOnce() -> R) -> R {
    if owns_transaction_lock() {
        return body();
    }
    let _guard = lock_transaction();
    body()
}

/// The single lock for every code and table write.
///
/// Lifting a page's protection, writing and restoring it must not interleave
/// with another such write on the same page, or one thread restores the
/// protection while the other is still writing. A commit holds it only for its
/// patch phase - from right before the first thread is suspended until its
/// detaches are finalized - and every other writer only for the write itself.
/// No holder waits for the loader lock or the transaction lock, so it can be
/// taken under the loader lock (`DLL_PROCESS_DETACH`, the `LdrLoadDll` detour).
static CODE_LOCK: Mutex<()> = Mutex::new(());

/// Thread id of the current [`CODE_LOCK`] holder, or 0 while it is free. Lets a
/// write made by the holder itself (a detach or rollback inside a commit) run
/// without taking the lock again.
static CODE_OWNER: AtomicU32 = AtomicU32::new(0);

/// A held [`CODE_LOCK`] that records its owning thread.
pub(crate) struct CodeGuard {
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl CodeGuard {
    fn new(guard: std::sync::MutexGuard<'static, ()>) -> Self {
        CODE_OWNER.store(unsafe { GetCurrentThreadId() }, Ordering::Release);
        Self { _guard: guard }
    }
}

impl Drop for CodeGuard {
    fn drop(&mut self) {
        // Cleared before the mutex itself is released.
        CODE_OWNER.store(0, Ordering::Release);
    }
}

fn owns_code_lock() -> bool {
    CODE_OWNER.load(Ordering::Acquire) == unsafe { GetCurrentThreadId() }
}

/// Takes [`CODE_LOCK`] unless this thread already holds it, recovering from
/// poisoning (it guards no data).
fn hold_code_lock() -> Option<CodeGuard> {
    if owns_code_lock() {
        return None;
    }
    Some(CodeGuard::new(
        CODE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
    ))
}

/// Takes [`CODE_LOCK`] without waiting. `Some(None)` means this thread already
/// holds it; `None` that another thread does.
pub(crate) fn try_hold_code_lock() -> Option<Option<CodeGuard>> {
    if owns_code_lock() {
        return Some(None);
    }
    match CODE_LOCK.try_lock() {
        Ok(guard) => Some(Some(CodeGuard::new(guard))),
        Err(std::sync::TryLockError::WouldBlock) => None,
        Err(std::sync::TryLockError::Poisoned(poisoned)) => {
            Some(Some(CodeGuard::new(poisoned.into_inner())))
        }
    }
}

/// Runs a code or table write under [`CODE_LOCK`].
///
/// When this thread already holds the lock (a commit detaching or rolling back
/// hooks inside its suspend window) `write` runs directly, so it neither
/// deadlocks nor waits on a mutex there.
pub(crate) fn with_code_lock<R>(write: impl FnOnce() -> R) -> R {
    let _guard = hold_code_lock();
    write()
}

/// Tries to take the process-wide transaction lock without blocking.
///
/// Returns `None` if a transaction currently holds it - including this thread
/// mid-commit/rollback, where the lock is not reentrant. Used by deferred stub
/// reclamation ([`crate::reclaim`]) so it can suspend threads only when it is safe
/// to do so, and otherwise leave the work for a later pass.
pub(crate) fn try_lock_transaction() -> Option<TransactionGuard> {
    match TRANSACTION_LOCK.try_lock() {
        Ok(guard) => Some(TransactionGuard::new(guard)),
        Err(std::sync::TryLockError::WouldBlock) => None,
        Err(std::sync::TryLockError::Poisoned(poisoned)) => {
            Some(TransactionGuard::new(poisoned.into_inner()))
        }
    }
}

fn detach_targets_equal(left: DetachTarget, right: DetachTarget) -> bool {
    match (left, right) {
        (DetachTarget::HookPtr(a), DetachTarget::HookPtr(b)) => a == b,
        (
            DetachTarget::HandleIndex {
                handle: a_handle,
                index: a_index,
            },
            DetachTarget::HandleIndex {
                handle: b_handle,
                index: b_index,
            },
        ) => a_handle == b_handle && a_index == b_index,
        _ => false,
    }
}

unsafe fn prepare_detach(target: DetachTarget) -> Result<bool, DetourError> {
    let hook = unsafe { hook_from_detach_target_mut(target)? };
    hook.detach_prepare()
}

unsafe fn hook_from_detach_target_mut<'a>(
    target: DetachTarget,
) -> Result<&'a mut Hook, DetourError> {
    match target {
        DetachTarget::HookPtr(hook) => {
            if hook.is_null() {
                Err(DetourError::InvalidParameter)
            } else {
                Ok(unsafe { &mut *hook })
            }
        }
        DetachTarget::HandleIndex { handle, index } => {
            if handle.is_null() {
                return Err(DetourError::InvalidParameter);
            }

            let hooks = unsafe { &mut *(handle as *mut crate::api::HandleSlots) };
            hooks
                .get_mut(index)
                .and_then(Option::as_mut)
                .ok_or(DetourError::InvalidParameter)
        }
    }
}

fn rollback_detaches(detached: &mut Vec<AppliedDetach>) {
    for detach in detached.iter().rev() {
        let Ok(hook) = (unsafe { hook_from_detach_target_mut(detach.target) }) else {
            continue;
        };
        let _ = hook.detach_rollback(detach.was_enabled);
    }
    detached.clear();
}

fn finalize_detaches(detached: &mut Vec<AppliedDetach>) {
    for detach in detached.iter() {
        match detach.target {
            DetachTarget::HookPtr(hook) => {
                if !hook.is_null() {
                    unsafe {
                        (*hook).detach_finalize();
                    }
                }
            }
            DetachTarget::HandleIndex { handle, index } => {
                if handle.is_null() {
                    continue;
                }

                // Empty the slot instead of removing it, so the indices of the
                // handle's other hooks stay the same.
                let hooks = unsafe { &mut *(handle as *mut crate::api::HandleSlots) };
                if let Some(mut hook) = hooks.get_mut(index).and_then(Option::take) {
                    hook.detach_finalize();
                }
            }
        }
    }

    detached.clear();
}

/// Per-hook resources a commit allocates before it suspends any thread.
enum Reserved {
    Nothing,
    /// The bytes an inline hook writes over its target.
    Patch(Vec<u8>),
    /// Clone storage for a VTable instance hook, taken over on install.
    Table(Option<crate::vtable::ClonedVtable>),
    /// A resolved EAT hook and its jump stub, taken over on install.
    Eat(crate::eat::PreparedEat),
}

/// Writes a prepared EAT hook into its export slot. Runs inside the suspend
/// window: on failure the prepared hook, stub included, stays in `reserved` and
/// is released with it once the threads run again.
fn install_eat(
    module: HMODULE,
    target_func: &mut String,
    reserved: &mut Reserved,
) -> Result<Hook, DetourError> {
    let Reserved::Eat(prepared) = reserved else {
        return Err(DetourError::InvalidParameter);
    };
    if !claim_table_slot(prepared.slot_ptr as usize) {
        return Err(DetourError::InvalidParameter);
    }
    let original_rva = unsafe { prepared.slot_ptr.read() };
    if let Err(err) =
        unsafe { crate::eat::EatHook::write_export_rva(prepared.slot_ptr, prepared.detour_rva) }
    {
        release_table_slot(prepared.slot_ptr as usize);
        return Err(err.into());
    }

    let Reserved::Eat(prepared) = std::mem::replace(reserved, Reserved::Nothing) else {
        unreachable!("checked above");
    };
    Ok(Hook::Eat(EatHook {
        module,
        // Moved out rather than cloned: the empty `String` left behind owns no
        // allocation.
        func_name: std::mem::take(target_func),
        slot_ptr: prepared.slot_ptr,
        original_rva,
        detour_rva: prepared.detour_rva,
        original_ptr: (module as usize).wrapping_add(original_rva as usize) as *mut u8,
        stub: prepared.stub,
        claimed: true,
        active: true,
        enabled: true,
    }))
}

/// Builds the jump an inline hook writes over its target: a jump to the detour,
/// padded with NOPs to the full stolen length.
fn inline_patch_bytes(data: &InlineData) -> Result<Vec<u8>, DetourError> {
    let target = data.target;
    let dest = data.detour;

    // We prepare the jump instruction in a buffer. For Relative5, it's 5 bytes: E9 + 4-byte offset. For Absolute14, it's 14 bytes: FF 25 00 00 00 00 + 8-byte absolute address.
    let mut patch_buffer = [0u8; 14];
    let patch_len: usize;

    match data.jump_type {
        JumpType::Relative5 => {
            let offset = (dest as isize)
                .wrapping_sub(target as isize)
                .wrapping_sub(5);

            debug_assert!(
                (i32::MIN as isize..=i32::MAX as isize).contains(&offset),
                "Offset for relative jump does not fit in 32 bits"
            );

            patch_buffer[0] = 0xE9;
            // We write the offset as a little-endian 4-byte value starting at patch_buffer[1]
            patch_buffer[1..5].copy_from_slice(&(offset as i32).to_le_bytes());
            patch_len = 5;
        }
        JumpType::Absolute14 => {
            #[cfg(target_arch = "x86_64")]
            {
                patch_buffer[0..6].copy_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
                patch_buffer[6..14].copy_from_slice(&(dest as u64).to_le_bytes());
                patch_len = 14;
            }
            #[cfg(target_arch = "x86")]
            {
                // Absolute jumps are not supported on x86, we should never reach this case because attach() should have returned an error if the target was too far away. We put this here just for completeness, but it should never be used.
                return Err(DetourError::InvalidParameter);
            }
        }
    };

    if data.stolen_len < patch_len {
        return Err(DetourError::InvalidParameter);
    }

    // stolen_len could be > patch_len, in that case we fill the rest with NOP 0x90 bytes
    let mut full_patch = vec![0x90u8; data.stolen_len];
    full_patch[..patch_len].copy_from_slice(&patch_buffer[..patch_len]); // E9 xx xx xx xx 90 90 90 90....
    Ok(full_patch)
}

fn managed_gateways() -> &'static Mutex<HashSet<usize>> {
    static GATEWAYS: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();
    GATEWAYS.get_or_init(|| Mutex::new(HashSet::new()))
}

fn register_managed_gateway(ptr: *mut u8) {
    let _ = managed_gateways().lock().map(|mut s| {
        s.insert(ptr as usize);
    });
}

pub(crate) fn unregister_managed_gateway(ptr: *mut u8) {
    let _ = managed_gateways().lock().map(|mut s| {
        s.remove(&(ptr as usize));
    });
}

fn is_managed_gateway(ptr: *mut u8) -> bool {
    managed_gateways()
        .lock()
        .map(|s| s.contains(&(ptr as usize)))
        .unwrap_or(false)
}

/// Hooks chained on a managed gateway, keyed by the gateway address.
struct ChainedGateway {
    /// Installed hooks whose target is this gateway.
    dependents: usize,
    /// The gateway's trampoline (address, size) once its owner was dropped,
    /// retired when the last dependent is released.
    orphan: Option<(usize, usize)>,
}

/// Updated only outside the suspend window, under the transaction lock.
fn chained_gateways() -> &'static Mutex<HashMap<usize, ChainedGateway>> {
    static CHAINED: OnceLock<Mutex<HashMap<usize, ChainedGateway>>> = OnceLock::new();
    CHAINED.get_or_init(|| Mutex::new(HashMap::new()))
}

fn add_gateway_dependent(gateway: *mut u8) {
    let _ = chained_gateways().lock().map(|mut m| {
        m.entry(gateway as usize)
            .or_insert(ChainedGateway {
                dependents: 0,
                orphan: None,
            })
            .dependents += 1;
    });
}

/// Drops one dependent of `gateway`. Returns whether the gateway's owner is
/// still alive, and the orphaned trampoline to retire once the last dependent
/// is gone.
fn remove_gateway_dependent(gateway: *mut u8) -> (bool, Option<(usize, usize)>) {
    let Ok(mut m) = chained_gateways().lock() else {
        return (false, None);
    };
    let Some(entry) = m.get_mut(&(gateway as usize)) else {
        return (true, None);
    };
    let owner_alive = entry.orphan.is_none();
    entry.dependents = entry.dependents.saturating_sub(1);
    if entry.dependents > 0 {
        return (owner_alive, None);
    }
    let orphan = entry.orphan;
    m.remove(&(gateway as usize));
    (owner_alive, orphan)
}

/// Whether an installed hook is chained on `gateway`.
fn is_chained_gateway(gateway: *mut u8) -> bool {
    chained_gateways()
        .lock()
        .map(|m| m.contains_key(&(gateway as usize)))
        .unwrap_or(false)
}

/// Hands the trampoline of a dropped hook to the hooks chained on its gateway.
/// Returns `false` if nothing is chained on it, so the caller retires it.
fn orphan_chained_gateway(gateway: *mut u8, size: usize) -> bool {
    chained_gateways()
        .lock()
        .map(|mut m| match m.get_mut(&(gateway as usize)) {
            Some(entry) if entry.dependents > 0 => {
                entry.orphan = Some((gateway as usize, size));
                true
            }
            _ => false,
        })
        .unwrap_or(false)
}

/// Table slots (import, export and VTable entries) redirected by a live hook.
/// A second hook on a slot is refused: unhooking the two in the wrong order
/// would put a released detour or stub back into the table.
///
/// Only touched under the code lock, so no suspended thread can hold it while a
/// commit claims slots inside its suspend window. Claiming there does not
/// allocate, as [`reserve_table_slots`] made room beforehand.
fn table_slots() -> &'static Mutex<HashSet<usize>> {
    static SLOTS: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();
    SLOTS.get_or_init(|| Mutex::new(HashSet::new()))
}

fn reserve_table_slots(additional: usize) {
    with_code_lock(|| {
        let _ = table_slots().lock().map(|mut s| s.reserve(additional));
    });
}

/// Claims `slot` for a new hook. Returns `false` if a live hook owns it.
pub(crate) fn claim_table_slot(slot: usize) -> bool {
    with_code_lock(|| table_slots().lock().is_ok_and(|mut s| s.insert(slot)))
}

pub(crate) fn release_table_slot(slot: usize) {
    with_code_lock(|| {
        let _ = table_slots().lock().map(|mut s| s.remove(&slot));
    });
}

fn table_slot_claimed(slot: usize) -> bool {
    with_code_lock(|| table_slots().lock().is_ok_and(|s| s.contains(&slot)))
}

/// Code ranges patched by installed inline hooks, as start -> length. Updated
/// only outside the suspend window, under the transaction lock.
fn live_patches() -> &'static Mutex<HashMap<usize, usize>> {
    static PATCHES: OnceLock<Mutex<HashMap<usize, usize>>> = OnceLock::new();
    PATCHES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn register_live_patch(target: *mut u8, len: usize) {
    let _ = live_patches().lock().map(|mut m| {
        m.insert(target as usize, len);
    });
}

fn unregister_live_patch(target: *mut u8) {
    let _ = live_patches().lock().map(|mut m| {
        m.remove(&(target as usize));
    });
}

fn overlaps_live_patch(target: *mut u8, len: usize) -> bool {
    live_patches()
        .lock()
        .map(|m| {
            m.iter()
                .any(|(&start, &patched)| ranges_overlap(start, patched, target as usize, len))
        })
        .unwrap_or(false)
}

/// Whether an installed inline hook patches code starting at `target`.
pub(crate) fn live_patch_starts_at(target: *const u8) -> bool {
    live_patches()
        .lock()
        .map(|m| m.contains_key(&(target as usize)))
        .unwrap_or(false)
}

fn ranges_overlap(a: usize, a_len: usize, b: usize, b_len: usize) -> bool {
    a < b.saturating_add(b_len) && b < a.saturating_add(a_len)
}

#[cfg(target_arch = "x86_64")]
unsafe fn write_managed_gateway_stub(src: *mut u8, dst: *const u8) {
    unsafe {
        // FF 25 00 00 00 00 [u64 addr]
        *src.add(0) = 0xFF;
        *src.add(1) = 0x25;
        *src.add(2) = 0x00;
        *src.add(3) = 0x00;
        *src.add(4) = 0x00;
        *src.add(5) = 0x00;
        std::ptr::copy_nonoverlapping(&(dst as u64).to_le_bytes()[0], src.add(6), 8);
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn read_managed_gateway_target(src: *const u8) -> Option<*const u8> {
    unsafe {
        if *src.add(0) != 0xFF
            || *src.add(1) != 0x25
            || *src.add(2) != 0x00
            || *src.add(3) != 0x00
            || *src.add(4) != 0x00
            || *src.add(5) != 0x00
        {
            return None;
        }

        let mut addr = [0u8; 8];
        std::ptr::copy_nonoverlapping(src.add(6), addr.as_mut_ptr(), 8);
        Some(u64::from_le_bytes(addr) as *const u8)
    }
}

#[cfg(target_arch = "x86")]
unsafe fn write_managed_gateway_stub(src: *mut u8, dst: *const u8) {
    let rel = (dst as isize).wrapping_sub(src as isize).wrapping_sub(5);
    unsafe {
        *src.add(0) = 0xE9;
        std::ptr::copy_nonoverlapping(&(rel as i32).to_le_bytes()[0], src.add(1), 4);
    }
}

#[cfg(target_arch = "x86")]
unsafe fn read_managed_gateway_target(src: *const u8) -> Option<*const u8> {
    unsafe {
        if *src.add(0) != 0xE9 {
            return None;
        }

        let mut rel = [0u8; 4];
        std::ptr::copy_nonoverlapping(src.add(1), rel.as_mut_ptr(), 4);
        let rel = i32::from_le_bytes(rel) as isize;
        Some(src.offset(5 + rel))
    }
}

#[cfg(all(test, feature = "debug-log"))]
mod debug_log_tests {
    use super::{DEBUG_EVENT_CAPACITY, DebugEvent, TransactionCore};

    /// The buffer must be usable without allocating, because events are recorded
    /// while other threads are suspended - where the heap lock may be held by a
    /// frozen thread, or hooked by the caller.
    #[test]
    fn recording_never_reallocates() {
        let mut tx = TransactionCore::begin();
        let capacity = tx.debug_events.capacity();
        let buffer_start = tx.debug_events.as_ptr();

        assert!(
            capacity >= DEBUG_EVENT_CAPACITY,
            "begin() must reserve the buffer up front"
        );

        // Fill it exactly, then push well past the end.
        for i in 0..capacity + 64 {
            tx.record_debug(DebugEvent::CommitDone { hooks: i });
        }

        assert_eq!(
            tx.debug_events.as_ptr(),
            buffer_start,
            "buffer moved: recording reallocated inside the suspend window"
        );
        assert_eq!(tx.debug_events.len(), capacity);
        assert_eq!(
            tx.debug_events_dropped, 64,
            "overflow must be counted, not stored"
        );

        tx.abort();
    }

    /// Flushing empties the buffer, so the backstop call in `Drop` cannot print
    /// the same events a second time.
    #[test]
    fn flushing_drains_the_buffer() {
        let mut tx = TransactionCore::begin();
        tx.record_debug(DebugEvent::CommitStart {
            hooks: 1,
            threads: 2,
        });
        tx.record_debug(DebugEvent::CommitDone { hooks: 1 });
        assert_eq!(tx.debug_events.len(), 2);

        tx.flush_debug_events();
        assert!(tx.debug_events.is_empty());
        assert_eq!(tx.debug_events_dropped, 0);

        // Second flush is a no-op rather than a repeat.
        tx.flush_debug_events();
        assert!(tx.debug_events.is_empty());

        tx.abort();
    }

    /// `cleanup_threads` is the single point every commit and abort path passes
    /// through, so it is what guarantees a flush happens after threads resume.
    #[test]
    fn abort_flushes_through_cleanup_threads() {
        let mut tx = TransactionCore::begin();
        tx.record_debug(DebugEvent::CommitDone { hooks: 7 });

        tx.abort();

        assert!(
            tx.debug_events.is_empty(),
            "abort() must flush via cleanup_threads()"
        );
    }
}
