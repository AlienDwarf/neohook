// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::DetourError;
use crate::HookKind;
use crate::alloc::{Trampoline, TrampolineAlloc};
use crate::disasm;
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::{CONTEXT, GetThreadContext, SetThreadContext};
use windows_sys::Win32::System::Threading::*;

/// The number of usize slots to scan on the stack for return addresses.
/// Default: 512 (corresponds to 4KB / one memory page on x64).
const STACK_SCAN_DEPTH: usize = 512;

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
    },
    Eat {
        module: HMODULE,
        target_func: String,
        detour: *const u8,
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
    /// redirection.
    pub fn enable(&mut self) -> Result<(), DetourError> {
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
        if unsafe { crate::mem::write_memory_atomic(target, bytes.as_ptr(), bytes.len()) }.is_some()
        {
            Ok(())
        } else {
            Err(DetourError::RelocationFailed)
        }
    }

    /// Unhooks this inline hook by restoring the original bytes at the target address.
    pub fn unhook(mut self) -> Result<(), DetourError> {
        self.perform_unhook()?;
        unregister_managed_gateway(self.trampoline.ptr);
        self.active = false;

        Ok(())
    }

    fn perform_unhook(&self) -> Result<(), DetourError> {
        // parameter validation
        if self.target.is_null() || self.orig_bytes.len() != self.stolen_len {
            return Err(DetourError::InvalidParameter);
        }

        unsafe {
            let mut old = 0u32;
            // Get current protection and add execute permissions
            let protect_ok = crate::mem::virtual_protect_same_execute(
                self.target,
                self.stolen_len,
                windows_sys::Win32::System::Memory::PAGE_READWRITE,
                &mut old,
            );
            if protect_ok == 0 {
                return Err(DetourError::RelocationFailed);
            }

            // copy the original bytes back to the target function
            std::ptr::copy_nonoverlapping(self.orig_bytes.as_ptr(), self.target, self.stolen_len);

            // If this hook had overwritten a managed gateway, restoring the original bytes
            // makes the target a managed gateway again
            if matches!(self.target_kind, TargetKind::ManagedGateway) {
                register_managed_gateway(self.target);
            }

            // CPU-Cache flush so CPU has to read from RAM not from L1 L2 L3 cache
            let flush_ok = windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache(
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                self.target as _,
                self.stolen_len,
            );

            // Restore original protection
            let restore_ok = windows_sys::Win32::System::Memory::VirtualProtect(
                self.target as _,
                self.stolen_len,
                old,
                &mut old,
            );

            // Wait til end even if an error occurs so we try to restore original protection always
            if flush_ok == 0 || restore_ok == 0 {
                return Err(DetourError::RelocationFailed);
            }
        }
        Ok(())
    }

    fn detach_finalize(&mut self) {
        if self.enabled {
            let _ = self.disable();
        }
        unregister_managed_gateway(self.trampoline.ptr);
        self.active = false;
        self.enabled = false;
    }
}

impl Drop for InlineHook {
    fn drop(&mut self) {
        if self.active {
            // auto unhook when dropped, best effort, ignore errors
            let _ = self.perform_unhook();
        }
        unregister_managed_gateway(self.trampoline.ptr);
    }
}

#[derive(Debug)]
pub struct IatHook {
    pub module: HMODULE,
    pub dll_name: String,
    pub func_name: String,
    pub original_ptr: *mut u8,
    active: bool,
    /// Detour pointer currently written into the import slot when enabled.
    detour: *mut u8,
    /// Whether the import slot currently points at the detour.
    enabled: bool,
}

impl IatHook {
    pub fn unhook(mut self) -> Result<(), DetourError> {
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
    pub fn enable(&mut self) -> Result<(), DetourError> {
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
        if self.enabled {
            let _ = self.disable();
        }
        self.active = false;
        self.enabled = false;
    }
}

impl Drop for IatHook {
    fn drop(&mut self) {
        if self.active {
            // auto unhook when dropped, best effort, ignore errors
            let _ = self.perform_unhook();
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
    pub fn enable(&mut self) -> Result<(), DetourError> {
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
        self.perform_unhook()?;
        self.active = false;
        Ok(())
    }

    fn perform_unhook(&self) -> Result<(), DetourError> {
        unsafe { crate::eat::EatHook::write_export_rva(self.slot_ptr, self.original_rva)? };
        Ok(())
    }

    fn detach_finalize(&mut self) {
        if self.enabled {
            let _ = self.disable();
        }
        self.active = false;
        self.enabled = false;
    }
}

impl Drop for EatHook {
    fn drop(&mut self) {
        if self.active {
            // auto unhook when dropped, best effort, ignore errors
            let _ = self.perform_unhook();
        }
        // `stub` is released here via its own Drop, after the slot no longer
        // points at it.
    }
}

/// Installed VTable hook type used by transaction commits.
pub type VtableHook = crate::vtable::VTableHook;
/// Installed per-instance VTable hook type used by transaction commits.
pub type VtableInstanceHook = crate::vtable::VTableInstanceHook;

pub struct TransactionCore {
    threads: Vec<HANDLE>,
    pending_hooks: Vec<PendingHook>,
    is_pending: bool,
    redirected_threads: Vec<(HANDLE, u64)>, // for safety, we store the original RIP of redirected threads so we can restore it if needed
    redirected_stacks: Vec<(HANDLE, usize, usize)>, // for safety, we store the original stack pointer and size of redirected threads so we can restore it if needed
    // Process-wide transaction lock guard. Held from the first thread
    // suspension (or the start of commit) until threads are resumed, so two
    // transactions on different threads cannot suspend each other or patch
    // code concurrently. `None` while the transaction holds no lock.
    global_lock: Option<std::sync::MutexGuard<'static, ()>>,
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
            pending_hooks: Vec::new(),
            is_pending: true,
            redirected_threads: Vec::new(),
            redirected_stacks: Vec::new(),
            global_lock: None,
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
        if self.global_lock.is_none() {
            self.global_lock = Some(lock_transaction());
        }
    }

    /// Opens, suspends, and tracks the thread identified by `thread_id`.
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

            // Take the process-wide lock before suspending any thread, so a
            // concurrent transaction can never freeze the thread that holds the
            // lock (which would deadlock).
            self.acquire_global_lock();

            if SuspendThread(h_thread) == u32::MAX {
                CloseHandle(h_thread);
                return Ok(());
            }

            self.threads.push(h_thread);
            Ok(())
        }
    }

    /// Suspends and tracks all threads in the current process except the calling
    /// thread.
    ///
    /// Thread IDs are collected, then
    /// each thread is opened and suspended internally. Threads that cannot be
    /// opened or suspended are skipped so that a single inaccessible thread does
    /// not abort the transaction.
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
    /// # Safety
    /// The caller must ensure that `target` and `detour` are valid pointers. NeoHook performs basic validation but does not guarantee that the pointers are valid or that the memory they point to is properly aligned or accessible. Invalid pointers may cause undefined behavior, including crashes.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn attach(
        &mut self,
        mut target: *mut u8,
        detour: *const u8,
    ) -> Result<*mut u8, DetourError> {
        if !self.is_pending {
            return Err(DetourError::NotStarted);
        }

        if target.is_null() || detour.is_null() {
            return Err(DetourError::InvalidParameter);
        }

        // If the target function is a managed gateway, we use a special hooking method that does not require disassembly or stolen bytes, as the gateway is designed to be overwritten with a jump to the trampoline. This allows us to hook methods that would otherwise be difficult or impossible to hook.
        // The trampoline will contain a stub that jumps to the original target after executing the detour, allowing for proper chaining of hooks
        if is_managed_gateway(target) {
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

        target = unsafe { crate::detour_code_from_pointer(target.cast_const()) };
        if target.is_null() {
            return Err(DetourError::InvalidParameter);
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

        // MANAGED GATEWAYS FOR HOOK CHAINING
        let tramp_capacity: usize = 128;
        let trampoline_handle = unsafe {
            // Allocate memory. rwx is required for the trampoline, we switch to rx later
            TrampolineAlloc::alloc_nearby_trampoline(target, tramp_capacity)
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

        unsafe {
            crate::iat::IatHook::find_import_address(h_module, target_dll, target_func)?;
        }

        // NOW WE CAN SAFELY PUSH THE HOOK TO THE PENDING LIST, THE COMMIT FUNCTION WILL TAKE CARE OF INSTALLING IT

        self.pending_hooks.push(PendingHook::Iat {
            module: h_module,
            target_dll: target_dll.to_string(),
            target_func: target_func.to_string(),
            detour,
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
        unsafe {
            crate::eat::EatHook::find_export_address(h_module, target_func)?;
        }

        self.pending_hooks.push(PendingHook::Eat {
            module: h_module,
            target_func: target_func.to_string(),
            detour,
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

        let original_ptr = unsafe { *(original_vtable as *mut *mut u8).add(index) };

        self.pending_hooks.push(PendingHook::VtableInstance {
            object_vptr,
            vtable_len,
            index,
            detour,
        });

        Ok(original_ptr)
    }

    /// Queues an installed hook to be detached when the transaction commits.
    ///
    /// The hook is only disabled during the commit phase. If a later operation
    /// in the same transaction fails, the hook is re-enabled before the error is
    /// returned. On successful commit the hook guard is made inert, so dropping
    /// it afterwards is a no-op.
    pub fn detach(&mut self, hook: &mut Hook) -> Result<(), DetourError> {
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
    /// The handle remains valid. On success, the selected hook is removed from
    /// the handle's hook list and all remaining hooks keep their relative order.
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

        let hooks = unsafe { &*(handle as *mut Vec<Hook>) };
        if index >= hooks.len() {
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
        // suspended earlier this is a no-op, since the lock is already held.
        self.acquire_global_lock();

        #[cfg(debug_assertions)]
        println!(
            "[Commit] Starting transaction with {} Hooks and {} threads...",
            self.pending_hooks.len(),
            self.threads.len()
        );

        let pending = std::mem::take(&mut self.pending_hooks);
        let mut installed: Vec<Hook> = Vec::new();
        let mut detached: Vec<AppliedDetach> = Vec::new();

        // Apply hooks
        for (hook_index, hook) in pending.into_iter().enumerate() {
            match hook {
                PendingHook::Inline(data) => {
                    // Borrow
                    let thread_handles = self.threads.clone();
                    // check if any thread is executing in the range of the original bytes, and if so, redirect them to the trampoline before we overwrite the code
                    for h_thread in thread_handles {
                        if let Err(e) = self.redirect_rip_relative_threads(h_thread, &data) {
                            rollback_detaches(&mut detached);
                            self.rollback(&mut installed);
                            self.cleanup_threads();
                            return Err(DetourError::CommitFailed {
                                index: hook_index,
                                kind: HookKind::Inline,
                                source: Box::new(e),
                            });
                        }
                    }

                    match self.apply_inline_hook(data) {
                        Ok(inst) => installed.push(Hook::Inline(inst)),
                        Err(e) => {
                            rollback_detaches(&mut detached);
                            self.rollback(&mut installed);
                            self.cleanup_threads();
                            return Err(DetourError::CommitFailed {
                                index: hook_index,
                                kind: HookKind::Inline,
                                source: Box::new(e),
                            });
                        }
                    }
                }
                PendingHook::Iat {
                    module,
                    target_dll,
                    target_func,
                    detour,
                } => unsafe {
                    match crate::iat::IatHook::hook_import(
                        module,
                        &target_dll,
                        &target_func,
                        detour,
                    ) {
                        Ok(original) => {
                            installed.push(Hook::Iat(IatHook {
                                module,
                                dll_name: target_dll,
                                func_name: target_func,
                                original_ptr: original,
                                active: true,
                                detour: detour as *mut u8,
                                enabled: true,
                            }));
                        }
                        Err(err) => {
                            rollback_detaches(&mut detached);
                            self.rollback(&mut installed);
                            self.cleanup_threads();
                            return Err(DetourError::CommitFailed {
                                index: hook_index,
                                kind: HookKind::Iat,
                                source: Box::new(err.into()),
                            });
                        }
                    }
                },
                PendingHook::Eat {
                    module,
                    target_func,
                    detour,
                } => unsafe {
                    match crate::eat::EatHook::hook_export(module, &target_func, detour) {
                        Ok(inst) => {
                            installed.push(Hook::Eat(EatHook {
                                module,
                                func_name: target_func,
                                slot_ptr: inst.slot_ptr,
                                original_rva: inst.original_rva,
                                detour_rva: inst.detour_rva,
                                original_ptr: inst.original_ptr,
                                stub: inst.stub,
                                active: true,
                                enabled: true,
                            }));
                        }
                        Err(err) => {
                            rollback_detaches(&mut detached);
                            self.rollback(&mut installed);
                            self.cleanup_threads();
                            return Err(DetourError::CommitFailed {
                                index: hook_index,
                                kind: HookKind::Eat,
                                source: Box::new(err.into()),
                            });
                        }
                    }
                },
                PendingHook::Vtable {
                    vtable,
                    index,
                    detour,
                } => unsafe {
                    // Install as RAII hook object so rollback/drop can restore.
                    match crate::vtable::VTableHook::install(vtable, index, detour) {
                        Ok(inst) => {
                            installed.push(Hook::Vtable(inst));
                        }
                        Err(err) => {
                            rollback_detaches(&mut detached);
                            self.rollback(&mut installed);
                            self.cleanup_threads();
                            return Err(DetourError::CommitFailed {
                                index: hook_index,
                                kind: HookKind::Vtable,
                                source: Box::new(err.into()),
                            });
                        }
                    }
                },
                PendingHook::VtableInstance {
                    object_vptr,
                    vtable_len,
                    index,
                    detour,
                } => unsafe {
                    match crate::vtable::VTableInstanceHook::install(
                        object_vptr,
                        vtable_len,
                        index,
                        detour,
                    ) {
                        Ok(inst) => {
                            installed.push(Hook::VtableInstance(inst));
                        }
                        Err(err) => {
                            rollback_detaches(&mut detached);
                            self.rollback(&mut installed);
                            self.cleanup_threads();
                            return Err(DetourError::CommitFailed {
                                index: hook_index,
                                kind: HookKind::VtableInstance,
                                source: Box::new(err.into()),
                            });
                        }
                    }
                },
                PendingHook::Detach(target) => match unsafe { prepare_detach(target) } {
                    Ok(was_enabled) => detached.push(AppliedDetach {
                        target,
                        was_enabled,
                    }),
                    Err(e) => {
                        rollback_detaches(&mut detached);
                        rollback_detaches(&mut detached);
                        self.rollback(&mut installed);
                        self.cleanup_threads();
                        return Err(DetourError::CommitFailed {
                            index: hook_index,
                            kind: HookKind::Detach,
                            source: Box::new(e),
                        });
                    }
                },
            }
        }

        // CPU Cache flush after all hooks installed
        unsafe {
            windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache(
                GetCurrentProcess(),
                std::ptr::null(),
                0,
            );
        }

        #[cfg(debug_assertions)]
        println!(
            "[Commit] transaction successfully committed with {} hooks installed.",
            installed.len()
        );

        // resume threads
        self.cleanup_threads();
        finalize_detaches(&mut detached);
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
    /// - Only a limited of the stack is scanned, as defined by
    ///   `STACK_SCAN_DEPTH`. Automatically detects when the stack frame ends to avoid invalid access
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
                #[cfg(debug_assertions)]
                eprintln!("[Debug] Couldn't read context for thread {:?}", h_thread);
                // Skip if we can't get the context
                return Ok(());
            }

            #[cfg(debug_assertions)]
            let tid = windows_sys::Win32::System::Threading::GetThreadId(h_thread);

            #[cfg(target_arch = "x86_64")]
            let original_rip = context.Rip as usize;
            #[cfg(target_arch = "x86")]
            let original_rip = context.Eip as usize;

            let target_start = data.target as usize;
            let target_end = target_start + data.stolen_len;

            // 1. RIP Redirection
            if original_rip >= target_start && original_rip < target_end {
                #[cfg(debug_assertions)]
                println!(
                    "[DEBUG] Thread {} Instruction Pointer has been redirected",
                    tid
                );
                let redirected_ip = Self::map_redirect_address_exact(data, original_rip)?
                    .ok_or(DetourError::RelocationFailed)?;

                self.redirected_threads
                    .push((h_thread, original_rip as u64));

                #[cfg(target_arch = "x86_64")]
                {
                    #[cfg(debug_assertions)]
                    println!(
                        "RIP: 0x{:X} -> 0x{:X} (Trampoline + {})",
                        original_rip, data.trampoline.ptr as usize, redirected_ip
                    );
                    context.Rip = redirected_ip as u64;
                }

                #[cfg(target_arch = "x86")]
                {
                    #[cfg(debug_assertions)]
                    println!(
                        "EIP: 0x{:X} -> 0x{:X} (Trampoline + {})",
                        original_rip, data.trampoline.ptr as u32, redirected_ip
                    );
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

            let mut mbi: windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION =
                std::mem::zeroed();
            if windows_sys::Win32::System::Memory::VirtualQuery(
                stack_ptr as *const _,
                &mut mbi,
                std::mem::size_of::<windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION>(),
            ) != 0
            {
                let stack_segment_top = mbi.BaseAddress as usize + mbi.RegionSize;

                for i in 0..STACK_SCAN_DEPTH {
                    let current_stack_addr = stack_ptr + (i * std::mem::size_of::<usize>());
                    if current_stack_addr + std::mem::size_of::<usize>() > stack_segment_top {
                        break;
                    }

                    let mut stack_value: usize = 0;
                    std::ptr::copy_nonoverlapping(
                        current_stack_addr as *const usize,
                        &mut stack_value,
                        1,
                    );

                    if let Some(new_return_addr) =
                        Self::map_redirect_address_exact(data, stack_value)?
                    {
                        #[cfg(debug_assertions)]
                        println!(
                            "[Stack] Thread {} return address found on stack at 0x{:X}:",
                            tid, current_stack_addr
                        );
                        #[cfg(debug_assertions)]
                        println!("        0x{:X} -> 0x{:X}", stack_value, new_return_addr);

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
    fn rollback(&mut self, installed: &mut Vec<Hook>) {
        // restore threads first before unhook
        for (h_thread, original_rip) in self.redirected_threads.drain(..) {
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

                    #[cfg(debug_assertions)]
                    println!(
                        "[Rollback] Thread restored to Original-IP 0x{:X}",
                        original_rip
                    );
                }
            }
        }

        for (_h_thread, stack_addr, original_value) in self.redirected_stacks.drain(..) {
            unsafe {
                std::ptr::copy_nonoverlapping(&original_value, stack_addr as *mut usize, 1);
            }
        }

        // Restore original bytes or IAT entries for each installed hook
        for detour in installed.drain(..) {
            match detour {
                Hook::Inline(hook) => {
                    let _ = hook.unhook();
                }
                Hook::Iat(hook) => {
                    let _ = hook.unhook();
                }
                Hook::Eat(hook) => {
                    let _ = hook.unhook();
                }
                Hook::Vtable(hook) => {
                    let _ = hook.unhook();
                }
                Hook::VtableInstance(hook) => {
                    let _ = hook.unhook();
                }
            }
        }
    }

    fn cleanup_threads(&mut self) {
        for &h in &self.threads {
            unsafe {
                ResumeThread(h);
                CloseHandle(h);
            }
        }
        self.threads.clear();
        // All threads have been resumed; release the process-wide transaction
        // lock (if this transaction holds it) so another transaction can run.
        self.global_lock = None;
    }

    // Apply an inline hook, returning an InstalledHook on success.
    fn apply_inline_hook(&mut self, data: InlineData) -> Result<InlineHook, DetourError> {
        unsafe {
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

            // stolen_len could be > patch_len, in that case we fill the rest with NOP 0x90 bytes
            let mut full_patch = vec![0x90u8; data.stolen_len];
            full_patch[..patch_len].copy_from_slice(&patch_buffer[..patch_len]); // E9 xx xx xx xx 90 90 90 90....

            // we write atomic to ensure a thread-safe patching. If something fails we return an error
            if crate::mem::write_memory_atomic(target, full_patch.as_ptr(), data.stolen_len)
                .is_some()
            {
                // If this hook is overwriting a managed gateway, we need to unregister it
                if matches!(data.target_kind, TargetKind::ManagedGateway) {
                    unregister_managed_gateway(data.target);
                }

                // Write was successful now we register the trampoline as a managed gateway so it can be hooked itself
                register_managed_gateway(data.trampoline.ptr);

                Ok(InlineHook {
                    target: data.target,
                    trampoline: data.trampoline,
                    stolen_len: data.stolen_len,
                    orig_bytes: data.orig_bytes,
                    jump_type: data.jump_type,
                    active: true,
                    target_kind: data.target_kind,
                    patch_bytes: full_patch,
                    enabled: true,
                })
            } else {
                // If the write fails, we return an error. The commit() function will catch this and call rollback() to undo any hooks that were already installed.
                Err(DetourError::RelocationFailed)
            }
        }
    }

    #[cfg(debug_assertions)]
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
                PendingHook::Detach(_) => {
                    println!("  [{}] DETACH", i);
                }
            }
        }

        if !self.redirected_threads.is_empty() {
            println!("RIP-Redirections: {}", self.redirected_threads.len());
        }

        if !self.redirected_stacks.is_empty() {
            println!("Stack-Redirections: {}", self.redirected_stacks.len());
        }

        println!("----------------------------------\n");
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
    }
}

/// Process-wide transaction lock.
///
/// NeoHook serializes the critical section of a transaction (thread suspension
/// and code patching) so concurrent transactions on different threads cannot
/// suspend each other or patch overlapping code at the same time. This mirrors
/// the "one transaction at a time" model used by Microsoft Detours.
///
/// A transaction must not be nested on the same thread (i.e. suspend threads or
/// commit a second transaction while a first one on that thread still holds the
/// lock), as the lock is not reentrant and that would deadlock.
static TRANSACTION_LOCK: Mutex<()> = Mutex::new(());

/// Acquires the process-wide transaction lock, recovering from poisoning.
///
/// If another transaction panicked while holding the lock, the underlying data
/// is `()` and carries no invariant, so recovering the guard keeps NeoHook
/// usable instead of permanently wedging every future transaction.
fn lock_transaction() -> std::sync::MutexGuard<'static, ()> {
    TRANSACTION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
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

            let hooks = unsafe { &mut *(handle as *mut Vec<Hook>) };
            hooks.get_mut(index).ok_or(DetourError::InvalidParameter)
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
    let mut handle_detaches = Vec::new();

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
                handle_detaches.push((handle, index));
            }
        }
    }

    handle_detaches.sort_by(|(left_handle, left_index), (right_handle, right_index)| {
        left_handle
            .cmp(right_handle)
            .then_with(|| right_index.cmp(left_index))
    });

    for (handle, index) in handle_detaches {
        if handle.is_null() {
            continue;
        }

        let hooks = unsafe { &mut *(handle as *mut Vec<Hook>) };
        if index >= hooks.len() {
            continue;
        }

        let mut hook = hooks.remove(index);
        hook.detach_finalize();
    }

    detached.clear();
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

fn unregister_managed_gateway(ptr: *mut u8) {
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
