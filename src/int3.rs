// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! INT3 software-breakpoint hooking.
//!
//! Like a [`crate::veh::VehHook`], an INT3 hook redirects a function through a
//! vectored exception handler instead of overwriting its prologue with a jump.
//! The difference is *how* the trap is armed:
//!
//! * A VEH hook uses the CPU's four hardware debug registers (`DR0`-`DR3`), so
//!   at most **four** targets can be hooked at once and the code is never
//!   modified.
//! * An INT3 hook patches a **single byte** (`0xCC`) at the target. There is no
//!   four-hook limit - the only ceiling is [`MAX_HOOKS`] slots - and arming is
//!   not per-thread, so threads created after the install still trap. The cost
//!   is that one byte of the target *is* modified (unlike a VEH hook).
//!
//! When a thread reaches the patched byte it raises `STATUS_BREAKPOINT`; the
//! process-wide handler rewrites the instruction pointer to the detour and
//! resumes. Because only a single byte is written - an operation the CPU
//! performs atomically - no thread suspension is required to install the hook.
//!
//! ## LIMITATIONS - READ BEFORE USING
//!
//! * **Full replacement.** Like [`crate::detour_inline!`] and VEH hooks, the
//!   detour *replaces* the target; there is no trampoline to call the original
//!   through. Calling the target again from the detour on the same thread would
//!   re-trigger the breakpoint and recurse.
//! * **One byte is modified.** Unlike a VEH hook, the target is not byte-for-byte
//!   intact, so this technique is unsuitable for read-only pages that reject the
//!   `0xCC` write, or for code guarded by an integrity check.
//! * **Debugger interaction.** The handler claims `STATUS_BREAKPOINT`
//!   exceptions whose address matches a registered target and passes every other
//!   breakpoint straight through, so an attached debugger keeps working.

use std::ffi::c_void;
use std::fmt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use windows_sys::Win32::System::Diagnostics::Debug::*;

use crate::alloc::Trampoline;
use crate::gateway::build_original_gateway;
use crate::mem::write_memory_atomic;

/// Maximum number of simultaneously installed INT3 hooks.
///
/// Unlike VEH hooks (capped at four by the hardware debug registers), the only
/// limit here is the size of the lock-free slot table read by the handler.
pub const MAX_HOOKS: usize = 256;

/// The `INT3` opcode patched over the first byte of the target.
const INT3_OPCODE: u8 = 0xCC;

/// NTSTATUS raised by an `INT3` instruction.
const STATUS_BREAKPOINT: i32 = 0x8000_0003u32 as i32;

/// Vectored handler return values.
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

/// Lock-free slot table read by the exception handler.
///
/// Each slot maps a breakpoint target address to its detour. A zero `target`
/// marks the slot as free. The handler only ever loads these atomics, so it
/// never has to take a lock on the faulting thread.
static SLOT_TARGET: [AtomicUsize; MAX_HOOKS] = [const { AtomicUsize::new(0) }; MAX_HOOKS];
static SLOT_DETOUR: [AtomicUsize; MAX_HOOKS] = [const { AtomicUsize::new(0) }; MAX_HOOKS];

/// Serializes installs/unhooks and owns the registered handler.
struct Int3Manager {
    /// Handle from `AddVectoredExceptionHandler`, stored as `usize` so the
    /// state is `Send`. Zero when no handler is registered.
    handler: usize,
    /// Number of active hooks; the handler is removed when it drops to zero.
    count: usize,
}

static MANAGER: Mutex<Int3Manager> = Mutex::new(Int3Manager {
    handler: 0,
    count: 0,
});

/// Errors produced while installing or removing an INT3 hook.
#[derive(Debug)]
pub enum Int3HookError {
    /// A null target or detour pointer was supplied.
    InvalidParameter,
    /// All [`MAX_HOOKS`] slots are already in use.
    NoFreeSlot,
    /// The target address is already hooked.
    AlreadyHooked,
    /// `AddVectoredExceptionHandler` failed.
    HandlerRegistrationFailed,
    /// Writing the `0xCC` byte into the target failed (e.g. the page rejected
    /// the protection change).
    PatchFailed,
    /// The call-original gateway could not be built (the prologue was not
    /// relocatable, or no executable memory was free within jump range). Only
    /// returned by [`Int3Hook::install_with_original`].
    GatewayBuildFailed,
}

impl fmt::Display for Int3HookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameter => write!(f, "invalid INT3 hook parameters"),
            Self::NoFreeSlot => write!(f, "all {MAX_HOOKS} INT3 hook slots are in use"),
            Self::AlreadyHooked => write!(f, "target address is already INT3-hooked"),
            Self::HandlerRegistrationFailed => {
                write!(f, "failed to register the vectored exception handler")
            }
            Self::PatchFailed => write!(f, "failed to write the INT3 byte into the target"),
            Self::GatewayBuildFailed => {
                write!(
                    f,
                    "failed to build the call-original gateway for the target"
                )
            }
        }
    }
}

impl std::error::Error for Int3HookError {}

/// An installed INT3 software-breakpoint hook.
///
/// The hook stays active until it is explicitly removed with [`Self::unhook`]
/// or dropped, at which point the original byte is restored and the vectored
/// handler is removed once the last hook is gone.
#[derive(Debug)]
pub struct Int3Hook {
    target: *const u8,
    detour: *const u8,
    /// The original byte overwritten by `0xCC`, restored on unhook.
    original_byte: u8,
    slot: usize,
    active: bool,
    /// Callable gateway to the original function, present only when the hook was
    /// installed via [`Self::install_with_original`]. Freed on drop/unhook.
    gateway: Option<Trampoline>,
}

// The hook owns no thread-local state; the breakpoint lives in the patched byte
// and the global slot table, so the guard can move between threads.
unsafe impl Send for Int3Hook {}
unsafe impl Sync for Int3Hook {}

impl Int3Hook {
    /// Installs an INT3 hook that redirects `target` to `detour`.
    ///
    /// Patches the first byte of `target` with `0xCC` and registers the vectored
    /// exception handler if it is not already active. No threads are suspended:
    /// the single-byte write is atomic.
    ///
    /// # Errors
    ///
    /// * [`Int3HookError::InvalidParameter`] if `target` or `detour` is null.
    /// * [`Int3HookError::AlreadyHooked`] if `target` is already hooked.
    /// * [`Int3HookError::NoFreeSlot`] if all [`MAX_HOOKS`] slots are used.
    /// * [`Int3HookError::HandlerRegistrationFailed`] if the handler could not be
    ///   registered.
    /// * [`Int3HookError::PatchFailed`] if the `0xCC` byte could not be written.
    ///
    /// # Safety
    ///
    /// - `target` must point at the start of a real instruction in executable
    ///   memory (normally a function entry).
    /// - `detour` must be a function pointer with an ABI/signature compatible
    ///   with `target`, since it is entered with the target's original register
    ///   and stack state.
    pub unsafe fn install(target: *const u8, detour: *const u8) -> Result<Self, Int3HookError> {
        unsafe { Self::install_inner(target, detour, false) }
    }

    /// Installs an INT3 hook that also exposes a callable gateway to the
    /// original function via [`Self::original_ptr`].
    ///
    /// Identical to [`Self::install`], but before patching the `0xCC` byte it
    /// builds a small trampoline holding the relocated prologue, so the detour
    /// can forward to the original without re-triggering the breakpoint. Use
    /// this when the detour needs the original's behaviour or return value;
    /// prefer [`Self::install`] for a pure full replacement.
    ///
    /// # Errors
    ///
    /// In addition to the errors documented on [`Self::install`], returns
    /// [`Int3HookError::GatewayBuildFailed`] if the prologue cannot be relocated
    /// or no executable memory is free within jump range of `target`.
    ///
    /// # Safety
    ///
    /// Same requirements as [`Self::install`].
    pub unsafe fn install_with_original(
        target: *const u8,
        detour: *const u8,
    ) -> Result<Self, Int3HookError> {
        unsafe { Self::install_inner(target, detour, true) }
    }

    unsafe fn install_inner(
        target: *const u8,
        detour: *const u8,
        want_gateway: bool,
    ) -> Result<Self, Int3HookError> {
        if target.is_null() || detour.is_null() {
            return Err(Int3HookError::InvalidParameter);
        }

        // Build the gateway from the still-original bytes, before the `0xCC`
        // patch overwrites the first byte. On failure nothing has been changed.
        let gateway = if want_gateway {
            Some(
                unsafe { build_original_gateway(target) }
                    .ok_or(Int3HookError::GatewayBuildFailed)?,
            )
        } else {
            None
        };

        let target_addr = target as usize;
        let detour_addr = detour as usize;

        let mut mgr = lock_manager();

        // Reject a target that is already hooked, and find a free slot.
        let mut free_slot = None;
        for (i, slot_target) in SLOT_TARGET.iter().enumerate() {
            let occupied = slot_target.load(Ordering::Relaxed);
            if occupied == target_addr {
                return Err(Int3HookError::AlreadyHooked);
            }
            if occupied == 0 && free_slot.is_none() {
                free_slot = Some(i);
            }
        }
        let slot = free_slot.ok_or(Int3HookError::NoFreeSlot)?;

        // Register the vectored handler before the breakpoint can fire.
        if mgr.handler == 0 {
            let handle = unsafe { AddVectoredExceptionHandler(1, Some(int3_handler)) };
            if handle.is_null() {
                return Err(Int3HookError::HandlerRegistrationFailed);
            }
            mgr.handler = handle as usize;
        }

        // Publish the detour first, then the target: the handler treats a slot
        // as live only once `SLOT_TARGET` is non-zero, so the detour is always
        // visible by the time a trap can match this slot.
        SLOT_DETOUR[slot].store(detour_addr, Ordering::Release);
        SLOT_TARGET[slot].store(target_addr, Ordering::Release);

        // Patch the single entry byte. The slot is already published, so a trap
        // taken the instant the byte lands resolves correctly.
        let original = unsafe { write_memory_atomic(target as *mut u8, &INT3_OPCODE, 1) };
        let original_byte = match original {
            Some(bytes) => bytes[0],
            None => {
                // Roll back the published slot and the handler refcount.
                SLOT_TARGET[slot].store(0, Ordering::Release);
                SLOT_DETOUR[slot].store(0, Ordering::Release);
                if mgr.count == 0 && mgr.handler != 0 {
                    unsafe { RemoveVectoredExceptionHandler(mgr.handler as *mut c_void) };
                    mgr.handler = 0;
                }
                return Err(Int3HookError::PatchFailed);
            }
        };

        mgr.count += 1;

        Ok(Self {
            target,
            detour,
            original_byte,
            slot,
            active: true,
            gateway,
        })
    }

    /// Returns the hooked target address.
    pub fn target(&self) -> *const u8 {
        self.target
    }

    /// Returns the detour the target is redirected to.
    pub fn detour(&self) -> *const u8 {
        self.detour
    }

    /// Returns a callable pointer to the original function, or `None` if the
    /// hook was installed with [`Self::install`] (full replacement) rather than
    /// [`Self::install_with_original`].
    ///
    /// Transmute the pointer to the target's function type and call it to run
    /// the original; this neither re-enters the detour nor re-triggers the
    /// breakpoint.
    pub fn original_ptr(&self) -> Option<*const u8> {
        self.gateway.as_ref().map(|t| t.ptr as *const u8)
    }

    /// Removes the hook: restores the original byte and frees its slot, removing
    /// the vectored handler once the last hook is gone.
    pub fn unhook(mut self) -> Result<(), Int3HookError> {
        self.remove();
        Ok(())
    }

    fn remove(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;

        let mut mgr = lock_manager();

        // Restore the original byte first so no further trap is taken, then
        // retire the slot. A thread already inside the handler still finds a
        // valid detour because the slot is cleared only afterwards.
        unsafe { write_memory_atomic(self.target as *mut u8, &self.original_byte, 1) };
        SLOT_TARGET[self.slot].store(0, Ordering::Release);
        SLOT_DETOUR[self.slot].store(0, Ordering::Release);

        if mgr.count > 0 {
            mgr.count -= 1;
        }
        if mgr.count == 0 && mgr.handler != 0 {
            unsafe { RemoveVectoredExceptionHandler(mgr.handler as *mut c_void) };
            mgr.handler = 0;
        }
    }
}

impl Drop for Int3Hook {
    fn drop(&mut self) {
        self.remove();
    }
}

/// The process-wide vectored exception handler.
///
/// Runs for every exception in the process, so it does the cheapest possible
/// work: only `STATUS_BREAKPOINT` exceptions whose address matches a live slot
/// are redirected; everything else is passed straight through (including
/// breakpoints raised by a debugger or `__debugbreak`).
unsafe extern "system" fn int3_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    if info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let record = unsafe { (*info).ExceptionRecord };
    let context = unsafe { (*info).ContextRecord };
    if record.is_null() || context.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if unsafe { (*record).ExceptionCode } != STATUS_BREAKPOINT {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // For an INT3 trap, the exception address is the address of the `0xCC` byte
    // itself - i.e. the target entry we patched.
    let fault_addr = unsafe { (*record).ExceptionAddress } as usize;
    if fault_addr == 0 {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    for (i, slot_target) in SLOT_TARGET.iter().enumerate() {
        if slot_target.load(Ordering::Acquire) == fault_addr {
            let detour = SLOT_DETOUR[i].load(Ordering::Acquire);
            if detour != 0 {
                // Redirect to the detour. The new instruction pointer is no
                // longer the breakpoint address, so execution resumes in the
                // detour without re-triggering the trap.
                unsafe { set_instruction_pointer(context, detour) };
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }

    EXCEPTION_CONTINUE_SEARCH
}

#[cfg(target_arch = "x86_64")]
unsafe fn set_instruction_pointer(context: *mut CONTEXT, ip: usize) {
    unsafe { (*context).Rip = ip as u64 };
}

#[cfg(target_arch = "x86")]
unsafe fn set_instruction_pointer(context: *mut CONTEXT, ip: usize) {
    unsafe { (*context).Eip = ip as u32 };
}

/// Recovers the manager lock even if a previous holder panicked; the guarded
/// state carries no invariant that a panic could corrupt.
fn lock_manager() -> std::sync::MutexGuard<'static, Int3Manager> {
    MANAGER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[inline(never)]
    extern "system" fn t_a() -> u32 {
        std::hint::black_box(1)
    }
    #[inline(never)]
    extern "system" fn t_b() -> u32 {
        std::hint::black_box(2)
    }
    #[inline(never)]
    extern "system" fn detour() -> u32 {
        std::hint::black_box(9999)
    }

    #[test]
    fn install_rejects_null_pointers() {
        let d = detour as *const () as *const u8;
        assert!(matches!(
            unsafe { Int3Hook::install(std::ptr::null(), d) },
            Err(Int3HookError::InvalidParameter)
        ));
        let t = t_a as *const () as *const u8;
        assert!(matches!(
            unsafe { Int3Hook::install(t, std::ptr::null()) },
            Err(Int3HookError::InvalidParameter)
        ));
    }

    #[test]
    fn install_rejects_duplicate_target() {
        let t = t_b as *const () as *const u8;
        let d = detour as *const () as *const u8;

        let hook = unsafe { Int3Hook::install(t, d) }.expect("first install should succeed");
        assert!(matches!(
            unsafe { Int3Hook::install(t, d) },
            Err(Int3HookError::AlreadyHooked)
        ));
        hook.unhook().unwrap();
    }

    #[test]
    fn redirects_and_restores() {
        // Resolve through a function pointer so the call really dispatches to
        // the patched entry byte rather than being inlined.
        let target: extern "system" fn() -> u32 = t_a;
        let t = t_a as *const () as *const u8;
        let d = detour as *const () as *const u8;

        assert_eq!(target(), 1, "sanity: original value before hook");

        let hook = unsafe { Int3Hook::install(t, d) }.expect("install should succeed");
        assert_eq!(target(), 9999, "call should be redirected to the detour");

        hook.unhook().unwrap();
        assert_eq!(target(), 1, "original byte should be restored after unhook");
    }

    #[test]
    fn original_gateway_forwards_to_real_function() {
        use std::sync::OnceLock;

        // A distinct target so it does not collide with the other tests' slots.
        #[inline(never)]
        extern "system" fn base(x: u32) -> u32 {
            std::hint::black_box(x).wrapping_add(1)
        }

        type Fn = extern "system" fn(u32) -> u32;
        static ORIG: OnceLock<Fn> = OnceLock::new();

        extern "system" fn detour_calls_orig(x: u32) -> u32 {
            // Forward to the original through the gateway, then add a marker.
            ORIG.get().unwrap()(x) + 1000
        }

        let target: Fn = base;
        let t = base as *const () as *const u8;
        let d = detour_calls_orig as *const () as *const u8;

        assert_eq!(target(5), 6, "sanity before hook");

        let hook = unsafe { Int3Hook::install_with_original(t, d) }.expect("install_with_original");
        let orig_ptr = hook.original_ptr().expect("gateway pointer present");
        ORIG.set(unsafe { std::mem::transmute::<*const u8, Fn>(orig_ptr) })
            .ok();

        // Detour ran (added 1000) *and* called through to the original (5 -> 6).
        assert_eq!(
            target(5),
            1006,
            "detour forwarded to the original via the gateway"
        );

        hook.unhook().unwrap();
        assert_eq!(target(5), 6, "original restored after unhook");
    }

    #[test]
    fn install_without_gateway_has_no_original_ptr() {
        let t = t_a as *const () as *const u8;
        let d = detour as *const () as *const u8;
        let hook = unsafe { Int3Hook::install(t, d) }.expect("install");
        assert!(
            hook.original_ptr().is_none(),
            "plain install must not expose a gateway"
        );
        hook.unhook().unwrap();
    }

    #[test]
    fn supports_more_than_four_hooks() {
        // The whole point versus VEH: no four-slot hardware ceiling. Install a
        // batch of distinct targets and confirm none are rejected for slots.
        #[inline(never)]
        extern "system" fn f0() -> u32 {
            std::hint::black_box(10)
        }
        #[inline(never)]
        extern "system" fn f1() -> u32 {
            std::hint::black_box(11)
        }
        #[inline(never)]
        extern "system" fn f2() -> u32 {
            std::hint::black_box(12)
        }
        #[inline(never)]
        extern "system" fn f3() -> u32 {
            std::hint::black_box(13)
        }
        #[inline(never)]
        extern "system" fn f4() -> u32 {
            std::hint::black_box(14)
        }
        #[inline(never)]
        extern "system" fn f5() -> u32 {
            std::hint::black_box(15)
        }

        let d = detour as *const () as *const u8;
        let targets: [*const u8; 6] = [
            f0 as *const () as *const u8,
            f1 as *const () as *const u8,
            f2 as *const () as *const u8,
            f3 as *const () as *const u8,
            f4 as *const () as *const u8,
            f5 as *const () as *const u8,
        ];

        let mut hooks = Vec::new();
        for t in targets {
            hooks.push(unsafe { Int3Hook::install(t, d) }.expect("install beyond four slots"));
        }
        assert_eq!(hooks.len(), 6, "all six hooks installed without a slot cap");

        for h in hooks.drain(..) {
            h.unhook().unwrap();
        }
    }
}
