// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! VEH (Vectored Exception Handler)
//!
//! A VEH hook does **not** modify a single byte of the target -
//! neither its code nor any pointer table. Instead
//! it uses a CPU hardware execution breakpoint (debug registers `DR0`-`DR3`) on
//! the target address and installs a process-wide vectored exception handler.
//! When a thread reaches the target, the CPU raises a single-step exception
//! *before* the first instruction executes; the handler rewrites the
//! instruction pointer to the detour and resumes. The function body is never
//! touched, which makes the technique useful for read-only or shared code that
//! must not be patched.
//!
//! ## LIMITATIONS MAKE SURE TO READ THIS BEFORE USING VEH HOOKS !!!
//!
//! * **Four hooks at a time.** There are only four hardware breakpoint
//!   registers, so AT MOST FOUR VEH hooks can be active in the process.
//! * **Per-thread arming.** Debug registers are per-thread. NeoHook arms every
//!   thread that exists at install time, but threads created *afterwards* will
//!   not carry the breakpoint and will call the original function.
//! * **Full replacement.** Like [`crate::detour_inline!`], the detour replaces
//!   the target; there is no trampoline to call the original through (calling
//!   the target again from the same thread would re-trigger the breakpoint).

use std::ffi::c_void;
use std::fmt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Threading::*;

use crate::threads::ThreadEnumerator;

/// Number of hardware breakpoint registers (`DR0`-`DR3`).
const SLOT_COUNT: usize = 4;

/// NTSTATUS raised by a hardware execution breakpoint.
const STATUS_SINGLE_STEP: i32 = 0x8000_0004u32 as i32;

/// Vectored handler return values.
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

// Architecture-specific debug-register word width and the context flag that
// restricts Get/SetThreadContext to the debug registers.
#[cfg(target_arch = "x86_64")]
type DrWord = u64;
#[cfg(target_arch = "x86_64")]
const CONTEXT_DEBUG: u32 = CONTEXT_DEBUG_REGISTERS_AMD64;

#[cfg(target_arch = "x86")]
type DrWord = u32;
#[cfg(target_arch = "x86")]
const CONTEXT_DEBUG: u32 = CONTEXT_DEBUG_REGISTERS_X86;

/// Lock-free slot table read by the exception handler.
///
/// Each slot maps a breakpoint target address to its detour. A zero `target`
/// marks the slot as free. The handler only ever loads these atomics, so it
/// never has to take a lock on the faulting thread.
static SLOT_TARGET: [AtomicUsize; SLOT_COUNT] = [const { AtomicUsize::new(0) }; SLOT_COUNT];
static SLOT_DETOUR: [AtomicUsize; SLOT_COUNT] = [const { AtomicUsize::new(0) }; SLOT_COUNT];

/// Serializes installs/unhooks and owns the registered handler.
struct VehManager {
    /// Handle from `AddVectoredExceptionHandler`, stored as `usize` so the
    /// state is `Send`. Zero when no handler is registered.
    handler: usize,
    /// Number of active hooks; the handler is removed when it drops to zero.
    count: usize,
}

static MANAGER: Mutex<VehManager> = Mutex::new(VehManager {
    handler: 0,
    count: 0,
});

/// Errors produced while installing or removing a VEH hook.
#[derive(Debug)]
pub enum VehHookError {
    /// A null target or detour pointer was supplied.
    InvalidParameter,
    /// All four hardware breakpoint slots are already in use.
    NoFreeSlot,
    /// The target address is already hooked.
    AlreadyHooked,
    /// `AddVectoredExceptionHandler` failed.
    HandlerRegistrationFailed,
}

impl fmt::Display for VehHookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameter => write!(f, "invalid VEH hook parameters"),
            Self::NoFreeSlot => write!(f, "all four hardware breakpoint slots are in use"),
            Self::AlreadyHooked => write!(f, "target address is already VEH-hooked"),
            Self::HandlerRegistrationFailed => {
                write!(f, "failed to register the vectored exception handler")
            }
        }
    }
}

impl std::error::Error for VehHookError {}

/// An installed VEH (hardware-breakpoint) hook.
///
/// The hook stays active until it is explicitly removed with [`Self::unhook`]
/// or dropped, at which point the breakpoint is cleared on every thread and the
/// vectored handler is removed once the last hook is gone.
#[derive(Debug)]
pub struct VehHook {
    target: *const u8,
    detour: *const u8,
    slot: usize,
    active: bool,
}

// The hook owns no thread-local state; the breakpoint lives in per-thread debug
// registers and the global slot table, so the guard can move between threads.
unsafe impl Send for VehHook {}
unsafe impl Sync for VehHook {}

impl VehHook {
    /// Installs a VEH hook that redirects `target` to `detour`.
    ///
    /// Arms a hardware execution breakpoint on `target` for every thread that
    /// currently exists in the process and registers the vectored exception
    /// handler if it is not already active.
    ///
    /// # Errors
    ///
    /// * [`VehHookError::InvalidParameter`] if `target` or `detour` is null.
    /// * [`VehHookError::AlreadyHooked`] if `target` is already hooked.
    /// * [`VehHookError::NoFreeSlot`] if all four breakpoint registers are used.
    /// * [`VehHookError::HandlerRegistrationFailed`] if the handler could not be
    ///   registered.
    ///
    /// # Safety
    ///
    /// - `target` must point at the entry of a real function in executable
    ///   memory.
    /// - `detour` must be a function pointer with an ABI/signature compatible
    ///   with `target`, since it is entered with the target's original register
    ///   and stack state.
    pub unsafe fn install(target: *const u8, detour: *const u8) -> Result<Self, VehHookError> {
        if target.is_null() || detour.is_null() {
            return Err(VehHookError::InvalidParameter);
        }

        let target_addr = target as usize;
        let detour_addr = detour as usize;

        let mut mgr = lock_manager();

        // Reject a target that is already hooked, and find a free slot.
        let mut free_slot = None;
        for (i, slot_target) in SLOT_TARGET.iter().enumerate() {
            let occupied = slot_target.load(Ordering::Relaxed);
            if occupied == target_addr {
                return Err(VehHookError::AlreadyHooked);
            }
            if occupied == 0 && free_slot.is_none() {
                free_slot = Some(i);
            }
        }
        let slot = free_slot.ok_or(VehHookError::NoFreeSlot)?;

        // Register the vectored handler before any breakpoint can fire.
        if mgr.handler == 0 {
            let handle = unsafe { AddVectoredExceptionHandler(1, Some(veh_handler)) };
            if handle.is_null() {
                return Err(VehHookError::HandlerRegistrationFailed);
            }
            mgr.handler = handle as usize;
        }

        // Publish the detour first, then the target: the handler treats a slot
        // as live only once `SLOT_TARGET` is non-zero, so the detour is always
        // visible by then.
        SLOT_DETOUR[slot].store(detour_addr, Ordering::Release);
        SLOT_TARGET[slot].store(target_addr, Ordering::Release);

        // Arm the breakpoint on every thread now that the slot is published.
        set_breakpoint_on_all_threads(slot, target_addr, true);

        mgr.count += 1;

        Ok(Self {
            target,
            detour,
            slot,
            active: true,
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

    /// Removes the hook: clears the breakpoint on every thread and frees its
    /// slot, removing the vectored handler once the last hook is gone.
    pub fn unhook(mut self) -> Result<(), VehHookError> {
        self.remove();
        Ok(())
    }

    fn remove(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;

        let mut mgr = lock_manager();

        // Disarm the breakpoint everywhere before retiring the slot so a late
        // trap still finds a valid detour rather than an empty slot.
        set_breakpoint_on_all_threads(self.slot, 0, false);
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

impl Drop for VehHook {
    fn drop(&mut self) {
        self.remove();
    }
}

/// The process-wide vectored exception handler.
///
/// Runs for every exception in the process, so it does the cheapest possible
/// work: only single-step exceptions whose address matches a live slot are
/// redirected; everything else is passed straight through.
unsafe extern "system" fn veh_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    if info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let record = unsafe { (*info).ExceptionRecord };
    let context = unsafe { (*info).ContextRecord };
    if record.is_null() || context.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if unsafe { (*record).ExceptionCode } != STATUS_SINGLE_STEP {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let fault_addr = unsafe { (*record).ExceptionAddress } as usize;
    if fault_addr == 0 {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    for (i, slot_target) in SLOT_TARGET.iter().enumerate() {
        if slot_target.load(Ordering::Acquire) == fault_addr {
            let detour = SLOT_DETOUR[i].load(Ordering::Acquire);
            if detour != 0 {
                // Redirect to the detour. Since the new instruction pointer is
                // no longer the breakpoint address, execution resumes without
                // re-triggering the breakpoint.
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
fn lock_manager() -> std::sync::MutexGuard<'static, VehManager> {
    MANAGER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Arms (or disarms) breakpoint `slot` for `address` on the calling thread and
/// every other thread in the process.
fn set_breakpoint_on_all_threads(slot: usize, address: usize, enable: bool) {
    // The calling thread cannot be suspended; update it directly.
    unsafe { set_debug_register(GetCurrentThread(), slot, address, enable) };

    for tid in ThreadEnumerator::enumerate_process_threads() {
        let access = THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME;
        let h_thread = unsafe { OpenThread(access, 0, tid) };
        if h_thread.is_null() {
            continue;
        }

        unsafe {
            // Suspend so the context read/modify/write is not racing the thread.
            SuspendThread(h_thread);
            set_debug_register(h_thread, slot, address, enable);
            ResumeThread(h_thread);
            CloseHandle(h_thread);
        }
    }
}

/// Programs a single hardware execution breakpoint in one thread's debug
/// registers.
///
/// When `enable` is true, `DR<slot>` is set to `address` and the matching local
/// enable bit in `DR7` is turned on with an execution condition (R/W = 00,
/// LEN = 00). When false, the register and its enable bit are cleared. Other
/// debug-register state is preserved.
unsafe fn set_debug_register(h_thread: HANDLE, slot: usize, address: usize, enable: bool) -> bool {
    #[repr(align(16))]
    struct AlignedContext(CONTEXT);

    let mut wrapper: AlignedContext = unsafe { std::mem::zeroed() };
    let ctx = &mut wrapper.0;
    ctx.ContextFlags = CONTEXT_DEBUG;

    if unsafe { GetThreadContext(h_thread, ctx) } == 0 {
        return false;
    }

    let value: DrWord = if enable { address as DrWord } else { 0 };
    match slot {
        0 => ctx.Dr0 = value,
        1 => ctx.Dr1 = value,
        2 => ctx.Dr2 = value,
        _ => ctx.Dr3 = value,
    }

    // Local-enable bit for this slot (DR7 bits 0,2,4,6).
    let local_enable: DrWord = (1 as DrWord) << (slot as u32 * 2);
    // R/W + LEN field for this slot (4 bits starting at DR7 bit 16).
    let field_shift = 16 + slot as u32 * 4;
    // Execution breakpoint => clear the 4-bit R/W+LEN field to zero.
    ctx.Dr7 &= !((0xF as DrWord) << field_shift);
    if enable {
        ctx.Dr7 |= local_enable;
    } else {
        ctx.Dr7 &= !local_enable;
    }

    ctx.ContextFlags = CONTEXT_DEBUG;
    unsafe { SetThreadContext(h_thread, ctx) != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern "system" fn slot_target_a() -> u32 {
        std::hint::black_box(1)
    }
    extern "system" fn slot_target_b() -> u32 {
        std::hint::black_box(2)
    }
    extern "system" fn slot_target_c() -> u32 {
        std::hint::black_box(3)
    }
    extern "system" fn slot_target_d() -> u32 {
        std::hint::black_box(4)
    }
    extern "system" fn slot_target_e() -> u32 {
        std::hint::black_box(5)
    }
    extern "system" fn slot_detour() -> u32 {
        std::hint::black_box(0)
    }

    #[test]
    fn install_rejects_null_pointers() {
        let detour = slot_detour as *const () as *const u8;
        assert!(matches!(
            unsafe { VehHook::install(std::ptr::null(), detour) },
            Err(VehHookError::InvalidParameter)
        ));
        let target = slot_target_a as *const () as *const u8;
        assert!(matches!(
            unsafe { VehHook::install(target, std::ptr::null()) },
            Err(VehHookError::InvalidParameter)
        ));
    }

    #[test]
    fn install_rejects_duplicate_target() {
        let target = slot_target_a as *const () as *const u8;
        let detour = slot_detour as *const () as *const u8;

        let hook =
            unsafe { VehHook::install(target, detour) }.expect("first install should succeed");
        assert!(matches!(
            unsafe { VehHook::install(target, detour) },
            Err(VehHookError::AlreadyHooked)
        ));
        hook.unhook().unwrap();
    }

    #[test]
    fn install_runs_out_of_slots_after_four() {
        let detour = slot_detour as *const () as *const u8;
        let targets = [
            slot_target_a as *const () as *const u8,
            slot_target_b as *const () as *const u8,
            slot_target_c as *const () as *const u8,
            slot_target_d as *const () as *const u8,
        ];

        let mut hooks = Vec::new();
        for t in targets {
            hooks.push(unsafe { VehHook::install(t, detour) }.expect("install within slot budget"));
        }

        let fifth = slot_target_e as *const () as *const u8;
        assert!(matches!(
            unsafe { VehHook::install(fifth, detour) },
            Err(VehHookError::NoFreeSlot)
        ));

        for h in hooks.drain(..) {
            h.unhook().unwrap();
        }

        // A slot is free again after unhooking.
        let again = unsafe { VehHook::install(fifth, detour) }.expect("slot freed after unhook");
        again.unhook().unwrap();
    }
}
