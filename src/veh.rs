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

use std::fmt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Threading::*;

use crate::alloc::Trampoline;
use crate::gateway::build_original_gateway;
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

/// The address neohook last armed in each debug register, kept after the hook
/// is removed. A breakpoint the handler did not arm itself - another
/// component's, in a slot neohook never used or at a different address - is
/// never touched.
static SLOT_ARMED: [AtomicUsize; SLOT_COUNT] = [const { AtomicUsize::new(0) }; SLOT_COUNT];

/// DR6 bit set by a trap-flag single step (`BS`), as opposed to a debug
/// register hit.
const DR6_SINGLE_STEP: DrWord = 0x4000;

/// Ring of recently removed targets, so the handler can still recognise a late
/// trap from a thread whose stale breakpoint fired just before it was cleared.
const RETIRED_COUNT: usize = 16;
static RETIRED: [AtomicUsize; RETIRED_COUNT] = [const { AtomicUsize::new(0) }; RETIRED_COUNT];
static RETIRED_NEXT: AtomicUsize = AtomicUsize::new(0);

/// Serializes installs/unhooks and owns the registered handler.
struct VehManager {
    /// Handle from `AddVectoredExceptionHandler`, stored as `usize` so the
    /// state is `Send`. Zero until the first install. The handler is never
    /// removed: a thread can still trap on a stale breakpoint after its hook is
    /// gone, and the handler is what disarms it.
    handler: usize,
}

static MANAGER: Mutex<VehManager> = Mutex::new(VehManager { handler: 0 });

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
    /// The call-original gateway could not be built (the prologue was not
    /// relocatable, or no executable memory was free within jump range). Only
    /// returned by [`VehHook::install_with_original`].
    GatewayBuildFailed,
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
            Self::GatewayBuildFailed => {
                write!(
                    f,
                    "failed to build the call-original gateway for the target"
                )
            }
        }
    }
}

impl std::error::Error for VehHookError {}

/// An installed VEH (hardware-breakpoint) hook.
///
/// The hook stays active until it is explicitly removed with [`Self::unhook`]
/// or dropped, at which point the breakpoint is cleared on every thread. The
/// vectored handler stays registered so it can disarm any thread that still
/// traps on the stale breakpoint.
#[derive(Debug)]
pub struct VehHook {
    target: *const u8,
    detour: *const u8,
    slot: usize,
    active: bool,
    /// Callable gateway to the original function, present only when the hook was
    /// installed via [`Self::install_with_original`]. Freed on drop/unhook.
    gateway: Option<Trampoline>,
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
        unsafe { Self::install_inner(target, detour, false) }
    }

    /// Installs a VEH hook that also exposes a callable gateway to the original
    /// function via [`Self::original_ptr`].
    ///
    /// Identical to [`Self::install`], but it also builds a small trampoline
    /// holding the relocated prologue so the detour can forward to the original
    /// without re-entering the armed address. Use this when the detour needs the
    /// original's behaviour or return value; prefer [`Self::install`] for a pure
    /// full replacement. The target's bytes are still never modified.
    ///
    /// # Errors
    ///
    /// In addition to the errors documented on [`Self::install`], returns
    /// [`VehHookError::GatewayBuildFailed`] if the prologue cannot be relocated
    /// or no executable memory is free within jump range of `target`.
    ///
    /// # Safety
    ///
    /// Same requirements as [`Self::install`].
    pub unsafe fn install_with_original(
        target: *const u8,
        detour: *const u8,
    ) -> Result<Self, VehHookError> {
        unsafe { Self::install_inner(target, detour, true) }
    }

    unsafe fn install_inner(
        target: *const u8,
        detour: *const u8,
        want_gateway: bool,
    ) -> Result<Self, VehHookError> {
        if target.is_null() || detour.is_null() {
            return Err(VehHookError::InvalidParameter);
        }

        // The target's bytes are never patched, so the gateway can be built at
        // any point; do it up front so a failure leaves nothing to roll back.
        let gateway = if want_gateway {
            Some(
                unsafe { build_original_gateway(target) }
                    .ok_or(VehHookError::GatewayBuildFailed)?,
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
        SLOT_ARMED[slot].store(target_addr, Ordering::Release);
        SLOT_TARGET[slot].store(target_addr, Ordering::Release);

        // Arm the breakpoint on every thread now that the slot is published.
        set_breakpoint_on_all_threads(slot, target_addr, true);

        Ok(Self {
            target,
            detour,
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
    /// the original; because it resumes past the armed address it neither
    /// re-enters the detour nor re-triggers the breakpoint.
    pub fn original_ptr(&self) -> Option<*const u8> {
        self.gateway.as_ref().map(|t| t.ptr as *const u8)
    }

    /// Removes the hook: clears the breakpoint on every thread and frees its
    /// slot.
    pub fn unhook(mut self) -> Result<(), VehHookError> {
        self.remove();
        Ok(())
    }

    fn remove(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;

        let _mgr = lock_manager();

        // Disarm the breakpoint everywhere before retiring the slot so a late
        // trap still finds a valid detour rather than an empty slot. A thread
        // that is mid-dispatch can still get the old debug registers restored
        // on resume; the handler disarms those when they trap.
        set_breakpoint_on_all_threads(self.slot, 0, false);
        SLOT_TARGET[self.slot].store(0, Ordering::Release);
        SLOT_DETOUR[self.slot].store(0, Ordering::Release);

        let next = RETIRED_NEXT.fetch_add(1, Ordering::Relaxed) % RETIRED_COUNT;
        RETIRED[next].store(self.target as usize, Ordering::Release);
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
/// work: single-step exceptions whose address matches a live slot are
/// redirected, and a breakpoint that fired from one of our slots without a
/// matching hook is disarmed in the faulting thread; everything else is passed
/// straight through.
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

    // No live hook at this address. If DR6 says one of our breakpoint slots
    // fired here, the thread still carries a stale arming from a removed (or
    // replaced) hook: re-sync that slot in the context and resume. A slot only
    // counts as ours if neohook armed this very address in it.
    let ctx = unsafe { &mut *context };
    let hits = ctx.Dr6 & 0xF;
    let mut handled = false;
    for (slot, slot_target) in SLOT_TARGET.iter().enumerate() {
        let fired = hits & ((1 as DrWord) << slot) != 0;
        if !fired
            || debug_address(ctx, slot) != fault_addr as DrWord
            || SLOT_ARMED[slot].load(Ordering::Acquire) != fault_addr
        {
            continue;
        }
        let live = slot_target.load(Ordering::Acquire);
        program_slot(ctx, slot, live, live != 0);
        handled = true;
    }
    // The trap can also be captured after an unhook already rewrote the
    // thread's debug registers, so DR6 is empty or the fired slot no longer
    // holds the address, or after the slot was re-armed for another target.
    // Recognise those by the address of a recently removed hook, and re-sync
    // any fired slot that still holds it. A trap-flag single step is never one
    // of ours.
    if !handled
        && ctx.Dr6 & DR6_SINGLE_STEP == 0
        && RETIRED
            .iter()
            .any(|retired| retired.load(Ordering::Acquire) == fault_addr)
    {
        for (slot, slot_target) in SLOT_TARGET.iter().enumerate() {
            if hits & ((1 as DrWord) << slot) != 0
                && debug_address(ctx, slot) == fault_addr as DrWord
            {
                let live = slot_target.load(Ordering::Acquire);
                program_slot(ctx, slot, live, live != 0);
            }
        }
        handled = true;
    }
    if !handled {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    ctx.Dr6 = 0;
    // Resume flag: re-run the instruction without re-triggering a breakpoint.
    ctx.EFlags |= 0x1_0000;
    EXCEPTION_CONTINUE_EXECUTION
}

/// Returns the address held in `DR<slot>` of `ctx`.
fn debug_address(ctx: &CONTEXT, slot: usize) -> DrWord {
    match slot {
        0 => ctx.Dr0,
        1 => ctx.Dr1,
        2 => ctx.Dr2,
        _ => ctx.Dr3,
    }
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
            // A thread that cannot be suspended is left alone; if it keeps a
            // stale breakpoint, the handler disarms it on its next trap.
            if SuspendThread(h_thread) != u32::MAX {
                set_debug_register(h_thread, slot, address, enable);
                ResumeThread(h_thread);
            }
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

    program_slot(ctx, slot, address, enable);

    ctx.ContextFlags = CONTEXT_DEBUG;
    unsafe { SetThreadContext(h_thread, ctx) != 0 }
}

/// Sets (or clears) execution breakpoint `slot` in a context's debug
/// registers, preserving the other slots.
fn program_slot(ctx: &mut CONTEXT, slot: usize, address: usize, enable: bool) {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(16))]
    struct AlignedContext(CONTEXT);

    /// Calls the handler directly with a single-step at `addr` whose context
    /// carries `dr6` and `dr0`, as if the trap raced an unhook.
    fn handle_stale_trap(addr: usize, dr6: DrWord, dr0: DrWord) -> (i32, CONTEXT) {
        let mut ctx: AlignedContext = unsafe { std::mem::zeroed() };
        ctx.0.Dr6 = dr6;
        ctx.0.Dr0 = dr0;
        ctx.0.Dr7 = 1;
        let mut record: EXCEPTION_RECORD = unsafe { std::mem::zeroed() };
        record.ExceptionCode = STATUS_SINGLE_STEP;
        record.ExceptionAddress = addr as *mut _;
        let mut pointers = EXCEPTION_POINTERS {
            ExceptionRecord: &mut record,
            ContextRecord: &mut ctx.0,
        };
        let verdict = unsafe { veh_handler(&mut pointers) };
        (verdict, ctx.0)
    }

    #[test]
    fn handler_resumes_traps_of_removed_hooks() {
        // An address no live slot uses, recorded as recently removed.
        let addr = 0x7FFE_1230usize;
        let next = RETIRED_NEXT.fetch_add(1, Ordering::Relaxed) % RETIRED_COUNT;
        RETIRED[next].store(addr, Ordering::Release);

        // DR6 reports slot 0, but the unhook already cleared DR0.
        let (verdict, ctx) = handle_stale_trap(addr, 1, 0);
        assert_eq!(
            verdict, EXCEPTION_CONTINUE_EXECUTION,
            "DR6 hit, DR0 cleared"
        );
        assert_ne!(ctx.EFlags & 0x1_0000, 0, "resume flag set");
        assert_eq!(ctx.Dr6, 0, "DR6 consumed");

        // DR6 already empty.
        let (verdict, _) = handle_stale_trap(addr, 0, 0);
        assert_eq!(verdict, EXCEPTION_CONTINUE_EXECUTION, "DR6 empty");

        RETIRED[next].store(0, Ordering::Release);
    }

    /// Runs the handler on a single-step at `addr` with a raw DR6 and one
    /// debug register programmed, returning the verdict and the context.
    fn handle_trap_with(addr: usize, dr6: DrWord, slot: usize, dr: DrWord) -> (i32, CONTEXT) {
        let mut ctx: AlignedContext = unsafe { std::mem::zeroed() };
        ctx.0.Dr6 = dr6;
        program_slot(&mut ctx.0, slot, dr as usize, true);
        let mut record: EXCEPTION_RECORD = unsafe { std::mem::zeroed() };
        record.ExceptionCode = STATUS_SINGLE_STEP;
        record.ExceptionAddress = addr as *mut _;
        let mut pointers = EXCEPTION_POINTERS {
            ExceptionRecord: &mut record,
            ContextRecord: &mut ctx.0,
        };
        let verdict = unsafe { veh_handler(&mut pointers) };
        (verdict, ctx.0)
    }

    #[test]
    fn handler_leaves_foreign_hardware_breakpoints_alone() {
        // Another component's execution breakpoint in DR2, at an address
        // neohook never armed.
        let addr = 0x7FFE_7890usize;
        let (verdict, ctx) = handle_trap_with(addr, 1 << 2, 2, addr as DrWord);
        assert_eq!(verdict, EXCEPTION_CONTINUE_SEARCH, "foreign breakpoint");
        assert_eq!(ctx.Dr2, addr as DrWord, "foreign DR2 left armed");
        assert_ne!(ctx.Dr7 & (1 << 4), 0, "foreign DR7 enable left set");
    }

    #[test]
    fn handler_leaves_foreign_single_steps_on_removed_targets_alone() {
        // A trap-flag single step (DR6.BS) that happens to land on the address
        // of a removed hook belongs to whoever set the trap flag.
        let addr = 0x7FFE_ABC0usize;
        let next = RETIRED_NEXT.fetch_add(1, Ordering::Relaxed) % RETIRED_COUNT;
        RETIRED[next].store(addr, Ordering::Release);
        let (verdict, _) = handle_stale_trap(addr, 0x4000, 0);
        RETIRED[next].store(0, Ordering::Release);
        assert_eq!(verdict, EXCEPTION_CONTINUE_SEARCH, "trap-flag single step");
    }

    #[test]
    fn handler_leaves_foreign_single_steps_alone() {
        let (verdict, _) = handle_stale_trap(0x7FFE_4560, 0, 0);
        assert_eq!(verdict, EXCEPTION_CONTINUE_SEARCH);
    }

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
    fn original_gateway_forwards_to_real_function() {
        use std::sync::OnceLock;

        #[inline(never)]
        extern "system" fn base(x: u32) -> u32 {
            std::hint::black_box(x).wrapping_mul(3)
        }

        type Fn = extern "system" fn(u32) -> u32;
        static ORIG: OnceLock<Fn> = OnceLock::new();

        extern "system" fn detour_calls_orig(x: u32) -> u32 {
            ORIG.get().unwrap()(x) + 1
        }

        let target: Fn = base;
        let t = base as *const () as *const u8;
        let d = detour_calls_orig as *const () as *const u8;

        assert_eq!(target(4), 12, "sanity before hook");

        let hook = unsafe { VehHook::install_with_original(t, d) }.expect("install_with_original");
        let orig_ptr = hook.original_ptr().expect("gateway pointer present");
        ORIG.set(unsafe { std::mem::transmute::<*const u8, Fn>(orig_ptr) })
            .ok();

        // Detour ran (+1) and forwarded to the original (4 -> 12) through the
        // gateway, without re-triggering the hardware breakpoint.
        assert_eq!(
            target(4),
            13,
            "detour forwarded to the original via the gateway"
        );

        hook.unhook().unwrap();
        assert_eq!(target(4), 12, "original behaviour after unhook");
    }

    #[test]
    fn install_without_gateway_has_no_original_ptr() {
        let t = slot_target_a as *const () as *const u8;
        let d = slot_detour as *const () as *const u8;
        let hook = unsafe { VehHook::install(t, d) }.expect("install");
        assert!(
            hook.original_ptr().is_none(),
            "plain install must not expose a gateway"
        );
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
