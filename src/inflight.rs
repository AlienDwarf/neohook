// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Detects threads that are still dispatching an exception raised at one of a
//! set of addresses.
//!
//! The INT3 and VEH hooks redirect through a vectored exception handler. Once
//! the last hook is gone the handler can be removed - which it must be before
//! the module holding it is unloaded - but only after every thread that already
//! trapped on a removed hook has left the handler. A trap that is still being
//! dispatched when the handler disappears reaches no handler at all and
//! crashes the process.
//!
//! While an exception is dispatched, the kernel keeps its `EXCEPTION_RECORD`
//! on the faulting thread's user stack, above the stack pointer, until
//! `NtContinue` resumes the thread. A thread suspended at any point of that
//! window - inside `KiUserExceptionDispatcher`, the vectored handler list or
//! the handler itself - therefore still has a record on its stack whose code
//! and address match the trap. Once the thread is resumed the record lies
//! below the stack pointer and is no longer found.
//!
//! Debug registers add a second case. Every exception dispatch saves the
//! thread's `CONTEXT`, debug registers included, next to its record and
//! restores it on resume. A thread dispatching any exception while a VEH
//! breakpoint was armed gets that breakpoint back when it resumes, even after
//! the unhook cleared its live registers, and then needs the handler. Such a
//! saved context, with a trap address in an enabled `DR0`-`DR3`, counts as in
//! flight too.
//!
//! A thread can also be stopped in the trap before any record is on the stack
//! that is scanned: inside the kernel while a debugger sees the first chance,
//! or in the 64-bit half of a WOW64 dispatch. Its instruction pointer is then
//! still at the trap (or just past an `int3`), so that counts as well.

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, GetLastError, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{CONTEXT, GetThreadContext};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualQuery,
};
use windows_sys::Win32::System::Threading::{
    GetExitCodeThread, OpenThread, ResumeThread, SuspendThread, THREAD_GET_CONTEXT,
    THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
};

#[cfg(target_arch = "x86_64")]
const CONTEXT_FLAGS: u32 = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_AMD64;
#[cfg(target_arch = "x86")]
const CONTEXT_FLAGS: u32 = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_X86;

/// `ContextFlags` of a saved context that carries the debug registers.
#[cfg(target_arch = "x86_64")]
const CONTEXT_DEBUG: u32 =
    windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_DEBUG_REGISTERS_AMD64;
#[cfg(target_arch = "x86")]
const CONTEXT_DEBUG: u32 =
    windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_DEBUG_REGISTERS_X86;

/// Offset of `ExceptionAddress` inside `EXCEPTION_RECORD`.
#[cfg(target_arch = "x86_64")]
const ADDRESS_OFFSET: usize = 16;
#[cfg(target_arch = "x86")]
const ADDRESS_OFFSET: usize = 12;

/// `STILL_ACTIVE`, the exit code of a thread that has not exited yet.
const THREAD_STILL_ACTIVE: u32 = 259;

/// Upper bound on the stack bytes read per thread; a larger stack counts as not
/// inspected.
const MAX_STACK_SCAN_BYTES: usize = 32 * 1024 * 1024;

const WORD: usize = std::mem::size_of::<usize>();

/// Returns `true` if any other thread may still be dispatching an exception
/// with `code` raised at an address for which `is_trap_address` holds - or,
/// with `saved_debug_registers`, any exception whose saved context arms a
/// debug register at such an address.
///
/// Suspends every other thread once and reads each stack. A thread that cannot
/// be opened, suspended or read counts as in flight, so the answer errs towards
/// keeping the handler. Allocates nothing while threads are suspended, and
/// `is_trap_address` must not either.
pub(crate) fn exceptions_in_flight(
    code: i32,
    is_trap_address: impl Fn(usize) -> bool,
    saved_debug_registers: bool,
) -> bool {
    let _freeze = crate::threads::hold_freeze_lock();
    let tids = crate::threads::ThreadEnumerator::enumerate_process_threads();
    // Reserved before the first suspension.
    let mut handles: Vec<HANDLE> = Vec::with_capacity(tids.len());
    let access = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION;

    let mut in_flight = false;
    unsafe {
        for &tid in &tids {
            let h = OpenThread(access, 0, tid);
            if h.is_null() {
                // A thread that already exited is not dispatching anything.
                if GetLastError() != ERROR_INVALID_PARAMETER {
                    in_flight = true;
                }
                continue;
            }
            if SuspendThread(h) == u32::MAX {
                if !thread_has_exited(h) {
                    in_flight = true;
                }
                CloseHandle(h);
                continue;
            }
            handles.push(h);
        }

        if !in_flight {
            for &h in &handles {
                if dispatching(h, code, &is_trap_address, saved_debug_registers) {
                    in_flight = true;
                    break;
                }
            }
        }

        for h in handles {
            ResumeThread(h);
            CloseHandle(h);
        }
    }
    in_flight
}

/// Whether the suspended thread `h` has a matching exception record (or saved
/// context) on its stack, or could not be inspected.
unsafe fn dispatching(
    h: HANDLE,
    code: i32,
    is_trap_address: &impl Fn(usize) -> bool,
    saved_debug_registers: bool,
) -> bool {
    unsafe {
        #[repr(align(16))]
        struct AlignedContext(CONTEXT);
        let mut ctx: AlignedContext = std::mem::zeroed();
        ctx.0.ContextFlags = CONTEXT_FLAGS;
        if GetThreadContext(h, &mut ctx.0) == 0 {
            return true;
        }
        #[cfg(target_arch = "x86_64")]
        let (ip, sp) = (ctx.0.Rip as usize, ctx.0.Rsp as usize);
        #[cfg(target_arch = "x86")]
        let (ip, sp) = (ctx.0.Eip as usize, ctx.0.Esp as usize);

        if is_trap_address(ip) || is_trap_address(ip.wrapping_sub(1)) {
            return true;
        }

        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
        if VirtualQuery(sp as *const _, &mut mbi, size) == 0 {
            return true;
        }
        let stack_allocation = mbi.AllocationBase as usize;

        let mut scanned = 0usize;
        let mut addr = sp;
        loop {
            if VirtualQuery(addr as *const _, &mut mbi, size) == 0 {
                return true;
            }
            if mbi.AllocationBase as usize != stack_allocation {
                return false;
            }
            let region_end = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
            if region_end <= addr {
                return false;
            }
            if mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0 {
                // `ExceptionAddress` is pointer-aligned, and `ExceptionCode`
                // sits `ADDRESS_OFFSET` bytes before it in the same record.
                let region_start = (mbi.BaseAddress as usize).max(sp);
                let mut slot = region_start.next_multiple_of(WORD);
                while slot.saturating_add(WORD) <= region_end {
                    scanned += WORD;
                    if scanned > MAX_STACK_SCAN_BYTES {
                        return true;
                    }
                    let value = std::ptr::read(slot as *const usize);
                    if is_trap_address(value) {
                        if slot >= region_start + ADDRESS_OFFSET
                            && std::ptr::read((slot - ADDRESS_OFFSET) as *const i32) == code
                        {
                            return true;
                        }
                        if saved_debug_registers
                            && arms_debug_register(slot, region_start, region_end)
                        {
                            return true;
                        }
                    }
                    slot += WORD;
                }
            }
            addr = region_end;
        }
    }
}

/// Whether the trap address at `slot` is `DR0`-`DR3` of a saved `CONTEXT` that
/// carries the debug registers and has that breakpoint enabled in `DR7`.
unsafe fn arms_debug_register(slot: usize, region_start: usize, region_end: usize) -> bool {
    let dr0 = std::mem::offset_of!(CONTEXT, Dr0);
    let flags = std::mem::offset_of!(CONTEXT, ContextFlags);
    let dr7 = std::mem::offset_of!(CONTEXT, Dr7);
    for n in 0..4 {
        let Some(base) = slot.checked_sub(dr0 + n * WORD) else {
            continue;
        };
        if base < region_start || base.saturating_add(std::mem::size_of::<CONTEXT>()) > region_end {
            continue;
        }
        let context_flags = unsafe { std::ptr::read((base + flags) as *const u32) };
        let dr7_value = unsafe { std::ptr::read((base + dr7) as *const usize) };
        if context_flags & CONTEXT_DEBUG == CONTEXT_DEBUG && dr7_value & (1 << (2 * n)) != 0 {
            return true;
        }
    }
    false
}

unsafe fn thread_has_exited(h: HANDLE) -> bool {
    unsafe {
        let mut code: u32 = 0;
        GetExitCodeThread(h, &mut code) != 0 && code != THREAD_STILL_ACTIVE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use windows_sys::Win32::System::Diagnostics::Debug::{
        AddVectoredExceptionHandler, EXCEPTION_POINTERS, RaiseException,
        RemoveVectoredExceptionHandler,
    };

    const PARK_CODE: i32 = 0xE04E_4801_u32 as i32;
    static PARKED: AtomicBool = AtomicBool::new(false);
    static RELEASE: AtomicBool = AtomicBool::new(false);
    static RAISED_AT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    /// Parks the raising thread inside the dispatch until released.
    unsafe extern "system" fn parking_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
        if unsafe { (*(*info).ExceptionRecord).ExceptionCode } != PARK_CODE {
            return 0;
        }
        let raised_at = unsafe { (*(*info).ExceptionRecord).ExceptionAddress } as usize;
        RAISED_AT.store(raised_at, Ordering::Release);
        PARKED.store(true, Ordering::Release);
        while !RELEASE.load(Ordering::Acquire) {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        -1
    }

    #[test]
    fn sees_a_thread_parked_inside_the_dispatch() {
        let handler = unsafe { AddVectoredExceptionHandler(1, Some(parking_handler)) };
        assert!(!handler.is_null());

        let raiser = std::thread::spawn(|| unsafe {
            RaiseException(PARK_CODE as u32, 0, 0, std::ptr::null());
        });
        while !PARKED.load(Ordering::Acquire) {
            std::thread::yield_now();
        }

        let raised_at = RAISED_AT.load(Ordering::Acquire);
        let is_raise = |a: usize| a == raised_at;
        let parked = exceptions_in_flight(PARK_CODE, is_raise, false);
        let other_code = exceptions_in_flight(PARK_CODE ^ 1, is_raise, false);
        let other_address = exceptions_in_flight(PARK_CODE, |_| false, false);

        RELEASE.store(true, Ordering::Release);
        raiser.join().unwrap();
        let after = exceptions_in_flight(PARK_CODE, is_raise, false);
        unsafe { RemoveVectoredExceptionHandler(handler) };

        assert!(parked, "a thread inside the dispatch is in flight");
        assert!(!other_code, "only records with the given code match");
        assert!(!other_address, "only records at a trap address match");
        assert!(!after, "a resumed thread is no longer in flight");
    }

    static SPINNING: AtomicBool = AtomicBool::new(false);
    static STOP_SPIN: AtomicBool = AtomicBool::new(false);

    #[inline(never)]
    fn spin() {
        SPINNING.store(true, Ordering::Release);
        while !STOP_SPIN.load(Ordering::Relaxed) {
            std::hint::spin_loop();
        }
    }

    #[test]
    fn sees_a_thread_stopped_at_a_trap_address() {
        let spinner = std::thread::spawn(spin);
        while !SPINNING.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        let start = spin as *const () as usize;
        let in_spin = |a: usize| (start..start + 0x100).contains(&a);

        let at_trap = exceptions_in_flight(PARK_CODE ^ 2, in_spin, false);
        let elsewhere = exceptions_in_flight(PARK_CODE ^ 2, |_| false, false);

        STOP_SPIN.store(true, Ordering::Relaxed);
        spinner.join().unwrap();
        assert!(
            at_trap,
            "a thread whose IP is at a trap address is in flight"
        );
        assert!(!elsewhere);
    }

    static ARMED_PARKED: AtomicBool = AtomicBool::new(false);
    static ARMED_RELEASE: AtomicBool = AtomicBool::new(false);
    const ARMED_CODE: i32 = 0xE04E_4802_u32 as i32;
    /// Never executed, so a breakpoint on it never fires.
    static BREAKPOINT_SITE: u8 = 0;

    unsafe extern "system" fn armed_parking_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
        if unsafe { (*(*info).ExceptionRecord).ExceptionCode } != ARMED_CODE {
            return 0;
        }
        ARMED_PARKED.store(true, Ordering::Release);
        while !ARMED_RELEASE.load(Ordering::Acquire) {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        -1
    }

    #[test]
    fn sees_a_saved_context_that_rearms_a_breakpoint() {
        use windows_sys::Win32::System::Diagnostics::Debug::SetThreadContext;
        use windows_sys::Win32::System::Threading::GetCurrentThread;

        let site = &BREAKPOINT_SITE as *const u8 as usize;
        let handler = unsafe { AddVectoredExceptionHandler(1, Some(armed_parking_handler)) };
        assert!(!handler.is_null());

        // The thread arms DR0 on itself, then dispatches an unrelated
        // exception: its saved context carries the armed DR0.
        let raiser = std::thread::spawn(move || unsafe {
            #[repr(align(16))]
            struct AlignedContext(CONTEXT);
            let mut ctx: AlignedContext = std::mem::zeroed();
            ctx.0.ContextFlags = CONTEXT_DEBUG;
            ctx.0.Dr0 = site as _;
            ctx.0.Dr7 = 1;
            assert_ne!(SetThreadContext(GetCurrentThread(), &ctx.0), 0);
            RaiseException(ARMED_CODE as u32, 0, 0, std::ptr::null());
            ctx.0.Dr0 = 0;
            ctx.0.Dr7 = 0;
            SetThreadContext(GetCurrentThread(), &ctx.0);
        });
        while !ARMED_PARKED.load(Ordering::Acquire) {
            std::thread::yield_now();
        }

        let with = exceptions_in_flight(ARMED_CODE ^ 1, |a| a == site, true);
        let without = exceptions_in_flight(ARMED_CODE ^ 1, |a| a == site, false);

        ARMED_RELEASE.store(true, Ordering::Release);
        raiser.join().unwrap();
        unsafe { RemoveVectoredExceptionHandler(handler) };

        assert!(with, "a saved context arming a trap address is in flight");
        assert!(!without, "only checked when asked for");
    }
}
