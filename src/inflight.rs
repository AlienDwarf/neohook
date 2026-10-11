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
/// with `code` raised at an address for which `is_trap_address` holds.
///
/// Suspends every other thread once and reads each stack. A thread that cannot
/// be opened, suspended or read counts as in flight, so the answer errs towards
/// keeping the handler. Allocates nothing while threads are suspended, and
/// `is_trap_address` must not either.
pub(crate) fn exceptions_in_flight(code: i32, is_trap_address: impl Fn(usize) -> bool) -> bool {
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
                if dispatching(h, code, &is_trap_address) {
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

/// Whether the suspended thread `h` has a matching exception record on its
/// stack, or could not be inspected.
unsafe fn dispatching(h: HANDLE, code: i32, is_trap_address: &impl Fn(usize) -> bool) -> bool {
    unsafe {
        #[repr(align(16))]
        struct AlignedContext(CONTEXT);
        let mut ctx: AlignedContext = std::mem::zeroed();
        ctx.0.ContextFlags = CONTEXT_FLAGS;
        if GetThreadContext(h, &mut ctx.0) == 0 {
            return true;
        }
        #[cfg(target_arch = "x86_64")]
        let sp = ctx.0.Rsp as usize;
        #[cfg(target_arch = "x86")]
        let sp = ctx.0.Esp as usize;

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
                    if slot >= region_start + ADDRESS_OFFSET {
                        let record = slot - ADDRESS_OFFSET;
                        if std::ptr::read(record as *const i32) == code
                            && is_trap_address(std::ptr::read(slot as *const usize))
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

    /// Parks the raising thread inside the dispatch until released.
    unsafe extern "system" fn parking_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
        if unsafe { (*(*info).ExceptionRecord).ExceptionCode } != PARK_CODE {
            return 0;
        }
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

        let parked = exceptions_in_flight(PARK_CODE, |_| true);
        let other_code = exceptions_in_flight(PARK_CODE ^ 1, |_| true);
        let other_address = exceptions_in_flight(PARK_CODE, |_| false);

        RELEASE.store(true, Ordering::Release);
        raiser.join().unwrap();
        let after = exceptions_in_flight(PARK_CODE, |_| true);
        unsafe { RemoveVectoredExceptionHandler(handler) };

        assert!(parked, "a thread inside the dispatch is in flight");
        assert!(!other_code, "only records with the given code match");
        assert!(!other_address, "only records at a trap address match");
        assert!(!after, "a resumed thread is no longer in flight");
    }
}
