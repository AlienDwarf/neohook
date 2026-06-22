// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Quiescence-gated reclamation of neohook-owned executable stubs.
//!
//! An inline trampoline, a VEH/INT3 gateway, an EAT jump stub and a mid-function
//! stub all live in memory neohook allocates. Freeing that memory the instant a
//! hook is dropped is unsound: another thread may still be executing inside the
//! stub - its instruction pointer in the stub, or a return address into it on the
//! stack - and freeing it then is a use-after-free.
//!
//! Instead a dropped stub is *retired* into a process-wide quarantine and freed
//! only once no thread is observed to be inside it. The check reuses the install
//! path's approach: the other threads are suspended, each instruction pointer and
//! a window of each stack are read, and only the regions no thread references are
//! released. Anything still in use stays quarantined and is retried on the next
//! pass.
//!
//! Retiring a stub is cheap (it only appends to the quarantine), so it is safe to
//! do from a `Drop` even while a transaction holds the process-wide lock - the
//! expensive suspend-and-scan never runs there. [`reclaim`] performs that pass; it
//! runs automatically at the start of every transaction (a no-op when the
//! quarantine is empty) and can also be called directly by code that only ever
//! unhooks and never installs again.

use std::sync::Mutex;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{CONTEXT, GetThreadContext};
use windows_sys::Win32::System::Memory::{
    MEM_RELEASE, MEMORY_BASIC_INFORMATION, VirtualFree, VirtualQuery,
};
use windows_sys::Win32::System::Threading::{
    OpenThread, ResumeThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
    THREAD_SUSPEND_RESUME,
};

#[cfg(target_arch = "x86_64")]
const CONTEXT_FLAGS: u32 = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_ALL_AMD64;
#[cfg(target_arch = "x86")]
const CONTEXT_FLAGS: u32 = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_ALL_X86;

/// How many stack slots are inspected per thread for return addresses pointing
/// into a retired stub. Mirrors the install path's `STACK_SCAN_DEPTH`.
const STACK_SCAN_DEPTH: usize = 512;

/// A retired executable region awaiting release, stored as integers so the
/// quarantine is `Send`.
#[derive(Clone, Copy)]
struct Region {
    base: usize,
    size: usize,
}

/// Process-wide quarantine of stubs whose hooks were dropped but which may still
/// have a thread executing inside them.
static QUARANTINE: Mutex<Vec<Region>> = Mutex::new(Vec::new());

fn lock_quarantine() -> std::sync::MutexGuard<'static, Vec<Region>> {
    QUARANTINE.lock().unwrap_or_else(|p| p.into_inner())
}

/// Hands an executable stub over for deferred, quiescence-checked release instead
/// of freeing it immediately.
///
/// Only appends to the quarantine, so it never suspends a thread or takes the
/// transaction lock - safe to call from a `Drop` running inside a commit/rollback.
pub(crate) fn retire(ptr: *mut u8, size: usize) {
    if ptr.is_null() || size == 0 {
        return;
    }
    lock_quarantine().push(Region {
        base: ptr as usize,
        size,
    });
}

/// Releases every quarantined stub that no thread is currently executing inside.
///
/// Suspends the other threads once, reads each instruction pointer and a window of
/// each stack, and frees only the regions nothing references; the rest stay
/// quarantined for a later pass. Best-effort: if a transaction currently holds the
/// process-wide lock (including this thread mid-commit), the pass is skipped and
/// the regions simply remain quarantined.
pub fn reclaim() {
    // Cheap early-out: nothing retired since the last pass.
    if lock_quarantine().is_empty() {
        return;
    }

    // Coordinate with the install engine: take the process-wide lock without
    // blocking. If a transaction holds it - possibly this very thread, mid
    // commit/rollback, where suspending threads would deadlock - defer.
    let Some(_guard) = crate::transaction::try_lock_transaction() else {
        return;
    };

    // Drain the quarantine while no thread is suspended.
    let regions: Vec<Region> = std::mem::take(&mut *lock_quarantine());
    if regions.is_empty() {
        return;
    }

    let still_busy = unsafe { free_quiescent_regions(regions) };

    if !still_busy.is_empty() {
        lock_quarantine().extend(still_busy);
    }
}

/// Suspends the other threads, frees the regions none of them are inside, and
/// returns the regions that are still in use.
///
/// All threads stay suspended across the scan *and* the frees, so a region cannot
/// be entered between deciding it is idle and releasing it. To avoid the classic
/// "allocate while a thread is suspended" heap-lock deadlock, every buffer is
/// reserved before the first thread is suspended.
unsafe fn free_quiescent_regions(regions: Vec<Region>) -> Vec<Region> {
    let tids = crate::threads::ThreadEnumerator::enumerate_process_threads();

    // Reserve up front so no push reallocates (which would take the heap lock)
    // while threads are suspended.
    let mut handles: Vec<HANDLE> = Vec::with_capacity(tids.len());
    let mut live: Vec<usize> = Vec::with_capacity(tids.len() * (STACK_SCAN_DEPTH + 4) + 4);
    let mut still_busy: Vec<Region> = Vec::with_capacity(regions.len());

    unsafe {
        // Freeze every other thread.
        for tid in tids {
            let h = OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                0,
                tid,
            );
            if h.is_null() {
                continue;
            }
            if SuspendThread(h) == u32::MAX {
                CloseHandle(h);
                continue;
            }
            handles.push(h);
        }

        // Collect every live code address: each instruction pointer plus a window
        // of each stack (return addresses left by calls through the stub).
        for &h in &handles {
            collect_thread_addresses(h, &mut live);
        }

        // Free what nothing references; keep the rest. Done while still frozen so
        // a thread cannot jump into a region between the check and the free.
        for r in regions {
            let busy = live
                .iter()
                .any(|&a| a >= r.base && a < r.base.saturating_add(r.size));
            if busy {
                still_busy.push(r);
            } else {
                VirtualFree(r.base as *mut _, 0, MEM_RELEASE);
            }
        }

        // Thaw.
        for h in handles {
            ResumeThread(h);
            CloseHandle(h);
        }
    }

    still_busy
}

/// Reads a suspended thread's instruction pointer and a window of its stack into
/// `live`. Skips silently if the context cannot be read.
unsafe fn collect_thread_addresses(h_thread: HANDLE, live: &mut Vec<usize>) {
    unsafe {
        #[repr(align(16))]
        struct AlignedContext(CONTEXT);
        let mut ctx: AlignedContext = std::mem::zeroed();
        ctx.0.ContextFlags = CONTEXT_FLAGS;

        if GetThreadContext(h_thread, &mut ctx.0) == 0 {
            return;
        }

        #[cfg(target_arch = "x86_64")]
        let (ip, sp) = (ctx.0.Rip as usize, ctx.0.Rsp as usize);
        #[cfg(target_arch = "x86")]
        let (ip, sp) = (ctx.0.Eip as usize, ctx.0.Esp as usize);

        live.push(ip);

        // Walk the top of the stack, stopping at the end of the committed region.
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        if VirtualQuery(
            sp as *const _,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        ) == 0
        {
            return;
        }
        let stack_top = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);

        for i in 0..STACK_SCAN_DEPTH {
            let slot = sp + i * std::mem::size_of::<usize>();
            if slot + std::mem::size_of::<usize>() > stack_top {
                break;
            }
            let mut value: usize = 0;
            std::ptr::copy_nonoverlapping(slot as *const usize, &mut value, 1);
            live.push(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retire_then_reclaim_frees_idle_region() {
        use windows_sys::Win32::System::Memory::{
            MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc,
        };

        let region = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                0x1000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        assert!(!region.is_null(), "allocation failed");

        // No thread is executing inside this freshly allocated page, so a reclaim
        // pass must release it.
        retire(region as *mut u8, 0x1000);
        reclaim();

        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let q = unsafe {
            VirtualQuery(
                region,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        assert_ne!(q, 0, "VirtualQuery after reclaim failed");
        assert_eq!(
            mbi.State,
            windows_sys::Win32::System::Memory::MEM_FREE,
            "an idle retired region should be released by reclaim"
        );
    }
}
