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
//! only once no thread is observed to be inside it. The other threads are
//! suspended, each instruction pointer and each thread's whole committed stack
//! are read, and only the regions no thread references are released. Anything
//! still in use stays quarantined and is retried on the next pass.
//!
//! The scan must be complete to be sound: a stub is freed only when *every*
//! thread was suspended and fully inspected. A thread that cannot be opened,
//! suspended, or read keeps the entire quarantine for a later pass rather than
//! counting as idle.
//!
//! Retiring a stub is cheap (it only appends to the quarantine), so it is safe to
//! do from a `Drop` even while a transaction holds the process-wide lock - the
//! expensive suspend-and-scan never runs there. [`reclaim`] performs that pass; it
//! runs automatically at the start of every transaction (a no-op when the
//! quarantine is empty) and can also be called directly by code that only ever
//! unhooks and never installs again.

use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, GetLastError, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{CONTEXT, GetThreadContext};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualFree,
    VirtualQuery,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThreadId, GetExitCodeThread, GetThreadId, OpenThread,
    ResumeThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
    THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
};

#[cfg(target_arch = "x86_64")]
const CONTEXT_FLAGS: u32 = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_ALL_AMD64;
#[cfg(target_arch = "x86")]
const CONTEXT_FLAGS: u32 = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_ALL_X86;

/// Access a thread handle needs to be frozen and inspected by a pass.
const THREAD_ACCESS: u32 = THREAD_SUSPEND_RESUME
    | THREAD_GET_CONTEXT
    | THREAD_QUERY_INFORMATION
    | THREAD_QUERY_LIMITED_INFORMATION;

/// `STILL_ACTIVE`, the exit code of a thread that has not exited yet. Declared
/// here because windows-sys only exposes it behind a feature the crate does not
/// otherwise need.
const THREAD_STILL_ACTIVE: u32 = 259;

/// Upper bound on the stack bytes read per thread. A stack larger than this is
/// reported as not fully inspected (so nothing is freed) rather than silently
/// scanned in part, which is what made a deep return address look absent.
const MAX_STACK_SCAN_BYTES: usize = 32 * 1024 * 1024;

/// Spare handle slots reserved for threads created after the enumeration, which
/// a pass freezes and inspects as it finds them.
const NEW_THREAD_SLACK: usize = 32;

/// How many times a pass re-walks the thread list looking for threads created
/// after the previous walk.
const WALK_ROUNDS: usize = 4;

/// Size of one stack slot.
const WORD: usize = std::mem::size_of::<usize>();

/// `ntdll!NtGetNextThread`, which walks the threads of a process one handle at a
/// time. Unlike a Toolhelp snapshot it allocates nothing, so it is usable while
/// the other threads are suspended.
type NtGetNextThreadFn = unsafe extern "system" fn(
    process: HANDLE,
    thread: HANDLE,
    access: u32,
    attributes: u32,
    flags: u32,
    new_thread: *mut HANDLE,
) -> i32;

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

/// Holds the quarantine lock for `duration`, setting `held` once it is taken.
#[cfg(all(test, target_arch = "x86_64"))]
pub(crate) fn hold_quarantine(held: &std::sync::atomic::AtomicBool, duration: std::time::Duration) {
    let _quarantine = lock_quarantine();
    held.store(true, std::sync::atomic::Ordering::Release);
    std::thread::sleep(duration);
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
/// Suspends the other threads once, reads each instruction pointer and each whole
/// stack, and frees only the regions nothing references; the rest stay quarantined
/// for a later pass, as does everything if any thread could not be inspected.
/// Best-effort: if a transaction currently holds the process-wide lock (including
/// this thread mid-commit), the pass is skipped and the regions simply remain
/// quarantined.
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

    // Unwind tables go before anything is suspended (their lock could be held
    // by a frozen thread), and come back for the regions that stay.
    let bases: Vec<usize> = regions.iter().map(|r| r.base).collect();
    crate::unwind::suspend(&bases);

    let still_busy = unsafe { free_quiescent_regions(regions) };

    let busy_bases: Vec<usize> = still_busy.iter().map(|r| r.base).collect();
    crate::unwind::settle(&bases, &busy_bases);

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
    // Another thread is suspending the process right now: try again later.
    let Some(_freeze) = crate::threads::try_hold_freeze_lock() else {
        return regions;
    };
    let tids = crate::threads::ThreadEnumerator::enumerate_process_threads();

    // Resolve the thread walker before anything is frozen: `GetModuleHandle`
    // takes the loader lock, which a suspended thread could own.
    let next_thread = nt_get_next_thread();

    // Reserve up front so no push reallocates (which would take the heap lock)
    // while threads are suspended. Inputs are iterated by reference for the same
    // reason: consuming them would free their buffers inside the frozen window.
    let capacity = tids.len() + NEW_THREAD_SLACK;
    let mut handles: Vec<HANDLE> = Vec::with_capacity(capacity);
    let mut frozen: Vec<u32> = Vec::with_capacity(capacity);
    let mut busy: Vec<bool> = vec![false; regions.len()];
    let mut still_busy: Vec<Region> = Vec::with_capacity(regions.len());

    // Cleared by anything that leaves a thread uninspected. Regions are freed
    // only when every thread in the process was accounted for.
    let mut inspected_all = true;

    unsafe {
        // Freeze every other thread.
        for &tid in &tids {
            let h = OpenThread(THREAD_ACCESS, 0, tid);
            if h.is_null() {
                // A thread that exited between the enumeration and here cannot
                // reference a stub; any other failure leaves it uninspected.
                if GetLastError() != ERROR_INVALID_PARAMETER {
                    inspected_all = false;
                }
                continue;
            }
            if SuspendThread(h) == u32::MAX {
                if thread_has_exited(h) {
                    // Remember it, so the catch-up walk does not stop on it as
                    // a new thread.
                    frozen.push(tid);
                } else {
                    inspected_all = false;
                }
                CloseHandle(h);
                continue;
            }
            handles.push(h);
            frozen.push(tid);
        }

        // Check every live code address: each instruction pointer plus every
        // committed stack slot (return addresses left by calls through the stub).
        for &h in &handles {
            if !inspect_thread(h, &regions, &mut busy) {
                inspected_all = false;
            }
        }

        // Threads created after the enumeration above are not in `handles` yet.
        if !catch_up_new_threads(next_thread, &mut handles, &mut frozen, &regions, &mut busy) {
            inspected_all = false;
        }

        // Free what nothing references; keep the rest. Done while still frozen so
        // a thread cannot jump into a region between the check and the free.
        for (&r, &is_busy) in regions.iter().zip(busy.iter()) {
            if is_busy || !inspected_all {
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

/// Marks every region `addr` falls inside.
fn mark(addr: usize, regions: &[Region], busy: &mut [bool]) {
    for (r, is_busy) in regions.iter().zip(busy.iter_mut()) {
        if !*is_busy && addr >= r.base && addr < r.base.saturating_add(r.size) {
            *is_busy = true;
        }
    }
}

/// Reads a suspended thread's instruction pointer, general registers and whole
/// stack, marking the regions any of them references. Returns `false` if the thread could not be
/// inspected in full, in which case it must not be treated as idle.
unsafe fn inspect_thread(h_thread: HANDLE, regions: &[Region], busy: &mut [bool]) -> bool {
    unsafe {
        #[repr(align(16))]
        struct AlignedContext(CONTEXT);
        let mut ctx: AlignedContext = std::mem::zeroed();
        ctx.0.ContextFlags = CONTEXT_FLAGS;

        if GetThreadContext(h_thread, &mut ctx.0) == 0 {
            return false;
        }

        #[cfg(target_arch = "x86_64")]
        let (ip, sp) = (ctx.0.Rip as usize, ctx.0.Rsp as usize);
        #[cfg(target_arch = "x86")]
        let (ip, sp) = (ctx.0.Eip as usize, ctx.0.Esp as usize);

        mark(ip, regions, busy);
        // A detour can hold a trampoline pointer in a register it is about to
        // call through, with no copy on the stack.
        #[cfg(target_arch = "x86_64")]
        let registers = [
            ctx.0.Rax, ctx.0.Rbx, ctx.0.Rcx, ctx.0.Rdx, ctx.0.Rsi, ctx.0.Rdi, ctx.0.Rbp, ctx.0.R8,
            ctx.0.R9, ctx.0.R10, ctx.0.R11, ctx.0.R12, ctx.0.R13, ctx.0.R14, ctx.0.R15,
        ];
        #[cfg(target_arch = "x86")]
        let registers = [
            ctx.0.Eax, ctx.0.Ebx, ctx.0.Ecx, ctx.0.Edx, ctx.0.Esi, ctx.0.Edi, ctx.0.Ebp,
        ];
        for register in registers {
            mark(register as usize, regions, busy);
        }
        scan_stack(sp, regions, busy)
    }
}

/// Walks a suspended thread's stack from its stack pointer up to the end of the
/// stack allocation, marking the regions any slot points into.
///
/// The upper bound is the end of the reservation holding the stack pointer -
/// equivalent to the thread's `NT_TIB::StackBase`, but readable with
/// `VirtualQuery` alone, without a TEB lookup per thread. Only committed,
/// readable pages are read; uncommitted or guarded ones are skipped.
///
/// Returns `false` if the walk could not be completed.
unsafe fn scan_stack(sp: usize, regions: &[Region], busy: &mut [bool]) -> bool {
    unsafe {
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

        if VirtualQuery(sp as *const _, &mut mbi, size) == 0 {
            return false;
        }
        let stack_allocation = mbi.AllocationBase as usize;

        let mut scanned = 0usize;
        let mut addr = sp;
        loop {
            if VirtualQuery(addr as *const _, &mut mbi, size) == 0 {
                return false;
            }
            // Past the end of the stack reservation.
            if mbi.AllocationBase as usize != stack_allocation {
                return true;
            }
            let region_end = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
            if region_end <= addr {
                return true;
            }

            if mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0 {
                let mut slot = addr.next_multiple_of(WORD);
                while slot.saturating_add(WORD) <= region_end {
                    scanned += WORD;
                    if scanned > MAX_STACK_SCAN_BYTES {
                        return false;
                    }
                    let mut value: usize = 0;
                    std::ptr::copy_nonoverlapping(slot as *const usize, &mut value, 1);
                    mark(value, regions, busy);
                    slot += WORD;
                }
            }

            addr = region_end;
        }
    }
}

/// True if the thread behind `h_thread` has already exited, so it can hold no
/// reference to a retired stub.
unsafe fn thread_has_exited(h_thread: HANDLE) -> bool {
    unsafe {
        let mut code: u32 = 0;
        GetExitCodeThread(h_thread, &mut code) != 0 && code != THREAD_STILL_ACTIVE
    }
}

/// Cached pointer to `ntdll!NtGetNextThread`, resolved once.
fn nt_get_next_thread() -> Option<NtGetNextThreadFn> {
    static ADDR: OnceLock<Option<usize>> = OnceLock::new();
    let addr = *ADDR.get_or_init(|| unsafe {
        let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr().cast());
        if ntdll.is_null() {
            return None;
        }
        GetProcAddress(ntdll, c"NtGetNextThread".as_ptr().cast()).map(|p| p as usize)
    });
    addr.map(|a| unsafe { std::mem::transmute::<usize, NtGetNextThreadFn>(a) })
}

/// Freezes and inspects any thread the pre-suspend enumeration missed, which a
/// Toolhelp snapshot cannot find again without allocating.
///
/// Walks the process's threads with the allocation-free `NtGetNextThread`, and
/// for every thread that is neither this one nor already frozen, suspends and
/// inspects it, then restarts the walk in case it spawned more. Returns `false`
/// if a thread could not be caught up, so nothing may be freed.
unsafe fn catch_up_new_threads(
    next_thread: Option<NtGetNextThreadFn>,
    handles: &mut Vec<HANDLE>,
    frozen: &mut Vec<u32>,
    regions: &[Region],
    busy: &mut [bool],
) -> bool {
    let Some(next_thread) = next_thread else {
        // Before Windows 8 there is no allocation-free thread walk, and
        // enumerating again here would risk the heap lock a suspended thread may
        // own. A thread created after the enumeration stays uninspected there.
        return true;
    };

    unsafe {
        let process = GetCurrentProcess();
        let current = GetCurrentThreadId();

        for _ in 0..WALK_ROUNDS {
            let mut restart = false;
            let mut cursor: HANDLE = std::ptr::null_mut();

            loop {
                let mut found: HANDLE = std::ptr::null_mut();
                let status = next_thread(process, cursor, THREAD_ACCESS, 0, 0, &mut found);
                // The cursor is only needed until the call that follows it.
                if !cursor.is_null() {
                    CloseHandle(cursor);
                    cursor = std::ptr::null_mut();
                }
                if status != 0 || found.is_null() {
                    break;
                }

                let tid = GetThreadId(found);
                if tid == current || tid == 0 || frozen.contains(&tid) {
                    cursor = found;
                    continue;
                }

                // A thread created after the enumeration.
                // Never grow either buffer here: a push that reallocates would
                // take the heap lock a suspended thread may hold.
                if handles.len() == handles.capacity() || frozen.len() == frozen.capacity() {
                    CloseHandle(found);
                    return false;
                }
                if SuspendThread(found) == u32::MAX {
                    if !thread_has_exited(found) {
                        CloseHandle(found);
                        return false;
                    }
                    // Already gone, so it references nothing and spawned
                    // nothing new: remember it and keep walking from it.
                    frozen.push(tid);
                    cursor = found;
                    continue;
                }
                // Keep its handle in `handles` so it is resumed with the rest,
                // and walk again: it may have spawned threads of its own.
                restart = true;
                handles.push(found);
                frozen.push(tid);
                if !inspect_thread(found, regions, busy) {
                    return false;
                }
                break;
            }

            if !cursor.is_null() {
                CloseHandle(cursor);
            }
            if !restart {
                return true;
            }
        }

        // Threads kept appearing; try again on a later pass.
        false
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

    /// XOR mask that keeps the region address off the stack in readable form.
    const MASK: usize = 0x5A5A_5A5A;

    /// Unmasks `masked` into a callee-saved register and spins there until
    /// `*stop` is set, so the address lives only in that register.
    #[cfg(target_arch = "x86_64")]
    #[unsafe(naked)]
    unsafe extern "C" fn hold_in_register(_masked: usize, _stop: *const u8) {
        std::arch::naked_asm!(
            "push rbx",
            "mov rbx, rcx",
            "xor rbx, {mask}",
            "2:",
            "pause",
            "cmp byte ptr [rdx], 0",
            "je 2b",
            "pop rbx",
            "ret",
            mask = const MASK,
        );
    }

    #[cfg(target_arch = "x86")]
    #[unsafe(naked)]
    unsafe extern "C" fn hold_in_register(_masked: usize, _stop: *const u8) {
        std::arch::naked_asm!(
            "push ebx",
            "mov ebx, [esp + 8]",
            "xor ebx, {mask}",
            "mov ecx, [esp + 12]",
            "2:",
            "pause",
            "cmp byte ptr [ecx], 0",
            "je 2b",
            "pop ebx",
            "ret",
            mask = const MASK,
        );
    }

    #[test]
    fn region_held_only_in_a_register_stays_quarantined() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use windows_sys::Win32::System::Memory::{
            MEM_COMMIT, MEM_FREE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc,
        };
        static STOP: AtomicBool = AtomicBool::new(false);

        let region = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                0x1000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        assert!(!region.is_null(), "allocation failed");
        let masked = region as usize ^ MASK;
        let holder = std::thread::spawn(move || unsafe {
            hold_in_register(masked, STOP.as_ptr() as *const u8)
        });
        std::thread::sleep(std::time::Duration::from_millis(100));

        let freed = |addr: *const core::ffi::c_void| {
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            let q = unsafe { VirtualQuery(addr, &mut mbi, std::mem::size_of_val(&mbi)) };
            q != 0 && mbi.State == MEM_FREE
        };
        retire(region as *mut u8, 0x1000);
        reclaim();
        let freed_while_held = freed(region);

        STOP.store(true, Ordering::Release);
        holder.join().unwrap();
        reclaim();
        assert!(
            !freed_while_held,
            "a region a thread holds in a register was freed"
        );
        assert!(freed(region), "freed once nothing references it");
    }

    /// Threads that have exited but whose handles are still open (an unjoined
    /// `JoinHandle`) reference nothing and must not keep an idle region
    /// quarantined, however many of them there are.
    #[test]
    fn exited_unjoined_threads_do_not_block_reclaim() {
        use windows_sys::Win32::System::Memory::{
            MEM_COMMIT, MEM_FREE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc,
        };

        let exited = 2 * WALK_ROUNDS;
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let handles: Vec<_> = (0..exited)
            .map(|_| {
                let done = done_tx.clone();
                std::thread::spawn(move || done.send(()).unwrap())
            })
            .collect();
        for _ in 0..exited {
            done_rx.recv().unwrap();
        }
        // Let the threads terminate; their handles stay open.
        std::thread::sleep(std::time::Duration::from_millis(200));

        let region = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                0x1000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        assert!(!region.is_null(), "allocation failed");
        retire(region as *mut u8, 0x1000);
        reclaim();

        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let q = unsafe { VirtualQuery(region, &mut mbi, std::mem::size_of_val(&mbi)) };
        let freed = q != 0 && mbi.State == MEM_FREE;
        // Drain the quarantine for later tests either way.
        drop(handles);
        reclaim();
        assert!(freed, "exited threads kept an idle region quarantined");
    }
}
