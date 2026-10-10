#![cfg(windows)]

//! A transaction suspends every other thread before it patches code. Touching
//! the heap while they are frozen can deadlock against a thread that was
//! suspended holding the heap lock, so nothing between the first suspension and
//! the last resume may allocate or free - including a rollback after a failed
//! patch.
//!
//! A counting global allocator checks, on every heap operation made by the
//! committing thread, whether a parked witness thread is currently suspended.

use neohook::DetourTransaction;
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_DECOMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc,
    VirtualFree,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread, THREAD_SUSPEND_RESUME,
};

struct WitnessAlloc;

static CHECKING: AtomicBool = AtomicBool::new(false);
static CHECKED_THREAD: AtomicU32 = AtomicU32::new(0);
static WITNESS: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());
static HEAP_OPS_WHILE_FROZEN: AtomicUsize = AtomicUsize::new(0);

impl WitnessAlloc {
    fn check(&self) {
        if !CHECKING.load(Ordering::Acquire)
            || unsafe { GetCurrentThreadId() } != CHECKED_THREAD.load(Ordering::Acquire)
        {
            return;
        }
        let witness: HANDLE = WITNESS.load(Ordering::Acquire);
        if witness.is_null() {
            return;
        }
        // SuspendThread returns the previous suspend count: non-zero means the
        // transaction has the witness frozen right now.
        let previous = unsafe { SuspendThread(witness) };
        if previous != u32::MAX {
            unsafe { ResumeThread(witness) };
            if previous > 0 {
                HEAP_OPS_WHILE_FROZEN.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

unsafe impl GlobalAlloc for WitnessAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.check();
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.check();
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        self.check();
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: WitnessAlloc = WitnessAlloc;

#[inline(never)]
extern "system" fn commit_target(a: u32) -> u32 {
    black_box(a).wrapping_mul(7).wrapping_add(1)
}

#[inline(never)]
extern "system" fn commit_detour(a: u32) -> u32 {
    black_box(a).wrapping_add(2)
}

/// Runs `body` on this thread while a sleeping witness thread is watched, and
/// returns how many heap operations `body` made while the witness was frozen.
fn heap_ops_while_frozen(body: impl FnOnce()) -> usize {
    let (tid_tx, tid_rx) = std::sync::mpsc::channel();
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let stop_in = std::sync::Arc::clone(&stop);
    let witness_thread = std::thread::spawn(move || {
        tid_tx.send(unsafe { GetCurrentThreadId() }).unwrap();
        while !stop_in.load(Ordering::Acquire) {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    });
    let witness_tid = tid_rx.recv().unwrap();
    let witness = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, witness_tid) };
    assert!(!witness.is_null(), "open witness thread");

    HEAP_OPS_WHILE_FROZEN.store(0, Ordering::Relaxed);
    WITNESS.store(witness, Ordering::Release);
    CHECKED_THREAD.store(unsafe { GetCurrentThreadId() }, Ordering::Release);
    CHECKING.store(true, Ordering::Release);
    body();
    CHECKING.store(false, Ordering::Release);
    WITNESS.store(std::ptr::null_mut(), Ordering::Release);

    stop.store(true, Ordering::Release);
    witness_thread.join().unwrap();
    unsafe { CloseHandle(witness) };

    HEAP_OPS_WHILE_FROZEN.load(Ordering::Relaxed)
}

#[test]
fn commit_does_not_touch_the_heap_while_threads_are_suspended() {
    let mut hooks = Vec::new();
    let frozen_ops = heap_ops_while_frozen(|| {
        let mut tx = DetourTransaction::begin();
        tx.update_all_threads();
        tx.attach(commit_target as *mut u8, commit_detour as *const u8)
            .expect("attach");
        hooks = tx.commit().expect("commit");
    });

    assert_eq!(hooks.len(), 1);
    assert_eq!(commit_target(1), 3, "detour should be active");
    drop(hooks);
    assert_eq!(commit_target(1), 8, "original should be restored");

    assert_eq!(
        frozen_ops, 0,
        "commit allocated or freed while other threads were suspended"
    );
}

#[test]
fn failed_commit_rolls_back_without_touching_the_heap() {
    // A scratch "function" whose page is decommitted after it is queued, so
    // patching it fails and the commit has to roll back the hook it already
    // installed - all while the other threads are still suspended.
    let page = unsafe {
        VirtualAlloc(
            std::ptr::null(),
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    } as *mut u8;
    assert!(!page.is_null(), "allocate scratch page");
    unsafe {
        std::ptr::write_bytes(page, 0x90, 32);
        *page.add(32) = 0xC3;
    }

    let mut result = None;
    let frozen_ops = heap_ops_while_frozen(|| {
        let mut tx = DetourTransaction::begin();
        tx.update_all_threads();
        tx.attach(commit_target as *mut u8, commit_detour as *const u8)
            .expect("attach real target");
        tx.attach(page, commit_detour as *const u8)
            .expect("attach scratch target");
        unsafe { VirtualFree(page.cast(), 0x1000, MEM_DECOMMIT) };
        result = Some(tx.commit());
    });

    let result = result.expect("commit ran");
    assert!(result.is_err(), "patching a decommitted page must fail");
    assert_eq!(
        commit_target(1),
        8,
        "rollback should restore the hook installed before the failure"
    );
    unsafe { VirtualFree(page.cast(), 0, MEM_RELEASE) };

    assert_eq!(
        frozen_ops, 0,
        "rollback allocated or freed while other threads were suspended"
    );
}
