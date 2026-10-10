#![cfg(windows)]

//! The reclaim pass suspends every other thread. Touching the heap in that
//! window can deadlock against a thread that was suspended while holding the
//! heap lock, so the pass must not allocate or free until the threads resume.
//!
//! A counting global allocator checks, on every heap operation made by the
//! reclaiming thread, whether a parked witness thread is currently suspended.

use neohook::DetourTransaction;
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
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
        // SuspendThread returns the previous suspend count: non-zero means
        // the reclaim pass has the witness frozen right now.
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
extern "system" fn reclaim_target(a: u32) -> u32 {
    black_box(a).wrapping_add(1)
}

#[inline(never)]
extern "system" fn reclaim_detour(a: u32) -> u32 {
    black_box(a).wrapping_add(2)
}

#[test]
fn reclaim_does_not_touch_the_heap_while_threads_are_suspended() {
    // A thread that does nothing but sleep, so it never holds a lock itself.
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

    // Retire a trampoline so the next reclaim pass has work to do.
    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();
    tx.attach(reclaim_target as *mut u8, reclaim_detour as *const u8)
        .expect("attach");
    let hooks = tx.commit().expect("commit");
    drop(hooks);

    WITNESS.store(witness, Ordering::Release);
    CHECKED_THREAD.store(unsafe { GetCurrentThreadId() }, Ordering::Release);
    CHECKING.store(true, Ordering::Release);
    neohook::reclaim();
    CHECKING.store(false, Ordering::Release);
    WITNESS.store(std::ptr::null_mut(), Ordering::Release);

    stop.store(true, Ordering::Release);
    witness_thread.join().unwrap();
    unsafe { CloseHandle(witness) };

    assert_eq!(
        HEAP_OPS_WHILE_FROZEN.load(Ordering::Relaxed),
        0,
        "reclaim allocated or freed while other threads were suspended"
    );
}
