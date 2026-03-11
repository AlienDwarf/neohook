#![cfg(windows)]

use neohook::DetourTransaction;
use std::hint::black_box;
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::Duration;

#[inline(never)]
extern "C" fn target_function(x: i32) -> i32 {
    sub_function_slow();
    black_box(x) + 1
}

#[inline(never)]
extern "C" fn sub_function_slow() {
    // While this thread is sleeping, the return address back into
    // `target_function` remains on the stack.
    thread::sleep(Duration::from_millis(200));
}

static DETOUR_CALLED: AtomicBool = AtomicBool::new(false);

#[inline(never)]
extern "C" fn detour_function(x: i32) -> i32 {
    DETOUR_CALLED.store(true, Ordering::SeqCst);
    black_box(x) + 100
}

#[test]
fn stack_redirection_remains_stable_while_other_thread_is_inside_target() {
    DETOUR_CALLED.store(false, Ordering::SeqCst);

    let barrier = Arc::new(Barrier::new(2));
    let worker_barrier = Arc::clone(&barrier);

    let handle = thread::spawn(move || {
        worker_barrier.wait();
        target_function(10)
    });

    barrier.wait();

    // Give the worker thread enough time to enter `sub_function_slow()`.
    thread::sleep(Duration::from_millis(50));

    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();

    #[cfg(debug_assertions)]
    tx.dump_state();

    let target_ptr = target_function as *mut u8;
    let detour_ptr = detour_function as *const u8;

    let attach_result = tx.attach(target_ptr, detour_ptr);
    assert!(attach_result.is_ok(), "failed to attach hook");

    let hooks = tx.commit().expect("failed to commit hook");

    let final_value = handle.join().expect("worker thread crashed");

    // If stack redirection works, the worker thread should survive.
    // Depending on timing and instruction position, the in-flight call may
    // still return through the original path or through the detour path.
    assert!(final_value == 11 || final_value == 110);

    // A fresh call after the hook must go through the detour.
    assert_eq!(target_function(10), 110);
    assert!(DETOUR_CALLED.load(Ordering::SeqCst));

    drop(hooks);
    assert_eq!(target_function(10), 11);
}
