#![cfg(all(windows, target_arch = "x86_64"))]

use neohook::DetourTransaction;
use neohook::detour_helper;
use std::arch::naked_asm;
use std::sync::{
    Arc, Barrier, OnceLock,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread;
use std::time::Duration;

type HeavyFn = fn(usize) -> usize;

static ORG_HEAVY: OnceLock<HeavyFn> = OnceLock::new();

const THREAD_COUNT: usize = 50;
const ITERATIONS: usize = 10;
const BASE_RESULT: usize = 5950;
const HOOKED_RESULT: usize = BASE_RESULT + 1337;

#[inline(never)]
fn heavy_computation(val: usize) -> usize {
    let mut sum = 0;
    for i in 0..100 {
        sum += val + i;
    }

    thread::sleep(Duration::from_millis(1));
    sum
}

fn detour_heavy_computation(val: usize) -> usize {
    if let Some(original) = ORG_HEAVY.get() {
        original(val) + 1337
    } else {
        0
    }
}

#[test]
fn multithreaded_hook_stability() {
    let barrier = Arc::new(Barrier::new(THREAD_COUNT + 1));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let success_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for thread_index in 0..THREAD_COUNT {
        let barrier = Arc::clone(&barrier);
        let stop_flag = Arc::clone(&stop_flag);
        let success_count = Arc::clone(&success_count);

        handles.push(thread::spawn(move || {
            barrier.wait();

            while !stop_flag.load(Ordering::Relaxed) {
                let result = heavy_computation(10);

                if result == BASE_RESULT || result == HOOKED_RESULT {
                    success_count.fetch_add(1, Ordering::Relaxed);
                } else {
                    panic!("unexpected result {result} observed in worker thread {thread_index}");
                }
            }
        }));
    }

    barrier.wait();

    for _ in 0..ITERATIONS {
        let _hooks = detour_helper!(
            ORG_HEAVY,
            heavy_computation,
            detour_heavy_computation,
            HeavyFn
        )
        .expect("failed to install detour via detour_helper");

        thread::sleep(Duration::from_millis(10));
    }

    stop_flag.store(true, Ordering::SeqCst);

    for handle in handles {
        handle.join().expect("a worker thread panicked");
    }

    assert!(
        success_count.load(Ordering::SeqCst) > 0,
        "expected at least one successful call during the stress test"
    );
}

#[unsafe(naked)]
unsafe extern "C" fn rip_target_raw(_lock: *const AtomicBool) {
    naked_asm!("2:", "cmp byte ptr [rcx], 1", "je 2b", "ret",);
}

#[unsafe(naked)]
unsafe extern "C" fn helper_spin_raw(_lock: *const AtomicBool) {
    naked_asm!("2:", "cmp byte ptr [rcx], 1", "je 2b", "ret",);
}

#[unsafe(naked)]
unsafe extern "C" fn stack_target_raw(_lock: *const AtomicBool) {
    naked_asm!(
        // The call must be at byte 0 so the return address is exactly start + 5.
        "call {helper}",
        // A longer instruction after the call ensures that the stolen length is > 5.
        "mov r10, 0x1122334455667788",
        "ret",
        helper = sym helper_spin_raw,
    );
}

#[unsafe(naked)]
unsafe extern "C" fn dummy_detour() {
    naked_asm!("ret");
}

#[test]
fn real_redirection_safety() {
    let rip_lock = Arc::new(AtomicBool::new(true));
    let stack_lock = Arc::new(AtomicBool::new(true));
    let barrier = Arc::new(Barrier::new(21));

    let mut handles = Vec::new();

    for _ in 0..10 {
        let lock = Arc::clone(&rip_lock);
        let barrier = Arc::clone(&barrier);

        handles.push(thread::spawn(move || {
            barrier.wait();
            unsafe {
                rip_target_raw(Arc::as_ptr(&lock));
            }
        }));
    }

    for _ in 0..10 {
        let lock = Arc::clone(&stack_lock);
        let barrier = Arc::clone(&barrier);

        handles.push(thread::spawn(move || {
            barrier.wait();
            unsafe {
                stack_target_raw(Arc::as_ptr(&lock));
            }
        }));
    }

    barrier.wait();
    thread::sleep(Duration::from_millis(50));

    let mut session = DetourTransaction::begin();
    session.update_all_threads();

    session
        .attach(
            rip_target_raw as *const () as *mut u8,
            dummy_detour as *const u8,
        )
        .expect("failed to attach RIP redirection test hook");

    session
        .attach(
            stack_target_raw as *const () as *mut u8,
            dummy_detour as *const u8,
        )
        .expect("failed to attach stack redirection test hook");

    let _hooks = session.commit().expect("failed to commit hooks");

    rip_lock.store(false, Ordering::SeqCst);
    stack_lock.store(false, Ordering::SeqCst);

    for handle in handles {
        handle.join().expect("a redirection worker thread panicked");
    }
}
