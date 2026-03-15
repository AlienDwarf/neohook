#![cfg(all(windows, target_arch = "x86_64"))]

use neohook::DetourTransaction;
use std::arch::naked_asm;
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread;
use std::time::Duration;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc, VirtualFree,
};

type HeavyFn = fn(usize) -> usize;

static ORG_HEAVY: std::sync::RwLock<Option<HeavyFn>> = std::sync::RwLock::new(None);

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
    let original = *ORG_HEAVY.read().unwrap();
    let original = original.expect("original trampoline not set");
    original(val) + 1337
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
        let mut session = DetourTransaction::begin();
        session.update_all_threads();

        let tramp = session
            .attach(
                heavy_computation as *const () as *mut u8,
                detour_heavy_computation as *const u8,
            )
            .expect("failed to attach detour");

        let trampoline_fn: HeavyFn = unsafe { std::mem::transmute(tramp) };
        *ORG_HEAVY.write().unwrap() = Some(trampoline_fn);

        let hooks = session.commit().expect("failed to commit detour");

        thread::sleep(Duration::from_millis(10));

        drop(hooks);
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

struct ExecStub {
    ptr: *mut u8,
}

impl Drop for ExecStub {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                VirtualFree(self.ptr as _, 0, MEM_RELEASE);
            }
        }
    }
}

/// Allocate an executable stub containing just `ret`, far enough away to force Absolute14.
fn alloc_far_ret_stub(target: *const u8) -> ExecStub {
    const SIZE: usize = 0x1000;

    // A few deliberately far-away hint addresses.
    // We only keep the allocation if the final distance is > 2 GB.
    let hints = [
        0x0000_1000_0000_0000usize,
        0x0000_2000_0000_0000usize,
        0x0000_3000_0000_0000usize,
        0x0000_4000_0000_0000usize,
        0x0000_5000_0000_0000usize,
    ];

    for &hint in &hints {
        let ptr = unsafe {
            VirtualAlloc(
                hint as *const core::ffi::c_void,
                SIZE,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        } as *mut u8;

        if ptr.is_null() {
            continue;
        }

        let dist = ((ptr as isize as i128) - (target as isize as i128)).abs();
        if dist > i32::MAX as i128 {
            unsafe {
                *ptr = 0xC3; // ret
            }
            return ExecStub { ptr };
        }

        unsafe {
            VirtualFree(ptr as _, 0, MEM_RELEASE);
        }
    }

    panic!("could not allocate far detour stub (> 2GB away)");
}

#[unsafe(naked)]
unsafe extern "C" fn helper_spin_raw(_lock: *const AtomicBool) {
    naked_asm!("2:", "cmp byte ptr [rcx], 1", "je 2b", "ret",);
}

#[unsafe(naked)]
unsafe extern "C" fn rip_target_raw(_lock: *const AtomicBool, _counter: *const AtomicUsize) {
    naked_asm!(
        "2:",
        "cmp byte ptr [rcx], 1",
        "je 2b",
        "lock inc qword ptr [rdx]",
        "ret",
    );
}

#[unsafe(naked)]
unsafe extern "C" fn stack_target_raw(_lock: *const AtomicBool, _counter: *const AtomicUsize) {
    naked_asm!(
        // Return address after this call is exactly start + 5.
        "call {helper}",
        // Visible side effect after returning from helper.
        "lock inc qword ptr [rdx]",
        // Make sure Absolute14 stealing spans well beyond +5.
        "mov r10, 0x1122334455667788",
        "ret",
        helper = sym helper_spin_raw,
    );
}

#[test]
fn real_redirection_safety() {
    let rip_lock = Arc::new(AtomicBool::new(true));
    let stack_lock = Arc::new(AtomicBool::new(true));
    let barrier = Arc::new(Barrier::new(21));

    let rip_hits = Arc::new(AtomicUsize::new(0));
    let stack_hits = Arc::new(AtomicUsize::new(0));

    let far_stub = alloc_far_ret_stub(stack_target_raw as *const u8);

    let mut handles = Vec::new();

    for _ in 0..10 {
        let lock = Arc::clone(&rip_lock);
        let hits = Arc::clone(&rip_hits);
        let barrier = Arc::clone(&barrier);

        handles.push(thread::spawn(move || {
            barrier.wait();
            unsafe {
                rip_target_raw(Arc::as_ptr(&lock), Arc::as_ptr(&hits));
            }
        }));
    }

    for _ in 0..10 {
        let lock = Arc::clone(&stack_lock);
        let hits = Arc::clone(&stack_hits);
        let barrier = Arc::clone(&barrier);

        handles.push(thread::spawn(move || {
            barrier.wait();
            unsafe {
                stack_target_raw(Arc::as_ptr(&lock), Arc::as_ptr(&hits));
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
            far_stub.ptr as *const u8,
        )
        .expect("failed to attach RIP redirection test hook");

    session
        .attach(
            stack_target_raw as *const () as *mut u8,
            far_stub.ptr as *const u8,
        )
        .expect("failed to attach stack redirection test hook");

    let _hooks = session.commit().expect("failed to commit hooks");

    rip_lock.store(false, Ordering::SeqCst);
    stack_lock.store(false, Ordering::SeqCst);

    for handle in handles {
        handle.join().expect("a redirection worker thread panicked");
    }

    assert_eq!(
        rip_hits.load(Ordering::SeqCst),
        10,
        "expected every RIP-redirection thread to reach the post-spin increment"
    );

    assert_eq!(
        stack_hits.load(Ordering::SeqCst),
        10,
        "expected every stack-redirection thread to return through the trampoline body"
    );
}
