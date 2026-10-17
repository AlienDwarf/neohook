// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(windows)]

use neohook::{DetourTransaction, detour_code_from_pointer};
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

type TargetFn = extern "C" fn(u32) -> u32;

#[inline(never)]
extern "C" fn pointer_target(value: u32) -> u32 {
    let mut acc = black_box(value);
    for i in 0..black_box(4u32) {
        acc = acc.wrapping_mul(3).wrapping_add(i);
    }
    acc ^ black_box(0x55)
}

#[inline(never)]
extern "C" fn pointer_detour(value: u32) -> u32 {
    black_box(value).wrapping_add(0xDEAD_0000)
}

/// A plain function pointer to the hook target held on another thread's stack
/// is not a return address and must survive the commit untouched.
#[test]
fn stack_function_pointer_to_target_is_not_redirected() {
    // Resolve any incremental-linking thunk so the pointer equals the patched entry.
    let target = unsafe { detour_code_from_pointer(pointer_target as *const u8) } as usize;
    let expected_original = pointer_target(7);

    let ready = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));

    let worker = {
        let ready = Arc::clone(&ready);
        let release = Arc::clone(&release);
        thread::spawn(move || {
            let slots = [target; 4];
            black_box(&slots);
            ready.store(true, Ordering::SeqCst);
            while !release.load(Ordering::SeqCst) {
                std::hint::spin_loop();
            }
            unsafe { std::ptr::read_volatile(&slots) }
        })
    };

    while !ready.load(Ordering::SeqCst) {
        std::hint::spin_loop();
    }

    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();
    tx.attach(target as *mut u8, pointer_detour as *const u8)
        .expect("attach should succeed");
    let _hooks = tx.commit().expect("commit should succeed");

    release.store(true, Ordering::SeqCst);
    let slots = worker.join().expect("worker panicked");

    for (i, &slot) in slots.iter().enumerate() {
        assert_eq!(
            slot, target,
            "stack slot {i} holding a function pointer was rewritten"
        );
    }

    let f: TargetFn = unsafe { std::mem::transmute::<usize, TargetFn>(slots[0]) };
    assert_eq!(
        f(7),
        pointer_detour(7),
        "call through pointer bypassed the hook"
    );
    assert_ne!(f(7), expected_original);
}
