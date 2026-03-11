#![cfg(windows)]

use neohook::DetourTransaction;
use std::hint::black_box;
use std::sync::OnceLock;

#[inline(never)]
fn base_calculation(val: i32) -> i32 {
    black_box(val) + 10
}

static TRAMP_HOOK_1: OnceLock<fn(i32) -> i32> = OnceLock::new();
static TRAMP_HOOK_2: OnceLock<fn(i32) -> i32> = OnceLock::new();

#[inline(never)]
fn detour_add_100(val: i32) -> i32 {
    let original_fn = TRAMP_HOOK_1
        .get()
        .expect("first trampoline was not initialized");
    original_fn(black_box(val)) + 100
}

#[inline(never)]
fn detour_multiply_2(val: i32) -> i32 {
    let original_fn = TRAMP_HOOK_2
        .get()
        .expect("second trampoline was not initialized");
    original_fn(black_box(val)) * 2
}

#[test]
fn hook_chaining_works() {
    // Install the first hook on the original target function.
    let mut tx1 = DetourTransaction::begin();
    let tramp1_ptr = tx1
        .attach(base_calculation as *mut u8, detour_add_100 as *const u8)
        .expect("failed to attach first hook");

    tx1.update_all_threads();
    let _hook1 = tx1.commit().expect("failed to commit first hook");

    let tramp1: fn(i32) -> i32 = unsafe { std::mem::transmute(tramp1_ptr) };
    let _ = TRAMP_HOOK_1.set(tramp1);

    assert_eq!(base_calculation(5), 115);

    // Install the second hook on the first trampoline.
    let mut tx2 = DetourTransaction::begin();
    let tramp2_ptr = tx2
        .attach(tramp1_ptr, detour_multiply_2 as *const u8)
        .expect("failed to attach second hook");

    tx2.update_all_threads();
    let _hook2 = tx2.commit().expect("failed to commit second hook");

    let tramp2: fn(i32) -> i32 = unsafe { std::mem::transmute(tramp2_ptr) };
    let _ = TRAMP_HOOK_2.set(tramp2);

    // Expected flow:
    // base_calculation -> detour_add_100 -> tramp1
    // tramp1 -> detour_multiply_2 -> tramp2
    // tramp2 -> original base_calculation
    //
    // Result: ((5 + 10) * 2) + 100 = 130
    assert_eq!(base_calculation(5), 130);
}
