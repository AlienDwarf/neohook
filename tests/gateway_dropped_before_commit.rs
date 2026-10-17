// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(windows)]

//! A hook chained onto a managed gateway must not be installed if the hook
//! owning that gateway is dropped between `attach` and `commit`.
//!
//! Dropping the owner retires the gateway; nothing is chained on it yet, so it
//! is freed by the next reclaim pass. A commit that still patches it, and an
//! unhook that later restores its bytes, would write into freed memory that may
//! already hold another hook's trampoline.

use neohook::DetourTransaction;
use std::hint::black_box;

#[inline(never)]
extern "system" fn target(x: u32) -> u32 {
    black_box(x).wrapping_mul(3).wrapping_add(1)
}

#[inline(never)]
extern "system" fn first_detour(x: u32) -> u32 {
    black_box(x).wrapping_add(100)
}

#[inline(never)]
extern "system" fn second_detour(x: u32) -> u32 {
    black_box(x).wrapping_add(200)
}

#[test]
fn chaining_onto_a_gateway_dropped_before_commit_fails() {
    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();
    let gateway = tx
        .attach(target as *mut u8, first_detour as *const u8)
        .expect("attach the base hook");
    let base = tx.commit().expect("commit the base hook");

    let mut chain = DetourTransaction::begin();
    chain.update_all_threads();
    chain
        .attach(gateway, second_detour as *const u8)
        .expect("attach onto the managed gateway");

    // The owner goes away while the chained hook is still queued.
    drop(base);
    assert_eq!(target(1), 4, "the base hook is gone");

    let result = chain.commit();
    let installed = result.is_ok();
    drop(result);
    neohook::reclaim();

    assert!(
        !installed,
        "a hook chained onto a gateway that was dropped before the commit was installed"
    );
    assert_eq!(target(1), 4);
}
