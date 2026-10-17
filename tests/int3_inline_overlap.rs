// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(windows)]

//! An INT3 hook and an inline hook must not patch the same bytes. The inline
//! hook used to relocate the `0xCC` into its trampoline, so calling the
//! original raised a breakpoint no handler claimed.

use neohook::{DetourTransaction, Int3Hook, Int3HookError};
use std::hint::black_box;

#[inline(never)]
extern "system" fn target_a(x: u32) -> u32 {
    black_box(x)
        .wrapping_mul(black_box(9))
        .wrapping_add(black_box(1))
}

#[inline(never)]
extern "system" fn target_b(x: u32) -> u32 {
    black_box(x)
        .wrapping_mul(black_box(7))
        .wrapping_add(black_box(2))
}

extern "system" fn int3_detour(x: u32) -> u32 {
    x + 5
}

extern "system" fn inline_detour(x: u32) -> u32 {
    x + 7
}

#[test]
fn inline_attach_on_an_int3_hooked_target_is_refused() {
    let int3 = unsafe { Int3Hook::install(target_a as *const u8, int3_detour as *const u8) }
        .expect("INT3 hook installs");

    let mut tx = DetourTransaction::begin();
    assert!(
        tx.attach(target_a as *mut u8, inline_detour as *const u8)
            .is_err()
    );
    drop(tx);
    assert_eq!(target_a(1), 6);

    int3.unhook().expect("INT3 hook removes");
    assert_eq!(target_a(1), 10);
}

#[test]
fn int3_install_on_an_inline_hooked_target_is_refused() {
    let mut tx = DetourTransaction::begin();
    tx.attach(target_b as *mut u8, inline_detour as *const u8)
        .expect("inline attach queues");
    let hooks = tx.commit().expect("inline hook commits");

    // The entry byte and any other byte of the patch.
    for offset in [0, 1] {
        let target = unsafe { (target_b as *const u8).add(offset) };
        assert!(matches!(
            unsafe { Int3Hook::install(target, int3_detour as *const u8) },
            Err(Int3HookError::AlreadyHooked)
        ));
    }
    assert_eq!(target_b(1), 8);

    drop(hooks);
    assert_eq!(target_b(1), 9);

    let int3 = unsafe { Int3Hook::install(target_b as *const u8, int3_detour as *const u8) }
        .expect("INT3 hook installs once the inline hook is gone");
    assert_eq!(target_b(1), 6);
    drop(int3);
}
