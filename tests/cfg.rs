// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end checks for CFG-aware hooking.
//!
//! The CI runs this file both normally and built with `-C control-flow-guard`
//! (see `.github/workflows/ci.yml`). Under the CFG build the process enforces
//! Control Flow Guard and every indirect call below (through a `fn` pointer or a
//! vtable slot) is instrumented, so these tests confirm that hooking - and
//! calling the original through the trampoline - stays correct while the call
//! targets are being registered through `SetProcessValidCallTargets`.
//!
//! Note: default (non-strict) CFG already permits private trampoline memory, so
//! this is a no-regression guard rather than a demonstration of a prevented
//! fail-fast; the registration is what makes the same hooks hold up under strict
//! CFG / export suppression, which cannot be toggled on a stock CI runner.

use neohook::{DetourTransaction, cfg, detour_helper};
use std::sync::OnceLock;

type AddFn = extern "system" fn(i32, i32) -> i32;
static ORIG_ADD: OnceLock<AddFn> = OnceLock::new();

#[inline(never)]
extern "system" fn add(a: i32, b: i32) -> i32 {
    std::hint::black_box(a) + std::hint::black_box(b)
}

extern "system" fn detour_add(a: i32, b: i32) -> i32 {
    // Calling the original through the stored trampoline pointer is an *indirect*
    // call - exactly the call a CFG build guards. It fail-fasts unless the
    // trampoline returned by the hook was registered as a valid call target.
    let orig = ORIG_ADD.get().expect("original not set");
    orig(a, b) * 10
}

#[test]
fn inline_original_call_survives_cfg() {
    let hooks = detour_helper!(ORIG_ADD, add, detour_add, AddFn).expect("inline hook");

    // (2 + 3) * 10, with the inner `orig(a, b)` reached via a guarded indirect
    // call into the registered trampoline.
    assert_eq!(add(2, 3), 50);

    drop(hooks);
    assert_eq!(add(2, 3), 5, "original restored after unhook");
}

type SlotFn = extern "system" fn() -> i32;

extern "system" fn original_method() -> i32 {
    1
}

extern "system" fn detour_method() -> i32 {
    2
}

#[test]
fn vtable_dispatch_survives_cfg() {
    let mut vtable = [original_method as *mut u8];

    let mut tx = DetourTransaction::begin();
    let original_ptr = tx
        .attach_vtable(vtable.as_mut_ptr(), 0, detour_method as *const u8)
        .expect("vtable attach");
    let _hooks = tx.commit().expect("commit");

    // Dispatch through the patched slot: a guarded indirect call to the detour.
    let current: SlotFn = unsafe { std::mem::transmute(vtable[0]) };
    assert_eq!(current(), 2);

    // The original is still reachable through the returned pointer.
    let original: SlotFn = unsafe { std::mem::transmute(original_ptr) };
    assert_eq!(original(), 1);
}

#[test]
fn enforcement_override_roundtrips() {
    cfg::set_enforcement(Some(true));
    assert!(cfg::is_enforced(), "forced-on override");

    cfg::set_enforcement(Some(false));
    assert!(!cfg::is_enforced(), "forced-off override");

    // Registration is a no-op (and reports false) while handling is forced off.
    assert!(!cfg::register_valid_target(add as *const u8));

    // Restore auto-detection so the other tests see the real process policy.
    cfg::set_enforcement(None);
}
