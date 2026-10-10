#![cfg(windows)]

//! `detour_closure!` keeps its shim state in statics owned by the macro call
//! site, so one call site can be expanded once and executed many times (for
//! example inside a helper function). These tests cover running such a call
//! site more than once.

use neohook::{DetourError, DetourTransaction, Hook, detour_closure};
use std::hint::black_box;
use std::sync::Mutex;

type BinOp = extern "system" fn(i32, i32) -> i32;

// Every test here patches live code and goes through the same call site, so
// they must not overlap.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

#[inline(never)]
extern "system" fn first_target(a: i32, b: i32) -> i32 {
    black_box(a) + black_box(b)
}

#[inline(never)]
extern "system" fn second_target(a: i32, b: i32) -> i32 {
    black_box(a) * black_box(b)
}

#[inline(never)]
extern "system" fn unrelated_target(a: i32, b: i32) -> i32 {
    black_box(a) - black_box(b)
}

#[inline(never)]
extern "system" fn unrelated_detour(a: i32, b: i32) -> i32 {
    black_box(a) ^ black_box(b)
}

/// One `detour_closure!` call site, reused for every target.
fn hook_plus_1000(target: BinOp) -> Result<Vec<Hook>, DetourError> {
    detour_closure!(
        target,
        "system" fn(a: i32, b: i32) -> i32,
        |orig, a, b| orig(a, b) + 1000,
    )
}

#[test]
fn reused_call_site_forwards_to_the_current_original() {
    let _serial = serial();

    let first: BinOp = first_target;
    let second: BinOp = second_target;

    let hooks = hook_plus_1000(first_target).expect("first install");
    assert_eq!(first(6, 7), 1013, "first hook forwards to first_target");
    drop(hooks);
    assert_eq!(first(6, 7), 13, "first hook removed");

    // A fresh transaction reclaims the first trampoline; the unrelated hook may
    // reuse its memory.
    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();
    tx.attach(unrelated_target as *mut u8, unrelated_detour as *const u8)
        .expect("attach unrelated");
    let unrelated = tx.commit().expect("commit unrelated");

    let hooks = hook_plus_1000(second_target).expect("second install");
    assert_eq!(
        second(6, 7),
        1042,
        "second hook must forward to second_target's original"
    );
    drop(hooks);
    drop(unrelated);
    assert_eq!(second(6, 7), 42, "second hook removed");
}

#[test]
fn reused_call_site_rejects_a_second_live_hook() {
    let _serial = serial();

    let first: BinOp = first_target;
    let second: BinOp = second_target;

    let hooks = hook_plus_1000(first_target).expect("first install");
    assert!(
        hook_plus_1000(second_target).is_err(),
        "a call site can only drive one live hook"
    );

    assert_eq!(
        first(6, 7),
        1013,
        "first hook still forwards to first_target"
    );
    assert_eq!(second(6, 7), 42, "second target left untouched");

    drop(hooks);
    assert_eq!(first(6, 7), 13, "first hook removed");
}
