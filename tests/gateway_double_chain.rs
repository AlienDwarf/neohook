// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(windows)]

//! A managed gateway can carry only one chained hook at a time. A second hook
//! onto the same gateway, queued in the same transaction or after the first
//! one is installed, must be refused instead of patching the gateway twice.
//!
//! The scenario runs in a child process, since a double patch can corrupt the
//! gateway and crash.

use neohook::{DetourError, DetourTransaction};
use std::hint::black_box;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

const CHILD_ENV: &str = "NEOHOOK_GATEWAY_DOUBLE_CHAIN_CHILD";

static ORIG_A: AtomicUsize = AtomicUsize::new(0);
static ORIG_B: AtomicUsize = AtomicUsize::new(0);
static ORIG_C: AtomicUsize = AtomicUsize::new(0);
static ORIG_D: AtomicUsize = AtomicUsize::new(0);

fn call_orig(slot: &AtomicUsize, val: i32) -> i32 {
    let f: fn(i32) -> i32 = unsafe { std::mem::transmute(slot.load(Ordering::SeqCst)) };
    f(black_box(val))
}

#[inline(never)]
fn base(val: i32) -> i32 {
    black_box(val) + 10
}

#[inline(never)]
fn base2(val: i32) -> i32 {
    black_box(val) + 20
}

#[inline(never)]
fn detour_a(val: i32) -> i32 {
    call_orig(&ORIG_A, val) + 1000
}

#[inline(never)]
fn detour_b(val: i32) -> i32 {
    call_orig(&ORIG_B, val) * 3
}

#[inline(never)]
fn detour_c(val: i32) -> i32 {
    call_orig(&ORIG_C, val) + 100
}

#[inline(never)]
fn detour_d(val: i32) -> i32 {
    call_orig(&ORIG_D, val) * 2
}

fn hook(target: *mut u8, detour: *const u8, orig: &AtomicUsize) -> neohook::Hook {
    let mut tx = DetourTransaction::begin();
    let gateway = tx.attach(target, detour).expect("attach");
    orig.store(gateway as usize, Ordering::SeqCst);
    tx.commit().expect("commit").remove(0)
}

fn gateway(slot: &AtomicUsize) -> *mut u8 {
    slot.load(Ordering::SeqCst) as *mut u8
}

fn same_transaction() {
    let a = hook(base as *mut u8, detour_a as *const u8, &ORIG_A);
    assert_eq!(base(1), 11 + 1000);

    let mut tx = DetourTransaction::begin();
    let first = tx
        .attach(gateway(&ORIG_A), detour_b as *const u8)
        .expect("first chained attach");
    ORIG_B.store(first as usize, Ordering::SeqCst);

    let second = tx.attach(gateway(&ORIG_A), detour_c as *const u8);
    assert!(
        matches!(second, Err(DetourError::InvalidParameter)),
        "a second detour on one gateway in one transaction was accepted"
    );

    let again = tx
        .attach(gateway(&ORIG_A), detour_b as *const u8)
        .expect("repeated chained attach");
    assert_eq!(again, first, "a repeated attach must reuse the queued hook");

    let mut hooks = tx.commit().expect("commit");
    assert_eq!(hooks.len(), 1);
    assert_eq!(base(1), 11 * 3 + 1000);

    drop(hooks.remove(0));
    assert_eq!(base(1), 11 + 1000);
    drop(a);
    assert_eq!(base(1), 11);
}

fn already_installed() {
    let c = hook(base2 as *mut u8, detour_c as *const u8, &ORIG_C);
    let d = hook(gateway(&ORIG_C), detour_d as *const u8, &ORIG_D);
    assert_eq!(base2(1), 21 * 2 + 100);

    let mut tx = DetourTransaction::begin();
    let second = tx.attach(gateway(&ORIG_C), detour_b as *const u8);
    assert!(
        matches!(second, Err(DetourError::InvalidParameter)),
        "a gateway that already carries a chained hook was chained again"
    );
    assert!(tx.commit().expect("empty commit").is_empty());
    assert_eq!(base2(1), 21 * 2 + 100);

    // Once the chained hook is gone the gateway can be chained again.
    drop(d);
    assert_eq!(base2(1), 21 + 100);
    let b = hook(gateway(&ORIG_C), detour_b as *const u8, &ORIG_B);
    assert_eq!(base2(1), 21 * 3 + 100);

    drop(b);
    drop(c);
    assert_eq!(base2(1), 21);
}

#[test]
fn a_gateway_carries_at_most_one_chained_hook() {
    if std::env::var(CHILD_ENV).is_ok() {
        already_installed();
        same_transaction();
        return;
    }

    let exe = std::env::current_exe().expect("current_exe");
    let output = Command::new(exe)
        .args([
            "a_gateway_carries_at_most_one_chained_hook",
            "--exact",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .stdin(Stdio::null())
        .output()
        .expect("run child test process");
    assert!(
        output.status.success(),
        "child failed: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}
