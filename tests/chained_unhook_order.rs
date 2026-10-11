#![cfg(windows)]

//! Dropping a hook before the hook chained on its gateway must not let the
//! chained hook's unhook write into the released gateway, which a later hook may
//! already be using.
//!
//! The scenario runs in a child process, since the stale write can also land in
//! freed memory and crash.

use neohook::DetourTransaction;
use std::hint::black_box;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

const CHILD_ENV: &str = "NEOHOOK_CHAINED_UNHOOK_ORDER_CHILD";

static ORIG_A: AtomicUsize = AtomicUsize::new(0);
static ORIG_B: AtomicUsize = AtomicUsize::new(0);
static ORIG_C: AtomicUsize = AtomicUsize::new(0);
static ORIG_E: AtomicUsize = AtomicUsize::new(0);

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
fn detour_e(val: i32) -> i32 {
    call_orig(&ORIG_E, val) * 2
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

fn scenario() {
    let a = hook(base as *mut u8, detour_a as *const u8, &ORIG_A);
    let b = hook(gateway(&ORIG_A), detour_b as *const u8, &ORIG_B);
    assert_eq!(base(1), 11 * 3 + 1000);

    // Removing the base restores the target; the chained hook is bypassed.
    drop(a);
    assert_eq!(base(1), 11);
    neohook::reclaim();

    let c = hook(base2 as *mut u8, detour_c as *const u8, &ORIG_C);
    let e = hook(gateway(&ORIG_C), detour_e as *const u8, &ORIG_E);
    assert_eq!(base2(1), 21 * 2 + 100);

    drop(b);
    assert_eq!(
        base2(1),
        21 * 2 + 100,
        "unhooking the orphaned chained hook disturbed an unrelated chain"
    );
    assert_eq!(base(1), 11);

    drop(e);
    assert_eq!(base2(1), 21 + 100);
    drop(c);
    assert_eq!(base2(1), 21);
}

#[test]
fn unhooking_a_chained_hook_after_its_base_leaves_other_hooks_intact() {
    if std::env::var(CHILD_ENV).is_ok() {
        scenario();
        return;
    }

    let exe = std::env::current_exe().expect("current_exe");
    let output = Command::new(exe)
        .args([
            "unhooking_a_chained_hook_after_its_base_leaves_other_hooks_intact",
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
