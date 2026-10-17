// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(windows)]

//! A thread that is deep inside a callee called from the target's stolen bytes
//! must be redirected at install time, however far its return address sits
//! from the top of its stack.
//!
//! The commit overwrites the stolen bytes with the jump; a thread whose return
//! address points into them would return into the middle of that jump. The
//! commit redirects such return addresses into the trampoline, but a scan that
//! only covers a window above each stack pointer misses one below a deep call
//! chain, and the thread faults the moment it returns.
//!
//! The scenario runs in a child process so that fault is reported as a test
//! failure instead of taking the test runner down with it.

use neohook::DetourTransaction;
use std::arch::naked_asm;
use std::hint::black_box;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

const CHILD_ENV: &str = "NEOHOOK_COMMIT_DEEP_STACK_CHILD";
const TEST_NAME: &str = "install_redirects_a_return_address_below_a_deep_call_chain";
const TIMEOUT: Duration = Duration::from_secs(30);

/// Recursion frames between the parked stack pointer and the return address
/// into the target. Each frame touches 4 KiB.
const FRAMES: usize = 16;

static PARKED: AtomicBool = AtomicBool::new(false);
static RELEASE: AtomicBool = AtomicBool::new(false);
static RESULT: AtomicU32 = AtomicU32::new(0);

#[inline(never)]
fn recurse(depth: usize) {
    let mut frame = [0u8; 4096];
    black_box(&mut frame);
    if depth > 0 {
        recurse(depth - 1);
    } else {
        PARKED.store(true, Ordering::Release);
        while !RELEASE.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    black_box(&mut frame);
}

extern "C" fn park_deep() {
    recurse(FRAMES);
}

/// Called by the target with the stack one slot off the ABI alignment; sets up
/// the alignment and shadow space `park_deep` expects.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn park_shim() {
    naked_asm!(
        "sub rsp, 32",
        "call {park}",
        "add rsp, 32",
        "ret",
        park = sym park_deep,
    );
}

#[cfg(target_arch = "x86")]
#[unsafe(naked)]
unsafe extern "C" fn park_shim() {
    naked_asm!(
        "sub esp, 8",
        "call {park}",
        "add esp, 8",
        "ret",
        park = sym park_deep,
    );
}

/// `target(callee)`: calls `callee` with a two- or four-byte indirect call at
/// its very start, so the return address lies inside the stolen bytes, then
/// returns 1.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn deep_target(_callee: unsafe extern "C" fn()) -> u32 {
    naked_asm!("call rcx", "mov eax, 1", "ret", "int3", "int3");
}

#[cfg(target_arch = "x86")]
#[unsafe(naked)]
unsafe extern "C" fn deep_target(_callee: unsafe extern "C" fn()) -> u32 {
    naked_asm!(
        "call dword ptr [esp + 4]",
        "mov eax, 1",
        "ret",
        "int3",
        "int3"
    );
}

extern "C" fn deep_detour(_callee: unsafe extern "C" fn()) -> u32 {
    2
}

fn scenario() {
    let worker = std::thread::spawn(|| {
        let r = unsafe { deep_target(park_shim) };
        RESULT.store(r, Ordering::Release);
    });

    let start = Instant::now();
    while !PARKED.load(Ordering::Acquire) {
        assert!(start.elapsed() < TIMEOUT, "the worker never parked");
        std::thread::sleep(Duration::from_millis(5));
    }

    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();
    tx.attach(
        deep_target as *const () as *mut u8,
        deep_detour as *const () as *const u8,
    )
    .expect("attach the deep target");
    let hooks = tx.commit().expect("commit the deep target");

    // Returning into the overwritten bytes faults and kills the child.
    RELEASE.store(true, Ordering::Release);
    worker.join().expect("worker thread");
    assert_eq!(
        RESULT.load(Ordering::Acquire),
        1,
        "the worker must finish the original call"
    );
    drop(hooks);
}

#[test]
fn install_redirects_a_return_address_below_a_deep_call_chain() {
    if std::env::var(CHILD_ENV).is_ok() {
        scenario();
        return;
    }

    let exe = std::env::current_exe().expect("current_exe");
    let mut child = Command::new(exe)
        .args([TEST_NAME, "--exact", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn child test process");

    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("wait for child") {
            assert!(status.success(), "child scenario failed: {status}");
            return;
        }
        if start.elapsed() > TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("child did not finish within {TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
