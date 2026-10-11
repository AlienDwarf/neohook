#![cfg(windows)]

//! Every pass that suspends all other threads - a commit, a reclaim pass,
//! arming a VEH breakpoint, the check before removing an exception handler -
//! must be serialized against every other such pass. Two threads that each
//! suspend "every other thread" at the same time suspend each other, and then
//! nothing resumes either of them or the rest of the process.
//!
//! The scenario runs in a child process so a hang is reported as a test
//! failure instead of stalling the test runner.

use neohook::{DetourTransaction, Int3Hook, VehHook};
use std::hint::black_box;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const CHILD_ENV: &str = "NEOHOOK_CONCURRENT_FREEZES_CHILD";
const TEST_NAME: &str = "concurrent_freezing_passes_do_not_suspend_each_other";
const RUN_FOR: Duration = Duration::from_secs(3);
/// Idle threads that make every suspend-all pass take longer.
const IDLE_THREADS: usize = 32;
const TIMEOUT: Duration = Duration::from_secs(60);

#[inline(never)]
extern "system" fn inline_target(x: u32) -> u32 {
    black_box(x).wrapping_mul(3)
}

#[inline(never)]
extern "system" fn inline_detour(x: u32) -> u32 {
    black_box(x).wrapping_add(1)
}

#[inline(never)]
extern "system" fn int3_target(x: u32) -> u32 {
    black_box(x).wrapping_mul(5)
}

#[inline(never)]
extern "system" fn veh_target(x: u32) -> u32 {
    black_box(x).wrapping_mul(7)
}

#[inline(never)]
extern "system" fn other_detour(x: u32) -> u32 {
    black_box(x).wrapping_add(2)
}

fn scenario() {
    let stop = Arc::new(AtomicBool::new(false));
    let mut workers = Vec::new();

    for _ in 0..IDLE_THREADS {
        let s = Arc::clone(&stop);
        workers.push(std::thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(1));
            }
        }));
    }

    // Commits (and the reclaim pass at every begin) suspend every thread.
    let s = Arc::clone(&stop);
    workers.push(std::thread::spawn(move || {
        while !s.load(Ordering::Relaxed) {
            let mut tx = DetourTransaction::begin();
            tx.update_all_threads();
            tx.attach(inline_target as *mut u8, inline_detour as *const u8)
                .expect("attach");
            drop(tx.commit().expect("commit"));
            neohook::reclaim();
        }
    }));

    // Removing the last INT3 hook checks every thread before the handler goes.
    let s = Arc::clone(&stop);
    workers.push(std::thread::spawn(move || {
        let t = int3_target as *const () as *const u8;
        let d = other_detour as *const () as *const u8;
        while !s.load(Ordering::Relaxed) {
            let hook = unsafe { Int3Hook::install(t, d) }.expect("int3 install");
            hook.unhook().unwrap();
        }
    }));

    // Arming a VEH breakpoint suspends each thread in turn, and removing the
    // last one checks every thread.
    let s = Arc::clone(&stop);
    workers.push(std::thread::spawn(move || {
        let t = veh_target as *const () as *const u8;
        let d = other_detour as *const () as *const u8;
        while !s.load(Ordering::Relaxed) {
            let hook = unsafe { VehHook::install(t, d) }.expect("veh install");
            hook.unhook().unwrap();
        }
    }));

    std::thread::sleep(RUN_FOR);
    stop.store(true, Ordering::Relaxed);
    for w in workers {
        w.join().expect("worker panicked");
    }
}

#[test]
fn concurrent_freezing_passes_do_not_suspend_each_other() {
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
            panic!("child hung: two passes suspended each other");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
