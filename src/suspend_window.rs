//! While a commit holds the other threads suspended it must not wait on any
//! lock one of them could own: not one of neohook's own mutexes, and not the
//! process heap lock. Otherwise a thread frozen mid-unhook or mid-allocation
//! wedges the transaction forever.
//!
//! Each race runs in a child process. A deadlock would also freeze any watchdog
//! thread in the same process (the transaction suspends it too), so the parent
//! kills the child and fails once a timeout passes instead.

use crate::DetourTransaction;
use std::hint::black_box;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc,
};

const CHILD_ENV: &str = "NEOHOOK_SUSPEND_WINDOW_CHILD";
const TIMEOUT: Duration = Duration::from_secs(12);
/// Each race stops after this many commits or [`RACE_TIME`], whichever comes
/// first. Without the fix the child hangs within a few rounds.
const ROUNDS: usize = 300;
const RACE_TIME: Duration = Duration::from_secs(6);

/// Runs `body` in a fresh copy of this test binary and fails if it does not
/// finish successfully within [`TIMEOUT`].
fn run_in_child(test_name: &str, body: fn()) {
    let full_name = format!("suspend_window::{test_name}");
    if std::env::var(CHILD_ENV).as_deref() == Ok(full_name.as_str()) {
        body();
        return;
    }

    let exe = std::env::current_exe().expect("current_exe");
    let mut child = Command::new(exe)
        .args([full_name.as_str(), "--exact", "--test-threads=1"])
        .env(CHILD_ENV, &full_name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn child test process");

    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("wait for child") {
            assert!(status.success(), "child race failed: {status}");
            return;
        }
        if start.elapsed() > TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("transaction deadlocked: child did not finish within {TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Hooks a scratch function over and over with every other thread suspended,
/// while `background` runs in a loop on another thread.
fn race_against(background: fn()) {
    let target = scratch_function();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_in = Arc::clone(&stop);
    let worker = std::thread::spawn(move || {
        while !stop_in.load(Ordering::Relaxed) {
            background();
        }
    });

    let start = Instant::now();
    for _ in 0..ROUNDS {
        if start.elapsed() > RACE_TIME {
            break;
        }
        let mut tx = DetourTransaction::begin();
        tx.update_all_threads();
        tx.attach(target, detour as *const u8)
            .expect("attach scratch target");
        let hooks = tx.commit().expect("commit scratch target");
        drop(hooks);
    }

    stop.store(true, Ordering::Relaxed);
    worker.join().expect("background thread");
}

/// A never-called function body (a NOP sled ending in `ret`) on its own page.
fn scratch_function() -> *mut u8 {
    let page = unsafe {
        VirtualAlloc(
            std::ptr::null(),
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    } as *mut u8;
    assert!(!page.is_null(), "allocate scratch page");
    unsafe {
        std::ptr::write_bytes(page, 0x90, 32);
        *page.add(32) = 0xC3;
    }
    page
}

#[inline(never)]
extern "system" fn detour(x: u32) -> u32 {
    black_box(x).wrapping_add(20)
}

/// Takes the gateway registry lock over and over, as dropping or unhooking an
/// inline hook does, without holding the transaction lock.
fn churn_gateway_registry() {
    crate::transaction::unregister_managed_gateway(0x1234 as *mut u8);
}

/// Allocates and frees blocks of varying size, so the heap lock is often held
/// at the moment the other thread suspends it.
fn churn_heap() {
    for size in (1..4096).step_by(61) {
        drop(black_box(vec![1u8; size]));
    }
    // Let the committing thread win the heap lock now and then, so it is not
    // merely starved.
    std::thread::yield_now();
}

#[test]
fn commit_survives_concurrent_gateway_registry_use() {
    run_in_child("commit_survives_concurrent_gateway_registry_use", || {
        race_against(churn_gateway_registry)
    });
}

#[test]
fn commit_survives_concurrent_heap_use() {
    run_in_child("commit_survives_concurrent_heap_use", || {
        race_against(churn_heap)
    });
}
