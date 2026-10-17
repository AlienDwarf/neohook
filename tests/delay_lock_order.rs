// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(windows)]

//! A delay hook registered while another thread holds an open transaction must
//! not deadlock against that thread loading a library.
//!
//! The race runs in a child process so a deadlock is reported as a failure
//! instead of hanging the test run.

use neohook::{DelayHook, DetourTransaction};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;

const CHILD_ENV: &str = "NEOHOOK_DELAY_LOCK_ORDER_CHILD";
const TIMEOUT: Duration = Duration::from_secs(12);

unsafe extern "system" fn never_called() {}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn race() {
    // Installs the LdrLoadDll hook. Neither export is called by this test.
    let first = unsafe { DelayHook::register("kernel32.dll", "Beep", never_called as *const u8) }
        .expect("first register");

    // Hold the transaction lock, as user code between update and commit does.
    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();

    let second = std::thread::spawn(|| {
        unsafe { DelayHook::register("kernel32.dll", "GetConsoleCP", never_called as *const u8) }
            .expect("second register")
    });
    // Let the second registration reach the lock.
    std::thread::sleep(Duration::from_millis(200));

    // Runs the LdrLoadDll detour on this thread while the lock is held.
    let module = unsafe { LoadLibraryW(wide("version.dll").as_ptr()) };
    assert!(!module.is_null(), "load through the delay hook");

    tx.abort();
    let second = second.join().expect("second register thread");
    drop(second);
    drop(first);
}

#[test]
fn register_does_not_deadlock_against_a_loading_lock_holder() {
    if std::env::var(CHILD_ENV).is_ok() {
        race();
        return;
    }

    let exe = std::env::current_exe().expect("current_exe");
    let mut child = Command::new(exe)
        .args([
            "register_does_not_deadlock_against_a_loading_lock_holder",
            "--exact",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn child test process");

    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("wait for child") {
            assert!(status.success(), "child failed: {status}");
            return;
        }
        if start.elapsed() > TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("deadlock: child did not finish within {TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
