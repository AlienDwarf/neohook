// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(windows)]

//! The tamper callback runs on the watchdog thread. Dropping the watchdog from
//! there used to make that thread join itself and hang forever.

use neohook::{WatchMode, Watchdog};
use std::sync::Mutex;
use std::sync::mpsc;
use std::time::Duration;

static WATCHDOG: Mutex<Option<Watchdog>> = Mutex::new(None);

#[test]
fn watchdog_can_be_dropped_from_its_callback() {
    let mut region = Box::new([0x90u8; 16]);
    let watchdog = Watchdog::with_interval(Duration::from_millis(10));
    watchdog.set_mode(WatchMode::DetectOnly);
    unsafe { watchdog.guard(region.as_ptr(), region.len()) }.expect("guard region");

    let (done_tx, done_rx) = mpsc::channel();
    let done_tx = Mutex::new(done_tx);
    watchdog.on_tamper(move |_| {
        let watchdog = WATCHDOG.lock().unwrap().take();
        drop(watchdog);
        let _ = done_tx.lock().unwrap().send(());
    });
    *WATCHDOG.lock().unwrap() = Some(watchdog);

    region[0] = 0xCC;
    assert!(
        done_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
        "the callback never returned"
    );
}
