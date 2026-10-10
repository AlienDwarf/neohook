// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Removing an INT3 hook while other threads keep calling the target must not
//! leave a thread that already trapped on the `0xCC` byte without a handler.

use neohook::Int3Hook;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

type Fn = extern "system" fn(u32) -> u32;

#[inline(never)]
extern "system" fn target(x: u32) -> u32 {
    std::hint::black_box(x).wrapping_add(1)
}

#[inline(never)]
extern "system" fn detour(x: u32) -> u32 {
    std::hint::black_box(x).wrapping_add(2)
}

#[test]
fn unhook_while_target_is_called_concurrently() {
    let stop = Arc::new(AtomicBool::new(false));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let f: Fn = std::hint::black_box(target as Fn);
                while !stop.load(Ordering::Relaxed) {
                    let r = f(1);
                    assert!(r == 2 || r == 3, "unexpected result {r}");
                }
            })
        })
        .collect();

    let t = target as *const () as *const u8;
    let d = detour as *const () as *const u8;
    let f: Fn = std::hint::black_box(target as Fn);
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        let hook = unsafe { Int3Hook::install(t, d) }.expect("install");
        assert_eq!(f(1), 3, "call should be redirected while hooked");
        hook.unhook().unwrap();
    }

    stop.store(true, Ordering::Relaxed);
    for w in workers {
        w.join().expect("worker panicked");
    }
    assert_eq!(f(1), 2, "original restored after the last unhook");
}
