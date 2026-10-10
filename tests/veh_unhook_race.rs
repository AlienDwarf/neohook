#![cfg(windows)]

//! Removing a VEH hook while other threads keep calling the target must not
//! leave a stale hardware breakpoint that traps with no handler to catch it.

use neohook::VehHook;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[inline(never)]
extern "system" fn race_target(x: u32) -> u32 {
    std::hint::black_box(x).wrapping_add(1)
}

extern "system" fn race_detour(x: u32) -> u32 {
    std::hint::black_box(x).wrapping_add(100)
}

#[test]
fn veh_unhook_while_threads_call_target_does_not_crash() {
    type Fn = extern "system" fn(u32) -> u32;
    let t = race_target as *const () as *const u8;
    let d = race_detour as *const () as *const u8;

    let stop = Arc::new(AtomicBool::new(false));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let f = std::hint::black_box(race_target as Fn);
                while !stop.load(Ordering::Relaxed) {
                    let r = f(std::hint::black_box(1));
                    assert!(r == 2 || r == 101, "unexpected result {r}");
                }
            })
        })
        .collect();

    let f = std::hint::black_box(race_target as Fn);
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        let hook = unsafe { VehHook::install(t, d) }.expect("install");
        assert_eq!(f(1), 101, "calling thread should hit the detour");
        hook.unhook().unwrap();
    }

    stop.store(true, Ordering::Relaxed);
    for w in workers {
        w.join().unwrap();
    }
    assert_eq!(f(1), 2, "original must be restored after the last unhook");
}
