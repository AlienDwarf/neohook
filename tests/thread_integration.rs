#![cfg(windows)]

use neohook::threads::ThreadEnumerator;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use windows_sys::Win32::Foundation::CloseHandle;

#[test]
fn enumerate_process_threads_finds_spawned_threads() {
    let stop = Arc::new(AtomicBool::new(false));
    let mut workers = Vec::new();

    // Spawn a number of worker threads so enumeration has something to find.
    for _ in 0..10 {
        let stop_flag = Arc::clone(&stop);
        workers.push(thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                thread::yield_now();
            }
        }));
    }

    let threads = ThreadEnumerator::enumerate_process_threads();

    // We expect at least the spawned worker threads to be visible.
    assert!(
        threads.len() >= 10,
        "expected to find at least the spawned worker threads, found {}",
        threads.len()
    );

    stop.store(true, Ordering::Relaxed);

    for handle in threads {
        unsafe {
            CloseHandle(handle);
        }
    }

    for worker in workers {
        worker.join().expect("worker thread panicked");
    }
}
