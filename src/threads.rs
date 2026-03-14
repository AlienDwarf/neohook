// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::Threading::*;

/// Provides functionality to enumerate threads
pub struct ThreadEnumerator;

impl ThreadEnumerator {
    /// Enumerates all thread IDs of the current process, excluding the calling thread.
    ///
    /// This function returns thread IDs
    ///
    /// If a thread snapshot cannot be created, an empty vector is returned.
    ///
    /// # Examples
    /// ```rust,ignore
    /// let thread_ids = ThreadEnumerator::enumerate_process_threads();
    ///
    /// for tid in thread_ids {
    ///     println!("found thread id: {}", tid);
    /// }
    /// ```
    pub fn enumerate_process_threads() -> Vec<u32> {
        let mut thread_ids = Vec::new();
        let process_id = unsafe { GetCurrentProcessId() };
        let current_thread_id = unsafe { GetCurrentThreadId() };

        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return thread_ids;
        }

        let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        unsafe {
            if Thread32First(snapshot, &mut entry) != 0 {
                loop {
                    if entry.th32OwnerProcessID == process_id
                        && entry.th32ThreadID != current_thread_id
                    {
                        thread_ids.push(entry.th32ThreadID);
                    }

                    if Thread32Next(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }

            CloseHandle(snapshot);
        }

        thread_ids
    }
}

#[cfg(test)]
mod tests {
    use crate::threads::ThreadEnumerator;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::thread;

    #[test]
    fn enumerate_process_thread_ids_finds_spawned_threads() {
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

        let thread_ids = ThreadEnumerator::enumerate_process_threads();

        // We expect at least the spawned worker threads to be visible.
        assert!(
            thread_ids.len() >= 10,
            "expected to find at least the spawned worker threads, found {}",
            thread_ids.len()
        );

        stop.store(true, Ordering::Relaxed);

        for worker in workers {
            worker.join().expect("worker thread panicked");
        }
    }
}
