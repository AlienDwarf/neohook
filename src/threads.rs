// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard, TryLockError};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::Threading::*;

/// Serializes every pass that suspends the other threads of the process: a
/// commit's patch phase, a reclaim pass, the watchdog's rewrite, arming or
/// disarming a VEH breakpoint and the in-flight check before an exception
/// handler is removed.
///
/// Two threads that each suspend "every other thread" at the same time can
/// suspend each other, and then nothing resumes either of them or the rest of
/// the process. Taken last, after every other crate lock; its holder takes no
/// other lock while threads are suspended.
static FREEZE_LOCK: Mutex<()> = Mutex::new(());

/// Thread id of the [`FREEZE_LOCK`] holder, or 0.
static FREEZE_OWNER: AtomicU32 = AtomicU32::new(0);

/// A held [`FREEZE_LOCK`], or nothing if this thread already held it.
pub(crate) struct FreezeGuard {
    guard: Option<MutexGuard<'static, ()>>,
}

impl Drop for FreezeGuard {
    fn drop(&mut self) {
        if self.guard.is_some() {
            // Cleared before the mutex itself is released.
            FREEZE_OWNER.store(0, Ordering::Release);
        }
    }
}

fn owns_freeze_lock() -> bool {
    FREEZE_OWNER.load(Ordering::Acquire) == unsafe { GetCurrentThreadId() }
}

fn freeze_guard(guard: MutexGuard<'static, ()>) -> FreezeGuard {
    FREEZE_OWNER.store(unsafe { GetCurrentThreadId() }, Ordering::Release);
    FreezeGuard { guard: Some(guard) }
}

/// Takes [`FREEZE_LOCK`], waiting for another thread's pass to finish.
pub(crate) fn hold_freeze_lock() -> FreezeGuard {
    if owns_freeze_lock() {
        return FreezeGuard { guard: None };
    }
    freeze_guard(FREEZE_LOCK.lock().unwrap_or_else(|p| p.into_inner()))
}

/// Takes [`FREEZE_LOCK`] without waiting; `None` while another thread holds it.
pub(crate) fn try_hold_freeze_lock() -> Option<FreezeGuard> {
    if owns_freeze_lock() {
        return Some(FreezeGuard { guard: None });
    }
    match FREEZE_LOCK.try_lock() {
        Ok(guard) => Some(freeze_guard(guard)),
        Err(TryLockError::WouldBlock) => None,
        Err(TryLockError::Poisoned(p)) => Some(freeze_guard(p.into_inner())),
    }
}

/// Provides functionality to enumerate threads
pub(crate) struct ThreadEnumerator;

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
