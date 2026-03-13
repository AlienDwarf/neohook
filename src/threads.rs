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
