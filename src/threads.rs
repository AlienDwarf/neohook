// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::Threading::*;

/// Provides functionality to enumerate threads
pub struct ThreadEnumerator;

impl ThreadEnumerator {
    /// Enumerates all threads of the current process, excluding the calling thread,
    /// and returns their handles.
    /// # Examples
    /// ```rust,ignore
    /// let threads = ThreadEnumerator::enumerate_process_threads();
    /// for thread in threads {
    ///     // Do something with the thread handle, e.g., suspend or resume the thread
    ///    unsafe { SuspendThread(thread) };
    /// }
    /// ```
    pub fn enumerate_process_threads() -> Vec<HANDLE> {
        let mut threads = Vec::new();
        let process_id = unsafe { GetCurrentProcessId() };
        let current_thread_id = unsafe { GetCurrentThreadId() };

        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return threads;
        }

        let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        unsafe {
            if Thread32First(snapshot, &mut entry) != 0 {
                loop {
                    // Check if the thread belongs to the current process and is not the calling thread
                    if entry.th32OwnerProcessID == process_id
                        && entry.th32ThreadID != current_thread_id
                    {
                        let access_flags = THREAD_SUSPEND_RESUME
                            | THREAD_GET_CONTEXT
                            | THREAD_SET_CONTEXT
                            | THREAD_QUERY_INFORMATION;

                        let h_thread = OpenThread(access_flags, 0, entry.th32ThreadID);
                        if !h_thread.is_null() {
                            threads.push(h_thread);
                        }
                    }

                    if Thread32Next(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snapshot);
        }
        threads
    }
}
