use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::Threading::*;

/// Provides functionality to enumerate threads
pub struct ThreadEnumerator;

impl ThreadEnumerator {
    /// Enumerates all threads of the current process, excluding the calling thread,
    /// and returns their handles.
    /// ## Example
    /// ```rust
    /// let threads = ThreadEnumerator::enumerate_process_threads();
    /// for thread in threads {
    ///     // Do something with the thread handle, e.g., suspend or resume the thread
    ///    unsafe { SuspendThread(thread) };
    /// }
    /// ```
    pub unsafe fn enumerate_process_threads() -> Vec<HANDLE> {
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
                        let h_thread = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
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
