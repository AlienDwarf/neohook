// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
use windows_sys::Win32::System::Memory::*;

#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::SystemInformation::GetSystemInfo;

/// Provides functionality to allocate memory for trampolines,
/// ensuring that the allocated memory is within a certain distance from the target function.
pub struct TrampolineAlloc;

impl TrampolineAlloc {
    /// Allocates a region of memory that is within 2GB of the target address, which is necessary for x86 relative jumps.
    /// - `target`: The address of the function we want to hook
    /// - `size`: The size of the memory region we want to allocate for the trampoline
    ///
    /// # Safety
    /// The caller must ensure that `target` is a valid pointer
    pub unsafe fn alloc_nearby(target: *const u8, size: usize) -> Option<*mut u8> {
        // safety check if size is 0 return none
        if size == 0 {
            return None;
        }

        // --- x86 ---
        // For x86, we can simply allocate anywhere in the process's address space because the entire 4GB range is addressable with relative jumps.
        #[cfg(target_arch = "x86")]
        {
            unsafe {
                let _ = target; // prevents "unused parameter" warning but it's not needed in x86
                let addr = VirtualAlloc(
                    std::ptr::null(),
                    size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                );
                if addr.is_null() {
                    return None;
                }
                return Some(addr as *mut u8);
            }
        }

        // --- x64 ---
        // For x64, we need to ensure that the allocated memory is within 2GB of the target address to be reachable by relative jumps.
        // If this is not possible we must use an absolute jump which requires a different patching strategy
        #[cfg(target_arch = "x86_64")]
        {
            use windows_sys::Win32::System::SystemInformation::SYSTEM_INFO;

            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };

            // Define boundaries in a 2GB range around the target address
            let safety_buffer = 1024 * 1024 + size; // 1MB + size of trampoline to ensure we have enough space (should be more than enough for almost every trampoline)
            let range = (i32::MAX as usize).saturating_sub(safety_buffer);

            // We define a search range of ±2GB around the target address
            let min_addr = (target as usize).saturating_sub(range);
            let max_addr = (target as usize).saturating_add(range);

            let mut current_addr = min_addr;

            // Get System Info to know the allocation granularity
            let mut si: SYSTEM_INFO = unsafe { std::mem::zeroed() };
            unsafe { GetSystemInfo(&mut si) };
            let alloc_granularity = si.dwAllocationGranularity as usize;

            // We scan block by block to find free regions that are at least `size` bytes
            while current_addr < max_addr {
                let query_result = unsafe {
                    VirtualQuery(
                        current_addr as _,
                        &mut mbi,
                        std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                    )
                };

                if query_result == 0 {
                    break;
                }

                // Is this region free and large enough for our trampoline?
                if mbi.State == MEM_FREE && mbi.RegionSize >= size {
                    // Try to allocate here
                    // We have to ensure it's 64KB aligned (Allocation Granularity)
                    let region_start = mbi.BaseAddress as usize;
                    let region_end = region_start.saturating_add(mbi.RegionSize);
                    let search_start = region_start.max(current_addr);
                    let alloc_candidate = align_up(search_start, alloc_granularity);

                    // Now a more robust check to ensure the candidate is within 2GB
                    if alloc_candidate.saturating_add(size) <= region_end
                        && alloc_candidate >= min_addr
                        && alloc_candidate.saturating_add(size) <= max_addr
                    {
                        let allocated = unsafe {
                            VirtualAlloc(
                                alloc_candidate as _,
                                size,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE,
                            )
                        };
                        if !allocated.is_null() {
                            return Some(allocated as *mut u8);
                        }
                    }
                }

                // We used to jump 2MB
                // However now we jump to the next region because it's more efficient
                current_addr = (mbi.BaseAddress as usize) + mbi.RegionSize;

                // Prevent overflow so we don't loop indefinitely
                if current_addr <= (mbi.BaseAddress as usize) {
                    break;
                }
            }

            None
        }
        // If we are on an unsupported architecture, we return None
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        {
            return None;
        }
    }
}

// Helper function to align an address up to the nearest multiple of `align`
#[cfg(target_arch = "x86_64")]
fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}

/// Lightweight Trampoline handle for convenience.
pub struct Trampoline {
    pub ptr: *mut u8,
    pub size: usize,
}

impl std::fmt::Debug for Trampoline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Trampoline")
            .field("ptr", &self.ptr)
            .field("size", &self.size)
            .finish()
    }
}

impl Trampoline {
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Change protection to RX (PAGE_EXECUTE_READ). Returns true on success.
    pub fn make_rx(&self) -> bool {
        unsafe {
            let mut old = 0u32;
            let res = VirtualProtect(self.ptr as _, self.size, PAGE_EXECUTE_READ, &mut old);
            res != 0
        }
    }
}

impl TrampolineAlloc {
    /// Allocate a `Trampoline` structure near `target` with RWX permissions.
    /// Caller should make_rx()
    ///
    /// # Safety
    /// The caller must ensure that `target` is a valid pointer
    pub unsafe fn alloc_nearby_trampoline(target: *const u8, size: usize) -> Option<Trampoline> {
        if target.is_null() {
            return None;
        }

        unsafe { Self::alloc_nearby(target, size) }.map(|p| Trampoline { ptr: p, size })
    }
}

impl Drop for Trampoline {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                let _ = VirtualFree(self.ptr as _, 0, MEM_RELEASE);
            }
        }
    }
}
