use windows_sys::Win32::System::Memory::*;

/// Provides functionality to allocate memory for trampolines,
/// ensuring that the allocated memory is within a certain distance from the target function.
pub struct TrampolineAlloc;

impl TrampolineAlloc {
    /// Allocates a region of memory that is within 2GB of the target address, which is necessary for x86 relative jumps.
    /// - `target`: The address of the function we want to hook
    /// - `size`: The size of the memory region we want to allocate for the trampoline
    /// # Safety
    /// This function performs raw pointer arithmetic. The caller must ensure that `target` is a valid pointer
    pub unsafe fn alloc_nearby(target: *const u8, size: usize) -> Option<*mut u8> {
        // safety check if size is 0 return none
        if size == 0 {
            return None;
        }

        // --- x86 ---
        // For x86, we can simply allocate anywhere in the process's address space because the entire 4GB range is addressable with relative jumps.
        #[cfg(target_arch = "x86")]
        {
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

        // --- x64 ---
        // For x64, we need to ensure that the allocated memory is within 2GB of the target address to be reachable by relative jumps.
        // If this is not possible we must use an absolute jump which requires a different patching strategy
        #[cfg(target_arch = "x86_64")]
        {
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };

            // We define a search range of ±2GB around the target address
            let min_addr = (target as usize).saturating_sub(0x7FFF_0000);
            let max_addr = (target as usize).saturating_add(0x7FFF_0000);

            let mut current_addr = min_addr;

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
                    let alloc_addr = align_up(current_addr, 64 * 1024);

                    if alloc_addr < (current_addr + mbi.RegionSize) {
                        let allocated = unsafe {
                            VirtualAlloc(
                                alloc_addr as _,
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
    }
}

// Helper function to align an address up to the nearest multiple of `align`
#[cfg(target_arch = "x86_64")]
fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}
