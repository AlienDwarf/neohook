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
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let curr = target as usize;

        // We search for a free region in 2MB steps ±1GB radius of the target which is maxumum jump distance for x86 relative jumps
        for i in 1..512 {
            let offset = i * 1024 * 1024 * 2; // i * 1024 = 1KB, * 1024 = 1MB, * 2 = 2MB 

            // We check both directions (above and below the target address) for free memory regions.
            for &search_addr in &[curr.saturating_add(offset), curr.saturating_sub(offset)] {
                if search_addr == 0 {
                    continue;
                }

                unsafe {
                    if VirtualQuery(
                        search_addr as _,
                        &mut mbi,
                        std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                    ) != 0
                    {
                        if mbi.State == MEM_FREE && mbi.RegionSize >= size {
                            let allocated = VirtualAlloc(
                                mbi.BaseAddress,
                                size,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE,
                            );
                            if !allocated.is_null() {
                                return Some(allocated as *mut u8);
                            }
                        }
                    }
                }
            }
        }
        None
    }
}
