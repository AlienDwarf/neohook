use windows_sys::Win32::System::Memory::*;
use windows_sys::core::BOOL;

/// Adjusts the new protection flags to include execute permissions 
/// if the old protection had execute permissions.
fn detour_page_protect_adjust_execute(old_protect: u32, new_protect: u32) -> u32 {
    const EXECUTE_FLAGS: u32 = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    
    if (old_protect & EXECUTE_FLAGS) != 0 {
        match new_protect {
            PAGE_READONLY => PAGE_EXECUTE_READ,
            PAGE_READWRITE => PAGE_EXECUTE_READWRITE,
            PAGE_WRITECOPY => PAGE_EXECUTE_WRITECOPY,
            _ => new_protect,
        }
    } else {
        new_protect
    }
}

/// Changes the protection of a region of memory, 
/// ensuring that if the original protection included execute permissions, 
/// the new protection will also include execute permissions.
pub unsafe fn virtual_protect_same_execute(
    address: *mut u8,
    size: usize,
    new_protect: u32,
    old_protect_out: *mut u32
) -> BOOL {
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    
    unsafe {
        if VirtualQuery(address as _, &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) == 0 {
            return 0;
        }

        let adjusted_protect = detour_page_protect_adjust_execute(mbi.Protect, new_protect);
        VirtualProtect(address as _, size, adjusted_protect, old_protect_out)
    }
}