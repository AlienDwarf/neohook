use std::ffi::CString;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;

pub fn get_module_size(h_module: HMODULE) -> u32 {
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };

    if unsafe {
        VirtualQuery(
            h_module as _,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    } != 0
    {
        // The RegionSize field of MEMORY_BASIC_INFORMATION gives the size of the region in bytes.
        return mbi.RegionSize as u32;
    }
    // If VirtualQuery fails, we return 0 to indicate an error.
    0
}

pub fn find_function(module_name: &str, function_name: &str) -> Option<*const u8> {
    // Encode the module and function names as UTF-16, which is required by Windows APIs.
    let module_name_wide: Vec<u16> = module_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // Get a handle to the module. This will return a handle to the module if it's already loaded in the process.
    let h_module = unsafe {
        let mut h = GetModuleHandleW(module_name_wide.as_ptr());
        if h.is_null() {
            // If the module is not already loaded, we can try to load it
            h = LoadLibraryW(module_name_wide.as_ptr());
        }
        h
    };

    if h_module.is_null() {
        return None; // Module not found
    }

    // Encode the function name as UTF-8, which is required by GetProcAddress.
    let function_name_cstr = match CString::new(function_name) {
        Ok(cstr) => cstr,
        Err(_) => return None, // Invalid function name
    };

    // Get the address of the function within the module.
    let func_address =
        unsafe { GetProcAddress(h_module, function_name_cstr.as_ptr() as *const u8) };

    // If the function is not found, GetProcAddress returns null. We return None in that case.
    // If the function is found, we return its address as a pointer to first byte of the function
    func_address.map(|addr| addr as *const u8)
}
