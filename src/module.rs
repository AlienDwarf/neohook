use std::ffi::CString;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::SystemServices::*;

// --- Architecture-specific imports ---
#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32 as IMAGE_NT_HEADERS;

#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;

pub fn get_module_size(h_module: HMODULE) -> u32 {
    // Reworked function. Now we read the PE headers to get the size of the module instead of using VirtualQuery,
    // which can be unreliable for modules with non-standard memory layouts (e.g., due to ASLR, rebasing, or custom section alignments).

    // safety check
    if h_module.is_null() {
        return 0;
    }

    let dos_header = h_module as *const IMAGE_DOS_HEADER;

    // validation: Is this a valid PE Module?
    unsafe {
        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            return 0;
        }
    }

    // Go to nt header
    let nt_headers =
        unsafe { (h_module as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS };

    // Now we can read the SizeOfImage from the optional header to get the size
    (unsafe { *nt_headers }).OptionalHeader.SizeOfImage
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
