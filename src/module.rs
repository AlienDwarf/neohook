// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
use std::ffi::CString;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::LibraryLoader::*;
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

/// Gets a (pseudo) handle to a loaded module by its name. This is a simple wrapper around `GetModuleHandleW` that returns an Option type for better error handling.
/// # Parameters
/// - `module_name`: The name of the module (DLL) to get the handle for. This should be the filename of the module, e.g., "kernel32.dll".
/// # Returns
/// `Some(HMODULE)` if the module is found, or `None` if the module is not loaded in the process.
pub fn get_module_handle(module_name: &str) -> Option<HMODULE> {
    unsafe {
        // Encode the module name as UTF-16, which is required by Windows APIs.
        let module_wide: Vec<u16> = module_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // Get a handle to the module
        let h_module = GetModuleHandleW(module_wide.as_ptr());
        if !h_module.is_null() {
            // If the module is found, return its handle
            Some(h_module)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::Foundation::HMODULE;

    use crate::module;

    #[test]
    fn get_module_size_returns_plausible_size_for_known_module() {
        let h_kernel32 =
            module::get_module_handle("kernel32.dll").expect("failed to get kernel32.dll handle");

        let size = module::get_module_size(h_kernel32);

        assert!(
            size > 0x10000,
            "kernel32.dll size looks implausibly small: {size}"
        );
    }

    #[test]
    fn get_module_size_returns_zero_for_invalid_handles() {
        let null_size = module::get_module_size(std::ptr::null_mut());
        assert_eq!(null_size, 0, "null module handle should return size 0");

        let mut stack_value = 0u32;
        let fake_module = (&mut stack_value as *mut u32).cast::<core::ffi::c_void>() as HMODULE;

        let fake_size = module::get_module_size(fake_module);
        assert_eq!(fake_size, 0, "non-module address should return size 0");
    }

    #[test]
    fn find_function_returns_address_for_existing_export() {
        let addr = module::find_function("kernel32.dll", "GetTickCount")
            .expect("expected GetTickCount to be found in kernel32.dll");

        assert!(
            !addr.is_null(),
            "resolved function pointer must not be null"
        );
    }

    #[test]
    fn find_function_returns_none_for_missing_export() {
        let addr = module::find_function("kernel32.dll", "DefinitelyNotARealWindowsExport_123");
        assert!(addr.is_none(), "missing export should return None");
    }

    #[test]
    fn find_function_returns_none_for_missing_module() {
        let addr = module::find_function("fantasy_dll_999.dll", "SomeFunc");
        assert!(addr.is_none(), "missing DLL should return None");
    }

    #[test]
    fn get_module_handle_returns_none_for_missing_module() {
        let handle = module::get_module_handle("fantasy_dll_999.dll");
        assert!(handle.is_none(), "missing DLL should return None");
    }

    #[test]
    fn find_function_returns_none_for_invalid_function_name_string() {
        let invalid_func_name = "Get\0TickCount";

        let addr = module::find_function("kernel32.dll", invalid_func_name);
        assert!(
            addr.is_none(),
            "embedded NUL in function name should return None"
        );
    }
}
