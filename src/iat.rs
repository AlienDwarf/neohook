// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
use std::ffi::CStr;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::SystemServices::*;

// --- Architecture-specific imports ---

// If we're on 32-bit (x86):
#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32 as IMAGE_NT_HEADERS;
#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA32 as IMAGE_THUNK_DATA;

// If we're on 64-bit (x64):
#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;
#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64 as IMAGE_THUNK_DATA;

pub struct IatHook;

impl IatHook {
    /// Hooks a function in the Import Address Table (IAT) of a module.
    ///
    /// Returns the original imported function pointer on success.
    ///
    /// # Safety
    ///
    /// - `h_module` must be a valid handle/base address of a PE module loaded in the
    ///   current process.
    /// - The PE headers and import directory referenced by `h_module` must be valid
    ///   and readable.
    /// - `detour_function` must be a valid function pointer with a compatible ABI
    ///   and signature for the target import.
    /// - Calling the returned original function pointer is only safe if it is cast
    ///   to the correct function type and called with the correct ABI.
    /// - Modifying the target module's IAT must be valid for the process and must
    ///   not violate any concurrency assumptions of the caller.
    pub unsafe fn hook_import(
        h_module: HMODULE, // Handle to the module whose IAT we want to hook
        target_dll: &str,
        target_func: &str,
        detour_function: *const u8,
    ) -> Option<*mut u8> {
        if h_module.is_null() {
            return None;
        }

        unsafe {
            // Parse the PE headers
            let dos_header = h_module as *const IMAGE_DOS_HEADER;
            if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
                return None;
            }

            // Calculate the address of the NT headers using the e_lfanew offset from the DOS header
            let nt_headers =
                (h_module as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;

            let import_dir =
                (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
            if import_dir.Size == 0 {
                return None;
            }

            // Iterate through the import descriptors to find the target DLL
            let mut import_desc = (h_module as usize + import_dir.VirtualAddress as usize)
                as *mut IMAGE_IMPORT_DESCRIPTOR;

            // Loop through the import descriptors until we find the target DLL or reach the end (indicated by a descriptor with all fields set to 0)
            while (*import_desc).Name != 0 {
                let name_ptr = (h_module as usize + (*import_desc).Name as usize) as *const i8;
                let dll_name = CStr::from_ptr(name_ptr).to_string_lossy();

                if dll_name.eq_ignore_ascii_case(target_dll) {
                    // We need to find the Original Thunk (names) and the First Thunk (addresses)
                    let mut thunk = (h_module as usize + (*import_desc).FirstThunk as usize)
                        as *mut IMAGE_THUNK_DATA;
                    let mut original_thunk = (h_module as usize
                        + (*import_desc).Anonymous.OriginalFirstThunk as usize)
                        as *const IMAGE_THUNK_DATA;

                    // If OriginalFirstThunk is 0, we should use FirstThunk for both (FALLBACK)
                    if (*import_desc).Anonymous.OriginalFirstThunk == 0 {
                        original_thunk = thunk as *const IMAGE_THUNK_DATA;
                    }

                    // Iterate through the thunks to find the target function
                    // Added: check for null pointers and zero ordinals to avoid infinite loops in case of malformed IATs
                    while (*thunk).u1.Function != 0
                        && !original_thunk.is_null()
                        && (*original_thunk).u1.Ordinal != 0
                    {
                        let mut is_match = false;

                        // ordinal check
                        #[cfg(target_arch = "x86")]
                        // In x86, the highest bit (0x80000000) indicates
                        let is_ordinal = ((*original_thunk).u1.Ordinal & 0x8000_0000) != 0;
                        #[cfg(target_arch = "x86_64")]
                        // In x64, the highest bit (0x8000000000000000) indicates
                        let is_ordinal = ((*original_thunk).u1.Ordinal & (1 << 63)) != 0;

                        if !is_ordinal {
                            let addr_of_data = (*original_thunk).u1.AddressOfData as usize;
                            if addr_of_data != 0 {
                                // Import by name, we need to check the function name
                                let import_by_name = (h_module as usize
                                    + (*original_thunk).u1.AddressOfData as usize)
                                    as *const IMAGE_IMPORT_BY_NAME;
                                // The Name field of IMAGE_IMPORT_BY_NAME is a null-terminated string, so we can use CStr to read it safely.
                                let func_name =
                                    CStr::from_ptr((*import_by_name).Name.as_ptr() as *const i8)
                                        .to_string_lossy();
                                // Compare the function name with the target function name
                                if func_name == target_func {
                                    is_match = true;
                                }
                            }
                        }

                        // if we found we change the protection to allow writing, then write the detour into the IAT and restore protection
                        if is_match {
                            let original_fn = (*thunk).u1.Function as *mut u8;
                            let mut old_protect = 0;
                            let ptr_size = std::mem::size_of::<usize>();

                            // Change the protection of the memory page containing the IAT entry to allow writing
                            crate::mem::virtual_protect_same_execute(
                                thunk as _,
                                ptr_size,
                                PAGE_READWRITE,
                                &mut old_protect,
                            );

                            // HERE WE INSTALL THE HOOK
                            // NOW SUPPORTING BOTH x86 AND x64
                            #[cfg(target_arch = "x86")]
                            {
                                (*thunk).u1.Function = detour_function as u32;
                            }
                            #[cfg(target_arch = "x86_64")]
                            {
                                (*thunk).u1.Function = detour_function as u64;
                            }

                            // Restore orig. protection
                            VirtualProtect(thunk as _, ptr_size, old_protect, &mut old_protect);

                            // Then return the original fn ptr
                            return Some(original_fn);
                        }

                        // Else, move to the next thunk
                        thunk = thunk.add(1);
                        original_thunk = original_thunk.add(1);
                    }
                }
                // If not found in this descriptor, move to the next one
                import_desc = import_desc.add(1);
            }
        }
        // If we reach here, it means we didn't find the target DLL or function in the IAT
        None
    }

    /// Safe wrapper that returns a Result and maps None to `DetourError::InvalidParameter`.
    pub fn hook_import_safe(
        h_module: HMODULE,
        target_dll: &str,
        target_func: &str,
        detour_function: *const u8,
    ) -> Result<*mut u8, crate::DetourError> {
        unsafe {
            if let Some(orig) =
                Self::hook_import(h_module, target_dll, target_func, detour_function)
            {
                Ok(orig)
            } else {
                Err(crate::DetourError::InvalidParameter)
            }
        }
    }

    /// This function is similar to `hook_import`, but instead of writing the detour, it just finds the address of the IAT slot for the specified imported function. This can be used for more advanced hooking techniques where you want to write a custom jump or trampoline instead of a direct detour.
    pub fn find_import_address(
        h_module: HMODULE,
        target_dll: &str,
        target_func: &str,
    ) -> Option<*mut *mut u8> {
        if h_module.is_null() {
            return None;
        }

        let dos_header = h_module as *const IMAGE_DOS_HEADER;

        let e_magic = unsafe { (*dos_header).e_magic };
        if e_magic != IMAGE_DOS_SIGNATURE {
            return None;
        }

        let e_lfanew = unsafe { (*dos_header).e_lfanew as usize };
        let nt_headers = (h_module as usize + e_lfanew) as *const IMAGE_NT_HEADERS;

        let import_dir = unsafe {
            (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize]
        };
        if import_dir.Size == 0 {
            return None;
        }

        let mut import_desc = (h_module as usize + import_dir.VirtualAddress as usize)
            as *mut IMAGE_IMPORT_DESCRIPTOR;

        while unsafe { (*import_desc).Name } != 0 {
            let name_rva = unsafe { (*import_desc).Name as usize };
            let name_ptr = (h_module as usize + name_rva) as *const i8;
            let dll_name = unsafe { CStr::from_ptr(name_ptr) }.to_string_lossy();

            if dll_name.eq_ignore_ascii_case(target_dll) {
                let mut thunk = unsafe { h_module as usize + (*import_desc).FirstThunk as usize }
                    as *mut IMAGE_THUNK_DATA;
                let mut original_thunk = (h_module as usize
                    + unsafe { (*import_desc).Anonymous.OriginalFirstThunk } as usize)
                    as *const IMAGE_THUNK_DATA;

                if unsafe { (*import_desc).Anonymous.OriginalFirstThunk } == 0 {
                    original_thunk = thunk as *const IMAGE_THUNK_DATA;
                }

                while unsafe { (*thunk).u1.Function } != 0
                    && !original_thunk.is_null()
                    && unsafe { (*original_thunk).u1.Ordinal } != 0
                {
                    let mut is_match = false;

                    #[cfg(target_arch = "x86")]
                    let is_ordinal = (unsafe { (*original_thunk).u1.Ordinal } & 0x8000_0000) != 0;
                    #[cfg(target_arch = "x86_64")]
                    let is_ordinal = (unsafe { (*original_thunk).u1.Ordinal } & (1 << 63)) != 0;

                    if !is_ordinal {
                        let addr_of_data = unsafe { (*original_thunk).u1.AddressOfData } as usize;
                        if addr_of_data != 0 {
                            let import_by_name =
                                (h_module as usize + addr_of_data) as *const IMAGE_IMPORT_BY_NAME;
                            let func_name = unsafe {
                                CStr::from_ptr((*import_by_name).Name.as_ptr() as *const i8)
                                    .to_string_lossy()
                            };
                            if func_name == target_func {
                                is_match = true;
                            }
                        }
                    }

                    if is_match {
                        // Return the address of the IAT slot
                        return Some(thunk as *mut *mut u8);
                    }

                    thunk = unsafe { thunk.add(1) };
                    original_thunk = unsafe { original_thunk.add(1) };
                }
            }
            import_desc = unsafe { import_desc.add(1) };
        }
        None
    }
}
