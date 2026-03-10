use std::ffi::CStr;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::SystemServices::*;
use windows_sys::Win32::System::WindowsProgramming::*;

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
                (h_module as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;

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
                        as *mut IMAGE_THUNK_DATA64;
                    let mut original_thunk = (h_module as usize
                        + (*import_desc).Anonymous.OriginalFirstThunk as usize)
                        as *const IMAGE_THUNK_DATA64;

                    // If OriginalFirstThunk is 0, we should use FirstThunk for both (FALLBACK)
                    if (*import_desc).Anonymous.OriginalFirstThunk == 0 {
                        original_thunk = thunk as *const IMAGE_THUNK_DATA64;
                    }

                    // Iterate through the thunks to find the target function
                    while (*thunk).u1.Function != 0 {
                        let mut is_match = false;

                        // Check if the import is by ordinal or by name. If it's by name, we need to compare the function name.
                        if ((*original_thunk).u1.Ordinal & (1 << 63)) == 0 {
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

                        // if we found we change the protection to allow writing, then write the detour into the IAT and restore protection
                        if is_match {
                            let original_fn = (*thunk).u1.Function as *mut u8;
                            let mut old_protect = 0;

                            // Change the protection of the memory page containing the IAT entry to allow writing
                            crate::mem::virtual_protect_same_execute(
                                thunk as _,
                                8,
                                PAGE_READWRITE,
                                &mut old_protect,
                            );

                            // HERE WE INSTALL THE HOOK
                            (*thunk).u1.Function = detour_function as u64;

                            // Restore orig. protection
                            VirtualProtect(thunk as _, 8, old_protect, &mut old_protect);

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
}
