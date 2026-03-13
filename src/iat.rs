// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt;
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
#[cfg(target_arch = "x86")]
const IMAGE_OPTIONAL_MAGIC: u16 = IMAGE_NT_OPTIONAL_HDR32_MAGIC;

// If we're on 64-bit (x64):
#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;
#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64 as IMAGE_THUNK_DATA;
#[cfg(target_arch = "x86_64")]
const IMAGE_OPTIONAL_MAGIC: u16 = IMAGE_NT_OPTIONAL_HDR64_MAGIC;

#[derive(Debug)]
enum InternalIatHookError {
    NullModule,
    NullDetour,
    InvalidDosHeader,
    InvalidNtHeader,
    InvalidNtSignature,
    InvalidOptionalHeader,
    NoImportDirectory,
    MalformedImportDirectory,
    NameResolutionUnavailable,
    TargetNotFound,
    ProtectFailed(std::io::Error),
}

#[derive(Debug)]
pub enum IatHookError {
    InvalidParameter,
    InvalidPeImage,
    ImportTableUnavailable,
    NameResolutionUnavailable,
    TargetNotFound,
    ProtectFailed(std::io::Error),
}

impl fmt::Display for IatHookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameter => write!(f, "invalid IAT hook parameters"),
            Self::InvalidPeImage => write!(f, "invalid PE image"),
            Self::ImportTableUnavailable => write!(f, "import table unavailable"),
            Self::NameResolutionUnavailable => write!(f, "name resolution unavailable"),
            Self::TargetNotFound => write!(f, "target import not found"),
            Self::ProtectFailed(e) => write!(f, "failed to change page protection: {e}"),
        }
    }
}

impl From<InternalIatHookError> for IatHookError {
    fn from(err: InternalIatHookError) -> Self {
        match err {
            InternalIatHookError::NullModule | InternalIatHookError::NullDetour => {
                Self::InvalidParameter
            }
            InternalIatHookError::InvalidDosHeader
            | InternalIatHookError::InvalidNtHeader
            | InternalIatHookError::InvalidNtSignature
            | InternalIatHookError::InvalidOptionalHeader => Self::InvalidPeImage,

            InternalIatHookError::NoImportDirectory
            | InternalIatHookError::MalformedImportDirectory => Self::ImportTableUnavailable,

            InternalIatHookError::NameResolutionUnavailable => Self::NameResolutionUnavailable,
            InternalIatHookError::TargetNotFound => Self::TargetNotFound,
            InternalIatHookError::ProtectFailed(e) => Self::ProtectFailed(e),
        }
    }
}

#[derive(Copy, Clone, Debug)]
struct ModuleImage {
    base_address: usize,
    size: usize,
    import_dir_rva: usize,
    import_dir_size: usize,
}

pub struct IatHook;

impl IatHook {
    /// Hooks a function in the Import Address Table (IAT) of a loaded module.
    ///
    /// Returns a pointer to the original function if the hook was successfully installed, or an error if it failed.
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
    ) -> Result<*mut u8, IatHookError> {
        if h_module.is_null() {
            return Err(map_err(InternalIatHookError::NullModule));
        }
        if detour_function.is_null() {
            return Err(map_err(InternalIatHookError::NullDetour));
        }

        // Parse the PE headers and find the target import thunk
        let image = unsafe { parse_loaded_module(h_module)? };
        let thunk = unsafe { find_import_thunk(&image, target_dll, target_func)? };

        let slot_ptr = unsafe { thunk_function_slot_ptr(thunk) };
        let slot_size = std::mem::size_of::<usize>();

        let original_fn = unsafe { thunk_function(thunk) as *mut u8 };

        // Change the protection of the memory page containing the IAT entry to allow writing
        let mut old_protect = 0;
        let success =
            unsafe { VirtualProtect(slot_ptr, slot_size, PAGE_READWRITE, &mut old_protect) };

        // 11.03.26 (03-11-26) If we fail to change the protection, we return an error with the last OS error
        if success == 0 {
            return Err(map_err(InternalIatHookError::ProtectFailed(
                std::io::Error::last_os_error(),
            )));
        }

        // HERE WE INSTALL THE HOOK
        unsafe {
            write_thunk_function_slot(slot_ptr, detour_function);
        };

        let mut ignored: u32 = 0;
        let restore_success =
            unsafe { VirtualProtect(slot_ptr, slot_size, old_protect, &mut ignored) };
        if restore_success == 0 {
            return Err(map_err(InternalIatHookError::ProtectFailed(
                std::io::Error::last_os_error(),
            )));
        }

        Ok(original_fn)
    }

    /// Finds the address of the IAT slot for a named import.
    ///
    /// # Safety
    ///
    /// - `h_module` must be the base address of a valid PE image loaded in the current process.
    /// - The module's PE headers and import directory must be readable and structurally valid.
    /// - The returned pointer is only valid as long as the module remains loaded at that address.
    /// - Writing through the returned slot pointer is unsafe and must only be done with a
    ///   function pointer of compatible ABI/signature.
    /// - The caller must ensure any modification is valid with respect to concurrency/reentrancy.
    pub unsafe fn find_import_address(
        h_module: HMODULE,
        target_dll: &str,
        target_func: &str,
    ) -> Result<*mut *mut u8, IatHookError> {
        let image = unsafe { parse_loaded_module(h_module)? };
        let thunk = unsafe { find_import_thunk(&image, target_dll, target_func)? };
        Ok(unsafe { thunk_function_slot_ptr(thunk) } as *mut *mut u8)
    }
}

unsafe fn parse_loaded_module(h_module: HMODULE) -> Result<ModuleImage, InternalIatHookError> {
    // Validate the module handle
    if h_module.is_null() {
        return Err(InternalIatHookError::NullModule);
    }

    // Parse the PE headers of the loaded module to find the import directory
    let base_address = h_module as usize;
    let dos = base_address as *const IMAGE_DOS_HEADER;

    // 11.03.26 (03-11-26) - Check the DOS signature
    // Should be "MZ" (0x5A4D) when valid
    if unsafe { (*dos).e_magic } != IMAGE_DOS_SIGNATURE {
        return Err(InternalIatHookError::InvalidDosHeader);
    }

    // Calculate the address of the NT headers using the e_lfanew offset from the DOS header
    let e_lfanew = unsafe { (*dos).e_lfanew };
    if e_lfanew <= 0 {
        return Err(InternalIatHookError::InvalidNtHeader);
    }

    let nt_addr = base_address
        .checked_add(e_lfanew as usize)
        .ok_or(InternalIatHookError::InvalidNtHeader)?;
    let nt = nt_addr as *const IMAGE_NT_HEADERS;

    // 11.03.26 (03-11-26) - Check the NT signature
    /* https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#signature-image-only
    Should be "PE\0\0" (0x4550) when valid
    Fail mean no valid PE file
    Prevents from certain types malformed or non PE files that could cause a crash
     */
    if unsafe { (*nt).Signature } != IMAGE_NT_SIGNATURE {
        return Err(InternalIatHookError::InvalidNtSignature);
    }

    // Check the Optional Header magic to ensure it's a valid PE32 or PE32+ file
    if unsafe { (*nt).OptionalHeader.Magic } != IMAGE_OPTIONAL_MAGIC {
        return Err(InternalIatHookError::InvalidOptionalHeader);
    }

    let size_of_image = unsafe { (*nt).OptionalHeader.SizeOfImage as usize };
    if size_of_image == 0 {
        return Err(InternalIatHookError::InvalidOptionalHeader);
    }

    let number_of_dirs = unsafe { (*nt).OptionalHeader.NumberOfRvaAndSizes as usize };
    if number_of_dirs <= IMAGE_DIRECTORY_ENTRY_IMPORT as usize {
        return Err(InternalIatHookError::NoImportDirectory);
    }

    // Get the Import Directory entry from the Data Directory
    let import_dir =
        unsafe { (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize] };

    // Validate the Import Directory entry
    if import_dir.VirtualAddress == 0 || import_dir.Size == 0 {
        return Err(InternalIatHookError::NoImportDirectory);
    }

    // rva = virtual address relative to the module base, we need to check that it points within the image
    let import_dir_rva = import_dir.VirtualAddress as usize;
    let import_dir_size = import_dir.Size as usize;

    // Check that the Import Directory fits within the image bounds
    let import_dir_end = import_dir_rva
        .checked_add(import_dir_size)
        // We check that the end of the import directory does not exceed the size of the image, to prevent out-of-bounds access when we later read the import descriptors.
        .ok_or(InternalIatHookError::MalformedImportDirectory)?;

    // crucial to prevent crashes or security issues when dealing with malformed or malicious PE files that could have an import directory that extends beyond the actual image size.
    if import_dir_end > size_of_image {
        return Err(InternalIatHookError::MalformedImportDirectory);
    }

    Ok(ModuleImage {
        base_address,
        size: size_of_image,
        import_dir_rva,
        import_dir_size,
    })
}

unsafe fn find_import_thunk(
    image: &ModuleImage,
    target_dll: &str,
    target_func: &str,
) -> Result<*mut IMAGE_THUNK_DATA, InternalIatHookError> {
    // desc_rva = RVA of the current IMAGE_IMPORT_DESCRIPTOR we're checking
    let mut desc_rva = image.import_dir_rva;

    // Calculate the end RVA of the import directory
    let desc_end = image
        .import_dir_rva
        .checked_add(image.import_dir_size)
        .ok_or(InternalIatHookError::MalformedImportDirectory)?;

    // Loop through the IMAGE_IMPORT_DESCRIPTORs until we find the target DLL or reach the end
    while desc_rva
        .checked_add(std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>())
        .ok_or(InternalIatHookError::MalformedImportDirectory)?
        <= desc_end
    {
        // Get a pointer to the current IMAGE_IMPORT_DESCRIPTOR
        let import_desc = unsafe {
            rva_to_ptr::<IMAGE_IMPORT_DESCRIPTOR>(image, desc_rva)
                .ok_or(InternalIatHookError::MalformedImportDirectory)?
        };

        // desc = the current IMAGE_IMPORT_DESCRIPTOR
        let desc = unsafe { *import_desc };

        // If the Name field is 0, it means we've reached the end of the import descriptors (the last one is all zeros)
        // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-directory-table
        // "The last [...] entry is empty"
        if desc.Name == 0 {
            return Err(InternalIatHookError::TargetNotFound);
        }

        // Read the DLL name from the Name RVA
        let dll_name = read_c_string_from_rva(image, desc.Name as usize)
            .ok_or(InternalIatHookError::MalformedImportDirectory)?;

        // Compare the DLL name with the target DLL name (case-insensitive)
        if dll_name.eq_ignore_ascii_case(target_dll) {
            // Here we found the DLL. Now we look for target func

            // sanity check if ft is 0 it means there are not iat entries
            if desc.FirstThunk == 0 {
                return Err(InternalIatHookError::MalformedImportDirectory);
            }

            // IMPORTANT: For name resolution we need the INT (OriginalFirstThunk).
            // If it's missing, we deliberately fail instead of trying to misuse the already overwritten IAT as a name table.

            if unsafe { desc.Anonymous.OriginalFirstThunk } == 0 {
                return Err(InternalIatHookError::NameResolutionUnavailable);
            }

            let mut thunk_rva = desc.FirstThunk as usize;
            let mut original_thunk_rva = unsafe { desc.Anonymous.OriginalFirstThunk as usize };

            // Loop through the thunks to find the target function
            loop {
                let thunk = unsafe {
                    rva_to_mut_ptr::<IMAGE_THUNK_DATA>(image, thunk_rva)
                        .ok_or(InternalIatHookError::MalformedImportDirectory)?
                };
                let original_thunk = unsafe {
                    rva_to_ptr::<IMAGE_THUNK_DATA>(image, original_thunk_rva)
                        .ok_or(InternalIatHookError::MalformedImportDirectory)?
                };

                // Our loop termination when we reach the end of the tunks
                let lookup = unsafe { thunk_address_of_data(original_thunk) };
                if lookup == 0 {
                    break;
                }

                // Check if the import is by ordinal or by name. If it's by ordinal, we can't resolve the name, so we skip it.
                if !unsafe { thunk_is_ordinal(original_thunk) } {
                    let func_name = read_import_name(image, lookup)
                        .ok_or(InternalIatHookError::MalformedImportDirectory)?;

                    // If the name matches we retourn the pointer to the IAT slot
                    if func_name == target_func {
                        return Ok(thunk);
                    }
                }

                thunk_rva = thunk_rva
                    .checked_add(std::mem::size_of::<IMAGE_THUNK_DATA>())
                    .ok_or(InternalIatHookError::MalformedImportDirectory)?;
                original_thunk_rva = original_thunk_rva
                    .checked_add(std::mem::size_of::<IMAGE_THUNK_DATA>())
                    .ok_or(InternalIatHookError::MalformedImportDirectory)?;
            }

            // If we reach here, it means we found the target DLL but not the target function within its imports
            return Err(InternalIatHookError::TargetNotFound);
        }

        // Move to the next IMAGE_IMPORT_DESCRIPTOR (WHILE ITERATION. NOT LOOP)
        desc_rva = desc_rva
            .checked_add(std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>())
            .ok_or(InternalIatHookError::MalformedImportDirectory)?;
    }

    Err(InternalIatHookError::MalformedImportDirectory)
}

unsafe fn rva_to_ptr<T>(image: &ModuleImage, rva: usize) -> Option<*const T> {
    let size = std::mem::size_of::<T>();
    if rva == 0 || size == 0 {
        return None;
    }

    let end = rva.checked_add(size)?;
    if end > image.size {
        return None;
    }

    let addr = image.base_address.checked_add(rva)?;
    Some(addr as *const T)
}

unsafe fn rva_to_mut_ptr<T>(image: &ModuleImage, rva: usize) -> Option<*mut T> {
    let size = std::mem::size_of::<T>();
    if rva == 0 || size == 0 {
        return None;
    }

    let end = rva.checked_add(size)?;
    if end > image.size {
        return None;
    }

    let addr = image.base_address.checked_add(rva)?;
    Some(addr as *mut T)
}

fn read_c_string_from_rva(image: &ModuleImage, rva: usize) -> Option<String> {
    if rva == 0 || rva >= image.size {
        return None;
    }

    let start = image.base_address.checked_add(rva)?;
    let end = image.base_address.checked_add(image.size)?;

    let mut cur = start;
    while cur < end {
        let byte = unsafe { *(cur as *const u8) };
        if byte == 0 {
            let len = cur.checked_sub(start)?;
            let bytes = unsafe { std::slice::from_raw_parts(start as *const u8, len) };
            return Some(String::from_utf8_lossy(bytes).into_owned());
        }
        cur = cur.checked_add(1)?;
    }

    None
}

fn read_import_name(image: &ModuleImage, import_by_name_rva: usize) -> Option<String> {
    // IMAGE_IMPORT_BY_NAME = WORD Hint; BYTE Name[];
    let name_rva = import_by_name_rva.checked_add(std::mem::size_of::<u16>())?;
    read_c_string_from_rva(image, name_rva)
}

#[cfg(target_arch = "x86")]
unsafe fn thunk_is_ordinal(thunk: *const IMAGE_THUNK_DATA) -> bool {
    (unsafe { (*thunk).u1.Ordinal } & 0x8000_0000) != 0
}

#[cfg(target_arch = "x86_64")]
unsafe fn thunk_is_ordinal(thunk: *const IMAGE_THUNK_DATA) -> bool {
    (unsafe { (*thunk).u1.Ordinal } & (1u64 << 63)) != 0
}

unsafe fn thunk_address_of_data(thunk: *const IMAGE_THUNK_DATA) -> usize {
    (unsafe { (*thunk).u1.AddressOfData }) as usize
}

unsafe fn thunk_function(thunk: *const IMAGE_THUNK_DATA) -> usize {
    (unsafe { (*thunk).u1.Function }) as usize
}

unsafe fn thunk_function_slot_ptr(thunk: *mut IMAGE_THUNK_DATA) -> *mut core::ffi::c_void {
    (unsafe { &mut (*thunk).u1.Function }) as *mut _ as *mut core::ffi::c_void
}

fn map_err(err: InternalIatHookError) -> IatHookError {
    err.into()
}

#[cfg(target_arch = "x86")]
unsafe fn write_thunk_function_slot(slot_ptr: *mut core::ffi::c_void, detour: *const u8) {
    unsafe { std::ptr::write(slot_ptr as *mut u32, detour as u32) }
}

#[cfg(target_arch = "x86_64")]
unsafe fn write_thunk_function_slot(slot_ptr: *mut core::ffi::c_void, detour: *const u8) {
    unsafe { std::ptr::write(slot_ptr as *mut u64, detour as u64) };
}
