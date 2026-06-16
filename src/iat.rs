// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::SystemServices::*;

use crate::pe::{self, ModuleImage as PeImage, PeError};

// --- Architecture-specific imports ---

// If we're on 32-bit (x86):
#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA32 as IMAGE_THUNK_DATA;

// If we're on 64-bit (x64):
#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64 as IMAGE_THUNK_DATA;

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

impl From<PeError> for InternalIatHookError {
    fn from(err: PeError) -> Self {
        match err {
            PeError::NullModule => Self::NullModule,
            PeError::InvalidDosHeader => Self::InvalidDosHeader,
            PeError::InvalidNtHeader => Self::InvalidNtHeader,
            PeError::InvalidNtSignature => Self::InvalidNtSignature,
            PeError::InvalidOptionalHeader => Self::InvalidOptionalHeader,
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
    /// Validated base/size view, shared with the generic PE helpers.
    image: PeImage,
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
        if unsafe { VirtualProtect(slot_ptr, slot_size, old_protect, &mut ignored) } == 0 {
            let protect_err = std::io::Error::last_os_error();
            unsafe {
                write_thunk_function_slot(slot_ptr, original_fn);
            }
            let _ = unsafe { VirtualProtect(slot_ptr, slot_size, old_protect, &mut ignored) };

            return Err(map_err(InternalIatHookError::ProtectFailed(protect_err)));
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
    // Validate the DOS/NT/Optional headers via the shared PE parser. This
    // already bounds the data directory lookup below to the image size.
    let image = pe::parse_module_image(h_module)?;

    // Get the Import Directory entry from the Data Directory. `data_directory`
    // returns `None` when the directory is absent, empty, or extends beyond the
    // image bounds, all of which mean there is no usable import table.
    let (import_dir_rva, import_dir_size) =
        pe::data_directory(&image, IMAGE_DIRECTORY_ENTRY_IMPORT as usize)
            .ok_or(InternalIatHookError::NoImportDirectory)?;

    Ok(ModuleImage {
        image,
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
        let import_desc = pe::rva_to_ptr::<IMAGE_IMPORT_DESCRIPTOR>(&image.image, desc_rva)
            .ok_or(InternalIatHookError::MalformedImportDirectory)?;

        // desc = the current IMAGE_IMPORT_DESCRIPTOR
        let desc = unsafe { *import_desc };

        // If the Name field is 0, it means we've reached the end of the import descriptors (the last one is all zeros)
        // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-directory-table
        // "The last [...] entry is empty"
        if desc.Name == 0 {
            return Err(InternalIatHookError::TargetNotFound);
        }

        // Read the DLL name from the Name RVA
        let dll_name = pe::read_c_string_from_rva(&image.image, desc.Name as usize)
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
                let thunk = pe::rva_to_mut_ptr::<IMAGE_THUNK_DATA>(&image.image, thunk_rva)
                    .ok_or(InternalIatHookError::MalformedImportDirectory)?;
                let original_thunk =
                    pe::rva_to_ptr::<IMAGE_THUNK_DATA>(&image.image, original_thunk_rva)
                        .ok_or(InternalIatHookError::MalformedImportDirectory)?;

                // Our loop termination when we reach the end of the tunks
                let lookup = unsafe { thunk_address_of_data(original_thunk) };
                if lookup == 0 {
                    break;
                }

                // Check if the import is by ordinal or by name. If it's by ordinal, we can't resolve the name, so we skip it.
                if !unsafe { thunk_is_ordinal(original_thunk) } {
                    let func_name = read_import_name(&image.image, lookup)
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

fn read_import_name(image: &PeImage, import_by_name_rva: usize) -> Option<String> {
    // IMAGE_IMPORT_BY_NAME = WORD Hint; BYTE Name[];
    let name_rva = import_by_name_rva.checked_add(std::mem::size_of::<u16>())?;
    pe::read_c_string_from_rva(image, name_rva)
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
