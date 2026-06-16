// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Module / PE introspection for the running process.
//!
//! These helpers mirror the Microsoft Detours `DetourEnumerate*` family: they
//! let callers discover hook targets at runtime by listing loaded modules, a
//! module's entry point, its exports (EAT) and its imports. All PE parsing is
//! bounds-checked through [`crate::pe`].

use crate::pe::{self, PeError};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::SystemServices::*;

// The high bit of an import lookup entry marks an import-by-ordinal. The flag
// width matches the pointer-sized IMAGE_THUNK_DATA on each architecture.
#[cfg(target_arch = "x86")]
const IMAGE_ORDINAL_FLAG: usize = 0x8000_0000;
#[cfg(target_arch = "x86_64")]
const IMAGE_ORDINAL_FLAG: usize = 1usize << 63;

/// A module loaded in the current process.
#[derive(Clone, Debug)]
pub struct ModuleInfo {
    /// Base address the module is loaded at (its `HMODULE`).
    pub base: HMODULE,
    /// Size of the module image in bytes.
    pub size: u32,
    /// File name of the module (e.g. `kernel32.dll`).
    pub name: String,
}

/// A single entry in a module's Export Address Table.
#[derive(Clone, Debug)]
pub struct ExportInfo {
    /// Export ordinal (already biased by the directory's ordinal base).
    pub ordinal: u32,
    /// Export name, or `None` for exports available by ordinal only.
    pub name: Option<String>,
    /// Resolved code address within the module.
    pub address: *const u8,
    /// For forwarded exports, the `"OTHERDLL.Function"` forwarder target.
    pub forwarder: Option<String>,
}

/// A single imported function in a module's import table.
#[derive(Clone, Debug)]
pub struct ImportInfo {
    /// Name of the DLL the function is imported from.
    pub dll: String,
    /// Imported function name, or `None` when imported by ordinal.
    pub name: Option<String>,
    /// Import ordinal, or `None` when imported by name.
    pub ordinal: Option<u16>,
    /// Bound address currently stored in the IAT slot.
    pub address: *const u8,
}

/// Enumerates every module currently loaded in the calling process.
///
/// Returns an empty vector if the module snapshot could not be taken.
pub fn enumerate_modules() -> Vec<ModuleInfo> {
    let mut modules = Vec::new();

    // Snapshot the modules of the current process (pid 0 == self). Both the
    // native and 32-bit module lists are requested so a WoW64 process sees all
    // of its modules.
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return modules;
    }

    let mut entry: MODULEENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    if unsafe { Module32FirstW(snapshot, &mut entry) } != 0 {
        loop {
            modules.push(ModuleInfo {
                base: entry.modBaseAddr as HMODULE,
                size: entry.modBaseSize,
                name: wide_to_string(&entry.szModule),
            });

            if unsafe { Module32NextW(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }

    unsafe { CloseHandle(snapshot) };
    modules
}

/// Returns the entry point of a loaded module.
///
/// When `h_module` is null, the entry point of the main executable is returned
/// (matching `DetourGetEntryPoint`). Returns `None` if the module headers are
/// invalid or the module has no entry point (`AddressOfEntryPoint == 0`).
pub fn get_entry_point(h_module: HMODULE) -> Option<*const u8> {
    let h = if h_module.is_null() {
        unsafe { GetModuleHandleW(std::ptr::null()) }
    } else {
        h_module
    };

    if h.is_null() {
        return None;
    }

    let image = pe::parse_module_image(h).ok()?;
    let rva = pe::entry_point_rva(&image)?;
    Some((image.base_address + rva) as *const u8)
}

/// Enumerates the exports (Export Address Table) of a loaded module.
///
/// Returns an empty vector for a module that exports nothing. Returns
/// `Err(PeError)` if the module's PE headers are invalid.
///
/// # Safety
///
/// `h_module` must be the base address of a valid PE image currently mapped in
/// the calling process, and must remain loaded for the duration of the call.
pub unsafe fn enumerate_exports(h_module: HMODULE) -> Result<Vec<ExportInfo>, PeError> {
    let image = pe::parse_module_image(h_module)?;

    let mut exports = Vec::new();

    // No export directory => the module has no exports.
    let Some((exp_rva, exp_size)) = pe::data_directory(&image, IMAGE_DIRECTORY_ENTRY_EXPORT as usize)
    else {
        return Ok(exports);
    };

    let Some(dir_ptr) = pe::rva_to_ptr::<IMAGE_EXPORT_DIRECTORY>(&image, exp_rva) else {
        return Ok(exports);
    };
    let dir = unsafe { *dir_ptr };

    let number_of_functions = dir.NumberOfFunctions as usize;
    let number_of_names = dir.NumberOfNames as usize;
    let ordinal_base = dir.Base;
    let functions_rva = dir.AddressOfFunctions as usize;
    let names_rva = dir.AddressOfNames as usize;
    let name_ordinals_rva = dir.AddressOfNameOrdinals as usize;

    // Build a map from function-table index -> export name by walking the
    // parallel AddressOfNames / AddressOfNameOrdinals arrays.
    let mut names: Vec<Option<String>> = vec![None; number_of_functions];
    for i in 0..number_of_names {
        let Some(name_rva) = read_u32(&image, names_rva, i) else {
            continue;
        };
        let Some(name_ordinal) = read_u16(&image, name_ordinals_rva, i) else {
            continue;
        };
        let idx = name_ordinal as usize;
        if idx < number_of_functions {
            names[idx] = pe::read_c_string_from_rva(&image, name_rva as usize);
        }
    }

    let exp_end = exp_rva.saturating_add(exp_size);

    // `names` has one slot per function-table entry, so iterating it walks every
    // export ordinal while consuming the resolved names.
    for (func_index, name) in names.into_iter().enumerate() {
        let Some(func_rva) = read_u32(&image, functions_rva, func_index) else {
            continue;
        };
        // A zero RVA marks an unused export slot.
        if func_rva == 0 {
            continue;
        }
        let func_rva = func_rva as usize;

        // A function RVA pointing back inside the export directory is a
        // forwarder string ("OTHERDLL.Function") rather than real code.
        let forwarder = if func_rva >= exp_rva && func_rva < exp_end {
            pe::read_c_string_from_rva(&image, func_rva)
        } else {
            None
        };

        exports.push(ExportInfo {
            ordinal: ordinal_base + func_index as u32,
            name,
            address: (image.base_address + func_rva) as *const u8,
            forwarder,
        });
    }

    Ok(exports)
}

/// Enumerates the imports of a loaded module across all of its imported DLLs.
///
/// Returns an empty vector for a module that imports nothing. Returns
/// `Err(PeError)` if the module's PE headers are invalid.
///
/// # Safety
///
/// `h_module` must be the base address of a valid PE image currently mapped in
/// the calling process, and must remain loaded for the duration of the call.
pub unsafe fn enumerate_imports(h_module: HMODULE) -> Result<Vec<ImportInfo>, PeError> {
    let image = pe::parse_module_image(h_module)?;

    let mut imports = Vec::new();

    let Some((import_rva, _import_size)) =
        pe::data_directory(&image, IMAGE_DIRECTORY_ENTRY_IMPORT as usize)
    else {
        return Ok(imports);
    };

    let thunk_size = std::mem::size_of::<usize>();
    let mut desc_rva = import_rva;

    loop {
        let Some(desc_ptr) = pe::rva_to_ptr::<IMAGE_IMPORT_DESCRIPTOR>(&image, desc_rva) else {
            break;
        };
        let desc = unsafe { *desc_ptr };

        // The descriptor array is terminated by an all-zero entry.
        if desc.Name == 0 {
            break;
        }

        let Some(dll) = pe::read_c_string_from_rva(&image, desc.Name as usize) else {
            break;
        };

        // Prefer the Import Name Table (OriginalFirstThunk) for resolving names;
        // fall back to the IAT (FirstThunk) when the INT is absent.
        let original_first_thunk = unsafe { desc.Anonymous.OriginalFirstThunk } as usize;
        let lookup_base = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            desc.FirstThunk as usize
        };
        let iat_base = desc.FirstThunk as usize;

        if lookup_base != 0 {
            let mut offset = 0usize;
            while let Some(lookup) = read_usize(&image, lookup_base + offset) {
                if lookup == 0 {
                    break;
                }

                // The bound address lives in the IAT (FirstThunk) slot.
                let address = read_usize(&image, iat_base + offset).unwrap_or(0) as *const u8;

                let (name, ordinal) = if lookup & IMAGE_ORDINAL_FLAG != 0 {
                    (None, Some((lookup & 0xFFFF) as u16))
                } else {
                    // `lookup` is the RVA of an IMAGE_IMPORT_BY_NAME (WORD hint
                    // followed by the NUL-terminated name).
                    let name = pe::read_c_string_from_rva(&image, lookup + std::mem::size_of::<u16>());
                    (name, None)
                };

                imports.push(ImportInfo {
                    dll: dll.clone(),
                    name,
                    ordinal,
                    address,
                });

                offset += thunk_size;
            }
        }

        desc_rva += std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
    }

    Ok(imports)
}

/// Reads the `index`-th `u32` of an array located at `base_rva`, bounds-checked.
fn read_u32(image: &pe::ModuleImage, base_rva: usize, index: usize) -> Option<u32> {
    let rva = base_rva.checked_add(index.checked_mul(std::mem::size_of::<u32>())?)?;
    let ptr = pe::rva_to_ptr::<u32>(image, rva)?;
    Some(unsafe { *ptr })
}

/// Reads the `index`-th `u16` of an array located at `base_rva`, bounds-checked.
fn read_u16(image: &pe::ModuleImage, base_rva: usize, index: usize) -> Option<u16> {
    let rva = base_rva.checked_add(index.checked_mul(std::mem::size_of::<u16>())?)?;
    let ptr = pe::rva_to_ptr::<u16>(image, rva)?;
    Some(unsafe { *ptr })
}

/// Reads a pointer-sized value at `rva`, bounds-checked.
fn read_usize(image: &pe::ModuleImage, rva: usize) -> Option<usize> {
    let ptr = pe::rva_to_ptr::<usize>(image, rva)?;
    Some(unsafe { *ptr })
}

/// Converts a fixed-size, NUL-padded UTF-16 buffer to a `String`.
fn wide_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module;

    #[test]
    fn enumerate_modules_includes_kernel32() {
        let modules = enumerate_modules();
        assert!(!modules.is_empty(), "expected at least one loaded module");

        let kernel32 = modules
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case("kernel32.dll"))
            .expect("kernel32.dll should be loaded");

        assert!(!kernel32.base.is_null(), "kernel32 base must not be null");
        assert!(kernel32.size > 0, "kernel32 size must be positive");
    }

    #[test]
    fn get_entry_point_is_within_kernel32_image() {
        let h = module::get_module_handle("kernel32.dll").expect("kernel32 handle");
        let entry = get_entry_point(h).expect("kernel32 should have an entry point");

        let base = h as usize;
        let end = base + module::get_module_size(h) as usize;
        let entry = entry as usize;

        assert!(
            entry >= base && entry < end,
            "entry point {entry:#x} outside [{base:#x}, {end:#x})"
        );
    }

    #[test]
    fn get_entry_point_null_returns_main_executable_entry() {
        let entry = get_entry_point(std::ptr::null_mut());
        assert!(
            entry.is_some(),
            "null handle should resolve the main executable entry point"
        );
    }

    #[test]
    fn enumerate_exports_finds_getprocaddress() {
        let h = module::get_module_handle("kernel32.dll").expect("kernel32 handle");
        let exports = unsafe { enumerate_exports(h) }.expect("kernel32 exports");

        assert!(!exports.is_empty(), "kernel32 should export functions");

        let gpa = exports
            .iter()
            .find(|e| e.name.as_deref() == Some("GetProcAddress"))
            .expect("GetProcAddress should be exported");

        assert!(!gpa.address.is_null(), "export address must not be null");
        assert!(gpa.forwarder.is_none(), "GetProcAddress is not a forwarder");
    }

    #[test]
    fn enumerate_imports_of_self_is_non_empty() {
        // The test executable imports from system DLLs.
        let h = unsafe { GetModuleHandleW(std::ptr::null()) };
        assert!(!h.is_null());

        let imports = unsafe { enumerate_imports(h) }.expect("self imports");
        assert!(
            !imports.is_empty(),
            "the test executable should import something"
        );
    }

    #[test]
    fn introspection_rejects_invalid_module() {
        let mut stack_value = 0u32;
        let fake = (&mut stack_value as *mut u32).cast::<core::ffi::c_void>() as HMODULE;

        assert!(unsafe { enumerate_exports(fake) }.is_err());
        assert!(unsafe { enumerate_imports(fake) }.is_err());
        assert!(get_entry_point(fake).is_none());
    }
}
