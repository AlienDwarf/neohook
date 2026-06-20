// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared, bounds-checked PE parsing primitives for loaded modules.
//!
//! These helpers operate on a module that is already mapped into the current
//! process at its `HMODULE` base address. They validate the DOS/NT/Optional
//! headers and translate Relative Virtual Addresses (RVAs) into pointers while
//! keeping every access inside the reported `SizeOfImage`, so malformed or
//! malicious images cannot drive an out-of-bounds read.
//!
//! Both [`crate::iat`] (import hooking) and [`crate::introspect`] (module/PE
//! introspection) build on top of this module.

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::SystemServices::*;

// --- Architecture-specific imports ---
#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32 as IMAGE_NT_HEADERS;
#[cfg(target_arch = "x86")]
const IMAGE_OPTIONAL_MAGIC: u16 = IMAGE_NT_OPTIONAL_HDR32_MAGIC;

#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;
#[cfg(target_arch = "x86_64")]
const IMAGE_OPTIONAL_MAGIC: u16 = IMAGE_NT_OPTIONAL_HDR64_MAGIC;

/// Errors produced while validating and parsing a loaded PE image.
#[derive(Debug)]
pub enum PeError {
    /// The module handle / base address was null.
    NullModule,
    /// The DOS header signature (`MZ`) was missing.
    InvalidDosHeader,
    /// The `e_lfanew` offset to the NT headers was invalid.
    InvalidNtHeader,
    /// The NT signature (`PE\0\0`) was missing.
    InvalidNtSignature,
    /// The Optional Header magic did not match the current architecture, or
    /// `SizeOfImage` was zero.
    InvalidOptionalHeader,
}

/// A validated view over a module mapped into the current process.
#[derive(Copy, Clone, Debug)]
pub struct ModuleImage {
    /// Base address the module is loaded at (`HMODULE`).
    pub base_address: usize,
    /// `SizeOfImage` from the Optional Header.
    pub size: usize,
}

/// Validates the headers of a loaded module and returns a [`ModuleImage`].
///
/// Performs the same DOS/NT/Optional-header checks used throughout NeoHook so
/// later RVA translations can rely on a known-good `SizeOfImage`.
pub fn parse_module_image(h_module: HMODULE) -> Result<ModuleImage, PeError> {
    if h_module.is_null() {
        return Err(PeError::NullModule);
    }

    let base_address = h_module as usize;
    let dos = base_address as *const IMAGE_DOS_HEADER;

    // DOS signature should be "MZ" (0x5A4D) when valid.
    if unsafe { (*dos).e_magic } != IMAGE_DOS_SIGNATURE {
        return Err(PeError::InvalidDosHeader);
    }

    // Locate the NT headers via the e_lfanew offset from the DOS header.
    let e_lfanew = unsafe { (*dos).e_lfanew };
    if e_lfanew <= 0 {
        return Err(PeError::InvalidNtHeader);
    }

    let nt_addr = base_address
        .checked_add(e_lfanew as usize)
        .ok_or(PeError::InvalidNtHeader)?;
    let nt = nt_addr as *const IMAGE_NT_HEADERS;

    // NT signature should be "PE\0\0" (0x4550) when valid.
    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#signature-image-only
    if unsafe { (*nt).Signature } != IMAGE_NT_SIGNATURE {
        return Err(PeError::InvalidNtSignature);
    }

    // Optional Header magic distinguishes PE32 vs PE32+.
    if unsafe { (*nt).OptionalHeader.Magic } != IMAGE_OPTIONAL_MAGIC {
        return Err(PeError::InvalidOptionalHeader);
    }

    let size_of_image = unsafe { (*nt).OptionalHeader.SizeOfImage as usize };
    if size_of_image == 0 {
        return Err(PeError::InvalidOptionalHeader);
    }

    Ok(ModuleImage {
        base_address,
        size: size_of_image,
    })
}

/// Returns the RVA of the module entry point (`AddressOfEntryPoint`), or `None`
/// if it is zero (e.g. resource-only DLLs).
pub fn entry_point_rva(image: &ModuleImage) -> Option<usize> {
    // Re-derive the NT headers; the image was already validated by
    // `parse_module_image`, so these reads are in-bounds.
    let dos = image.base_address as *const IMAGE_DOS_HEADER;
    let e_lfanew = unsafe { (*dos).e_lfanew } as usize;
    let nt = (image.base_address + e_lfanew) as *const IMAGE_NT_HEADERS;

    let rva = unsafe { (*nt).OptionalHeader.AddressOfEntryPoint } as usize;
    if rva == 0 { None } else { Some(rva) }
}

/// Returns the `(rva, size)` of the requested Data Directory entry, validated to
/// lie within the image.
///
/// `entry_index` is one of the `IMAGE_DIRECTORY_ENTRY_*` constants. Returns
/// `None` when the directory is absent, empty, or malformed.
pub fn data_directory(image: &ModuleImage, entry_index: usize) -> Option<(usize, usize)> {
    let dos = image.base_address as *const IMAGE_DOS_HEADER;
    let e_lfanew = unsafe { (*dos).e_lfanew } as usize;
    let nt = (image.base_address + e_lfanew) as *const IMAGE_NT_HEADERS;

    let number_of_dirs = unsafe { (*nt).OptionalHeader.NumberOfRvaAndSizes as usize };
    if number_of_dirs <= entry_index {
        return None;
    }

    let dir = unsafe { (*nt).OptionalHeader.DataDirectory[entry_index] };
    if dir.VirtualAddress == 0 || dir.Size == 0 {
        return None;
    }

    let rva = dir.VirtualAddress as usize;
    let size = dir.Size as usize;

    // The directory must fit entirely within the image.
    let end = rva.checked_add(size)?;
    if end > image.size {
        return None;
    }

    Some((rva, size))
}

/// Translates an RVA into a `*const T`, ensuring the whole `T` lies inside the
/// image bounds.
pub fn rva_to_ptr<T>(image: &ModuleImage, rva: usize) -> Option<*const T> {
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

/// Translates an RVA into a `*mut T`, ensuring the whole `T` lies inside the
/// image bounds.
pub fn rva_to_mut_ptr<T>(image: &ModuleImage, rva: usize) -> Option<*mut T> {
    rva_to_ptr::<T>(image, rva).map(|p| p as *mut T)
}

/// Reads a NUL-terminated ASCII/UTF-8 string located at `rva`, bounded by the
/// end of the image.
pub fn read_c_string_from_rva(image: &ModuleImage, rva: usize) -> Option<String> {
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
            return String::from_utf8(bytes.to_vec()).ok();
        }
        cur = cur.checked_add(1)?;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DOS header immediately followed by the NT headers, laid out the same
    /// way a real loaded module is. Driving `parse_module_image` against a
    /// pointer to one of these lets each validation branch be hit deliberately
    /// by corrupting a single field of an otherwise-valid image.
    #[repr(C)]
    struct FakeImage {
        dos: IMAGE_DOS_HEADER,
        nt: IMAGE_NT_HEADERS,
    }

    /// Builds a synthetic image whose headers pass every check, so each test
    /// can corrupt exactly one field and assert the resulting `PeError`.
    fn valid_image() -> Box<FakeImage> {
        // SAFETY: `IMAGE_DOS_HEADER` / `IMAGE_NT_HEADERS` are plain C POD
        // structs, so an all-zero instance is a sound starting point that we
        // then populate with the few fields the parser inspects.
        let mut img: Box<FakeImage> = Box::new(unsafe { std::mem::zeroed() });
        img.dos.e_magic = IMAGE_DOS_SIGNATURE;
        img.dos.e_lfanew = std::mem::offset_of!(FakeImage, nt) as i32;
        img.nt.Signature = IMAGE_NT_SIGNATURE;
        img.nt.OptionalHeader.Magic = IMAGE_OPTIONAL_MAGIC;
        img.nt.OptionalHeader.SizeOfImage = std::mem::size_of::<FakeImage>() as u32;
        img
    }

    fn parse(img: &FakeImage) -> Result<ModuleImage, PeError> {
        parse_module_image(img as *const FakeImage as HMODULE)
    }

    #[test]
    fn valid_headers_parse() {
        let img = valid_image();
        let parsed = parse(&img).expect("a well-formed image must parse");
        assert_eq!(parsed.base_address, &*img as *const FakeImage as usize);
        assert_eq!(parsed.size, std::mem::size_of::<FakeImage>());
    }

    #[test]
    fn null_module_is_rejected() {
        assert!(matches!(
            parse_module_image(std::ptr::null_mut()),
            Err(PeError::NullModule)
        ));
    }

    #[test]
    fn missing_dos_signature_is_rejected() {
        let mut img = valid_image();
        img.dos.e_magic = 0; // not "MZ"
        assert!(matches!(parse(&img), Err(PeError::InvalidDosHeader)));
    }

    #[test]
    fn non_positive_e_lfanew_is_rejected() {
        // Zero and negative offsets to the NT headers are both invalid.
        for bad in [0, -1] {
            let mut img = valid_image();
            img.dos.e_lfanew = bad;
            assert!(matches!(parse(&img), Err(PeError::InvalidNtHeader)));
        }
    }

    #[test]
    fn missing_nt_signature_is_rejected() {
        let mut img = valid_image();
        img.nt.Signature = 0; // not "PE\0\0"
        assert!(matches!(parse(&img), Err(PeError::InvalidNtSignature)));
    }

    #[test]
    fn wrong_optional_header_magic_is_rejected() {
        let mut img = valid_image();
        // Flip to the magic of the *other* architecture so it never matches.
        img.nt.OptionalHeader.Magic = !IMAGE_OPTIONAL_MAGIC;
        assert!(matches!(parse(&img), Err(PeError::InvalidOptionalHeader)));
    }

    #[test]
    fn zero_size_of_image_is_rejected() {
        let mut img = valid_image();
        img.nt.OptionalHeader.SizeOfImage = 0;
        assert!(matches!(parse(&img), Err(PeError::InvalidOptionalHeader)));
    }
}
