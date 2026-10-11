#![cfg(windows)]

//! Malformed PE headers must be rejected without reading outside the image.
//!
//! Each case builds a fake image in a private allocation. Cases that crashed
//! before being fixed run in a child process so a crash is reported as a
//! failure instead of taking down the test run.

use neohook::{DetourError, DetourTransaction, IatHookError, enumerate_exports, get_module_size};
use std::process::{Command, Stdio};
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::SystemServices::*;

#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32 as IMAGE_NT_HEADERS;
#[cfg(target_arch = "x86")]
const IMAGE_OPTIONAL_MAGIC: u16 = IMAGE_NT_OPTIONAL_HDR32_MAGIC;

#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;
#[cfg(target_arch = "x86_64")]
const IMAGE_OPTIONAL_MAGIC: u16 = IMAGE_NT_OPTIONAL_HDR64_MAGIC;

const CHILD_ENV: &str = "NEOHOOK_MALFORMED_PE_CHILD";
const IMAGE_SIZE: usize = 0x2000;
const NT_OFFSET: usize = 0x80;

unsafe extern "system" fn detour() {}

/// Runs `body` in a child copy of the test named `test`.
fn in_child(test: &str, body: fn()) {
    if std::env::var(CHILD_ENV).as_deref() == Ok(test) {
        body();
        return;
    }

    let exe = std::env::current_exe().expect("current_exe");
    let status = Command::new(exe)
        .args([test, "--exact", "--test-threads=1"])
        .env(CHILD_ENV, test)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn child test process");
    assert!(status.success(), "child failed: {status}");
}

/// A committed, read/write allocation laid out as a valid PE image. Everything
/// past `IMAGE_SIZE` in the allocation granule is reserved but not committed.
struct FakeImage {
    base: *mut u8,
}

impl FakeImage {
    fn new() -> Self {
        let base = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                IMAGE_SIZE,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        } as *mut u8;
        assert!(!base.is_null(), "VirtualAlloc");

        let image = Self { base };
        unsafe {
            let dos = image.dos();
            (*dos).e_magic = IMAGE_DOS_SIGNATURE;
            (*dos).e_lfanew = NT_OFFSET as i32;

            let nt = image.nt();
            (*nt).Signature = IMAGE_NT_SIGNATURE;
            (*nt).OptionalHeader.Magic = IMAGE_OPTIONAL_MAGIC;
            (*nt).OptionalHeader.SizeOfImage = IMAGE_SIZE as u32;
            (*nt).OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        }
        image
    }

    fn handle(&self) -> HMODULE {
        self.base.cast()
    }

    fn dos(&self) -> *mut IMAGE_DOS_HEADER {
        self.base.cast()
    }

    fn nt(&self) -> *mut IMAGE_NT_HEADERS {
        unsafe { self.base.add(NT_OFFSET) }.cast()
    }

    fn set_directory(&self, index: u16, rva: usize, size: usize) {
        let dir = &mut unsafe { &mut *self.nt() }.OptionalHeader.DataDirectory[index as usize];
        dir.VirtualAddress = rva as u32;
        dir.Size = size as u32;
    }

    fn write<T>(&self, rva: usize, value: T) {
        assert!(rva + std::mem::size_of::<T>() <= IMAGE_SIZE);
        unsafe { self.base.add(rva).cast::<T>().write_unaligned(value) };
    }
}

impl Drop for FakeImage {
    fn drop(&mut self) {
        unsafe { VirtualFree(self.base.cast(), 0, MEM_RELEASE) };
    }
}

fn attach_iat(image: &FakeImage, dll: &str, func: &str) -> Result<(), DetourError> {
    let mut tx = DetourTransaction::begin();
    let result = tx.attach_iat(image.handle(), dll, func, detour as *const u8);
    tx.abort();
    result
}

fn is_invalid_pe(result: Result<(), DetourError>) -> bool {
    matches!(result, Err(DetourError::Iat(IatHookError::InvalidPeImage)))
}

#[test]
fn attach_iat_rejects_out_of_range_e_lfanew() {
    in_child("attach_iat_rejects_out_of_range_e_lfanew", || {
        let image = FakeImage::new();
        unsafe { (*image.dos()).e_lfanew = 0x7FFF_FFF0 };
        assert!(is_invalid_pe(attach_iat(&image, "kernel32.dll", "Sleep")));

        // NT headers that start inside the image but run past its committed end.
        let image = FakeImage::new();
        let e_lfanew = IMAGE_SIZE - 4;
        unsafe { (*image.dos()).e_lfanew = e_lfanew as i32 };
        image.write(e_lfanew, IMAGE_NT_SIGNATURE);
        assert!(is_invalid_pe(attach_iat(&image, "kernel32.dll", "Sleep")));
    });
}

#[test]
fn get_module_size_rejects_malformed_headers() {
    in_child("get_module_size_rejects_malformed_headers", || {
        let image = FakeImage::new();
        assert_eq!(get_module_size(image.handle()), IMAGE_SIZE as u32);

        for e_lfanew in [0x7FFF_FFF0, -0x1000, (IMAGE_SIZE - 4) as i32] {
            let image = FakeImage::new();
            unsafe { (*image.dos()).e_lfanew = e_lfanew };
            image.write(IMAGE_SIZE - 4, IMAGE_NT_SIGNATURE);
            assert_eq!(get_module_size(image.handle()), 0, "e_lfanew {e_lfanew:#x}");
        }

        let image = FakeImage::new();
        unsafe { (*image.nt()).Signature = 0 };
        assert_eq!(get_module_size(image.handle()), 0, "missing PE signature");

        let image = FakeImage::new();
        unsafe { (*image.nt()).OptionalHeader.Magic = !IMAGE_OPTIONAL_MAGIC };
        assert_eq!(get_module_size(image.handle()), 0, "wrong optional magic");
    });
}

const EXPORT_DIR: usize = 0x400;
const EXPORT_FUNCTIONS: usize = 0x500;

/// Adds an export directory with two exported functions and no names.
fn with_exports(image: &FakeImage, base: u32, number_of_functions: u32) {
    image.set_directory(IMAGE_DIRECTORY_ENTRY_EXPORT, EXPORT_DIR, 0x28);
    image.write(EXPORT_DIR + 16, base);
    image.write(EXPORT_DIR + 20, number_of_functions);
    image.write(EXPORT_DIR + 28, EXPORT_FUNCTIONS as u32);
    image.write(EXPORT_FUNCTIONS, 0x600u32);
    image.write(EXPORT_FUNCTIONS + 4, 0x610u32);
}

#[test]
fn enumerate_exports_rejects_oversized_function_table() {
    in_child("enumerate_exports_rejects_oversized_function_table", || {
        let image = FakeImage::new();
        with_exports(&image, 1, u32::MAX);
        let exports = unsafe { enumerate_exports(image.handle()) }.expect("valid headers");
        assert!(exports.is_empty(), "table runs past the image");
    });
}

#[test]
fn enumerate_exports_skips_overflowing_ordinals() {
    in_child("enumerate_exports_skips_overflowing_ordinals", || {
        let image = FakeImage::new();
        with_exports(&image, u32::MAX, 2);
        let exports = unsafe { enumerate_exports(image.handle()) }.expect("valid headers");
        let ordinals: Vec<u32> = exports.iter().map(|e| e.ordinal).collect();
        assert_eq!(ordinals, [u32::MAX]);
    });
}

const IMPORT_DIR: usize = 0x800;
const DESCRIPTOR_SIZE: usize = 20;

/// Adds an import table for `a.dll!Alpha` and `b.dll!Target`, terminated by a
/// zero descriptor, whose directory entry reports `size` bytes.
fn with_imports(image: &FakeImage, size: usize) {
    image.set_directory(IMAGE_DIRECTORY_ENTRY_IMPORT, IMPORT_DIR, size);

    for (i, (dll, func)) in [("a.dll", "Alpha"), ("b.dll", "Target")].iter().enumerate() {
        let desc = IMPORT_DIR + i * DESCRIPTOR_SIZE;
        let dll_rva = 0x900 + i * 0x40;
        let by_name_rva = dll_rva + 0x10;
        let int_rva = 0xA00 + i * 0x20;
        let iat_rva = 0xB00 + i * 0x20;

        image.write(desc, int_rva as u32); // OriginalFirstThunk
        image.write(desc + 12, dll_rva as u32); // Name
        image.write(desc + 16, iat_rva as u32); // FirstThunk

        for (j, b) in dll.bytes().enumerate() {
            image.write(dll_rva + j, b);
        }
        // IMAGE_IMPORT_BY_NAME: a zero hint followed by the name.
        for (j, b) in func.bytes().enumerate() {
            image.write(by_name_rva + 2 + j, b);
        }

        image.write(int_rva, by_name_rva);
        image.write(iat_rva, 1usize);
    }
}

#[test]
fn attach_iat_walks_imports_past_an_understated_directory_size() {
    for size in [DESCRIPTOR_SIZE, 0] {
        let image = FakeImage::new();
        with_imports(&image, size);
        let result = attach_iat(&image, "b.dll", "Target");
        assert!(result.is_ok(), "size {size}: {result:?}");
    }
}
