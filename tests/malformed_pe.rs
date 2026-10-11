#![cfg(windows)]

//! Malformed PE headers must be rejected without reading outside the image.
//!
//! Each case builds a fake image in a private allocation. Cases that crashed
//! before being fixed run in a child process so a crash is reported as a
//! failure instead of taking down the test run.

use neohook::{DetourError, DetourTransaction, IatHookError, get_module_size};
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
