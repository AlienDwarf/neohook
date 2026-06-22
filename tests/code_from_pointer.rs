#![cfg(windows)]

use neohook::{DetourTransaction, detour_code_from_pointer};
use std::error::Error;
use std::hint::black_box;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc, VirtualFree,
};

type DemoFn = extern "C" fn(i32) -> i32;

#[inline(never)]
extern "C" fn real_target(value: i32) -> i32 {
    black_box(value) + black_box(7)
}

#[inline(never)]
extern "C" fn detour_target(value: i32) -> i32 {
    black_box(value) + black_box(100)
}

struct ExecutablePage(*mut u8);

impl ExecutablePage {
    fn new() -> Result<Self, Box<dyn Error>> {
        let page = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                4096,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            ) as *mut u8
        };

        if page.is_null() {
            Err("VirtualAlloc failed".into())
        } else {
            Ok(Self(page))
        }
    }

    fn ptr(&self) -> *mut u8 {
        self.0
    }
}

impl Drop for ExecutablePage {
    fn drop(&mut self) {
        unsafe {
            let _ = VirtualFree(self.0.cast(), 0, MEM_RELEASE);
        }
    }
}

fn write_import_thunk_stub(stub: *mut u8, target: *const u8) {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            *stub.add(0) = 0xFF;
            *stub.add(1) = 0x25;
            std::ptr::write_unaligned(stub.add(2) as *mut i32, 0);
            std::ptr::write_unaligned(stub.add(6) as *mut usize, target as usize);
        }

        #[cfg(target_arch = "x86")]
        {
            let slot = stub.add(16) as *mut usize;
            *stub.add(0) = 0xFF;
            *stub.add(1) = 0x25;
            std::ptr::write_unaligned(stub.add(2) as *mut u32, slot as u32);
            std::ptr::write_unaligned(slot, target as usize);
        }
    }
}

#[test]
fn public_code_from_pointer_resolves_import_thunk() -> Result<(), Box<dyn Error>> {
    let page = ExecutablePage::new()?;
    write_import_thunk_stub(page.ptr(), real_target as *const u8);

    let resolved = unsafe { detour_code_from_pointer(page.ptr()) };

    assert_eq!(resolved, real_target as *mut u8);
    Ok(())
}

#[test]
fn transaction_attach_hooks_real_code_when_target_is_import_thunk() -> Result<(), Box<dyn Error>> {
    let page = ExecutablePage::new()?;
    write_import_thunk_stub(page.ptr(), real_target as *const u8);

    let thunk: DemoFn = unsafe { std::mem::transmute(page.ptr()) };
    assert_eq!(thunk(5), 12);

    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();

    let trampoline = tx.attach(page.ptr(), detour_target as *const u8)?;
    let mut hooks = tx.commit()?;

    assert_eq!(thunk(5), 105);

    let original: DemoFn = unsafe { std::mem::transmute(trampoline) };
    assert_eq!(original(5), 12);

    hooks.remove(0).unhook()?;
    assert_eq!(thunk(5), 12);

    Ok(())
}
