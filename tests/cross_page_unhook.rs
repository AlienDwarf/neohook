// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(windows)]

//! Unhooking a target whose patched bytes straddle two pages must give each
//! page back its own protection, even if one page changed protection while the
//! hook was installed (as JIT or self-modifying code does).

use neohook::DetourTransaction;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, VirtualAlloc, VirtualFree, VirtualProtect, VirtualQuery,
};

extern "C" fn detour() -> u32 {
    7
}

fn protection(addr: *const u8) -> u32 {
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let len = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
    assert_ne!(unsafe { VirtualQuery(addr as _, &mut mbi, len) }, 0);
    mbi.Protect
}

#[test]
fn unhook_restores_each_page_protection() {
    unsafe {
        let base = VirtualAlloc(
            std::ptr::null(),
            0x2000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        ) as *mut u8;
        assert!(!base.is_null());

        // NOPs across the page boundary, then `xor eax, eax; ret`.
        let target = base.add(0x1000 - 4);
        std::ptr::write_bytes(target, 0x90, 20);
        std::ptr::copy_nonoverlapping([0x31u8, 0xC0, 0xC3].as_ptr(), target.add(20), 3);

        let mut tx = DetourTransaction::begin();
        tx.update_all_threads();
        tx.attach(target, detour as *const u8).expect("attach");
        let hooks = tx.commit().expect("commit");

        // The second page becomes read-execute while the hook is live.
        let second = base.add(0x1000);
        let mut old = 0;
        assert_ne!(
            VirtualProtect(second as _, 0x1000, PAGE_EXECUTE_READ, &mut old),
            0
        );
        drop(hooks);

        assert_eq!(
            protection(base),
            PAGE_EXECUTE_READWRITE,
            "first page after unhook"
        );
        assert_eq!(
            protection(second),
            PAGE_EXECUTE_READ,
            "second page after unhook"
        );

        assert_ne!(VirtualFree(base as _, 0, MEM_RELEASE), 0);
    }
}
