// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::core::BOOL;

/// Adjusts the new protection flags to include execute permissions
/// if the old protection had execute permissions.
fn detour_page_protect_adjust_execute(old_protect: u32, new_protect: u32) -> u32 {
    const EXECUTE_FLAGS: u32 =
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

    if (old_protect & EXECUTE_FLAGS) != 0 {
        match new_protect {
            PAGE_READONLY => PAGE_EXECUTE_READ,
            PAGE_READWRITE => PAGE_EXECUTE_READWRITE,
            PAGE_WRITECOPY => PAGE_EXECUTE_WRITECOPY,
            _ => new_protect,
        }
    } else {
        new_protect
    }
}

/// Changes the protection of a region of memory,
/// ensuring that if the original protection included execute permissions,
/// the new protection will also include execute permissions.
///
/// # Safety
/// The caller must ensure that `address` is a valid pointer
pub unsafe fn virtual_protect_same_execute(
    address: *mut u8,
    size: usize,
    new_protect: u32,
    old_protect_out: *mut u32,
) -> BOOL {
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };

    unsafe {
        if VirtualQuery(
            address as _,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        ) == 0
        {
            return 0;
        }

        let adjusted_protect = detour_page_protect_adjust_execute(mbi.Protect, new_protect);
        VirtualProtect(address as _, size, adjusted_protect, old_protect_out)
    }
}

/// Atomically (as much as possible) write `len` bytes from `src` into `target`.
/// Returns true on success. This helper preserves execute flags when changing protections.
///
/// # Safety
/// The caller must ensure that `target` and `src` are valid pointers
pub unsafe fn write_memory_atomic(target: *mut u8, src: *const u8, len: usize) -> Option<Vec<u8>> {
    if target.is_null() || src.is_null() || len == 0 {
        return None;
    }

    let mut old_protect: u32 = 0;
    unsafe {
        // FIRST, change the protection to allow writing (while preserving execute permissions if they were present)
        if virtual_protect_same_execute(target, len, PAGE_READWRITE, &mut old_protect) == 0 {
            return None;
        }

        // NOW we can safely read
        let mut orig = vec![0u8; len];
        std::ptr::copy_nonoverlapping(target as *const u8, orig.as_mut_ptr(), len);

        // Perform the write
        std::ptr::copy_nonoverlapping(src, target, len);

        // Flush instruction cache so CPUs reload from RAM instead of L1/L2/L3
        FlushInstructionCache(GetCurrentProcess(), target as _, len);

        // Restore original protection
        let mut tmp = 0u32;
        VirtualProtect(target as _, len, old_protect, &mut tmp);

        Some(orig)
    }
}
