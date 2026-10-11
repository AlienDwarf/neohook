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

const PAGE_SIZE: usize = 0x1000;

/// Most pages one [`PageProtections`] batch tracks. A code patch spans at most
/// two pages; longer writes are processed in batches of this many pages.
const MAX_BATCH_PAGES: usize = 8;

/// Changes the protection of the page containing `page` to `new_protect`,
/// keeping execute permission if that page had it. Returns the page's previous
/// protection.
unsafe fn protect_page_same_execute(page: usize, new_protect: u32) -> Option<u32> {
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    unsafe {
        if VirtualQuery(
            page as _,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        ) == 0
        {
            return None;
        }
        let adjusted = detour_page_protect_adjust_execute(mbi.Protect, new_protect);
        let mut old = 0u32;
        if VirtualProtect(page as _, 1, adjusted, &mut old) == 0 {
            return None;
        }
        Some(old)
    }
}

/// The saved protections of up to [`MAX_BATCH_PAGES`] consecutive pages, kept
/// on the stack so it is usable inside the commit suspend window.
struct PageProtections {
    first_page: usize,
    count: usize,
    old: [u32; MAX_BATCH_PAGES],
}

impl PageProtections {
    /// Changes every page of `[start, start + len)` (`len > 0`, at most
    /// [`MAX_BATCH_PAGES`] pages) to `new_protect`, preserving each page's own
    /// execute permission. On failure the pages already changed are restored.
    unsafe fn change(start: usize, len: usize, new_protect: u32) -> Option<Self> {
        let first_page = start & !(PAGE_SIZE - 1);
        let last_page = (start + len - 1) & !(PAGE_SIZE - 1);
        let pages = (last_page - first_page) / PAGE_SIZE + 1;
        debug_assert!(pages <= MAX_BATCH_PAGES);

        let mut saved = Self {
            first_page,
            count: 0,
            old: [0; MAX_BATCH_PAGES],
        };
        for i in 0..pages.min(MAX_BATCH_PAGES) {
            match unsafe { protect_page_same_execute(first_page + i * PAGE_SIZE, new_protect) } {
                Some(old) => {
                    saved.old[i] = old;
                    saved.count = i + 1;
                }
                None => {
                    unsafe { saved.restore() };
                    return None;
                }
            }
        }
        Some(saved)
    }

    /// Restores every saved page to its own previous protection. Returns
    /// `false` if any page could not be restored.
    unsafe fn restore(&self) -> bool {
        let mut ok = true;
        for (i, &old) in self.old[..self.count].iter().enumerate() {
            let mut tmp = 0u32;
            let page = self.first_page + i * PAGE_SIZE;
            ok &= unsafe { VirtualProtect(page as _, 1, old, &mut tmp) } != 0;
        }
        ok
    }
}

/// Splits `[start, start + len)` into consecutive chunks of at most
/// [`MAX_BATCH_PAGES`] pages and calls `f(chunk_start, chunk_len)` for each,
/// stopping at the first chunk for which `f` returns `false`. The caller must
/// ensure `start + len` does not overflow.
fn for_each_page_batch(start: usize, len: usize, mut f: impl FnMut(usize, usize) -> bool) -> bool {
    let end = start + len;
    let mut chunk = start;
    while chunk < end {
        let batch_end = (chunk & !(PAGE_SIZE - 1))
            .saturating_add(MAX_BATCH_PAGES * PAGE_SIZE)
            .min(end);
        if !f(chunk, batch_end - chunk) {
            return false;
        }
        chunk = batch_end;
    }
    true
}

/// Changes the protection of a region of memory page by page, so that every
/// page whose original protection included execute permission keeps it.
///
/// `old_protect_out` receives the previous protection of the **first** page,
/// as with `VirtualProtect`. A range whose pages had different protections
/// cannot be restored from that single value.
///
/// # Safety
/// The caller must ensure that `address` is a valid pointer
pub unsafe fn virtual_protect_same_execute(
    address: *mut u8,
    size: usize,
    new_protect: u32,
    old_protect_out: *mut u32,
) -> BOOL {
    let start = address as usize;
    if size == 0 || start.checked_add(size).is_none() {
        return 0;
    }

    let mut first_old = None;
    let ok = for_each_page_batch(start, size, |chunk, chunk_len| {
        match unsafe { PageProtections::change(chunk, chunk_len, new_protect) } {
            Some(saved) => {
                first_old.get_or_insert(saved.old[0]);
                true
            }
            None => false,
        }
    });
    if let Some(old) = first_old
        && !old_protect_out.is_null()
    {
        unsafe { *old_protect_out = old };
    }
    ok as BOOL
}

/// Copies `len` bytes from `src` to `target` (first saving the previous bytes
/// to `orig` if it is non-null). Each touched page is made writable with its
/// own execute permission preserved and gets its own protection back
/// afterwards; the instruction cache is flushed. Allocation-free and
/// lock-free, so it is usable inside the commit suspend window.
unsafe fn write_pages(target: *mut u8, src: *const u8, orig: *mut u8, len: usize) -> bool {
    let start = target as usize;
    if start.checked_add(len).is_none() {
        return false;
    }

    for_each_page_batch(start, len, |chunk, chunk_len| unsafe {
        let Some(saved) = PageProtections::change(chunk, chunk_len, PAGE_READWRITE) else {
            return false;
        };
        let offset = chunk - start;
        if !orig.is_null() {
            std::ptr::copy_nonoverlapping(chunk as *const u8, orig.add(offset), chunk_len);
        }
        std::ptr::copy_nonoverlapping(src.add(offset), chunk as *mut u8, chunk_len);

        // Flush instruction cache so CPUs reload from RAM instead of L1/L2/L3
        FlushInstructionCache(GetCurrentProcess(), chunk as _, chunk_len);

        saved.restore();
        true
    })
}

/// Writes `len` bytes from `src` into `target` and returns the bytes that were
/// there before, or `None` on failure. Execute permission is preserved per page
/// while the protection is temporarily lifted, every page gets its own
/// protection back, and the instruction cache is flushed.
///
/// Despite the name, the write is **not synchronized** with other threads: it is
/// a plain `VirtualProtect` + copy + `FlushInstructionCache` and suspends nothing.
/// Only a 1-byte write is observed atomically by a concurrently executing thread;
/// for anything longer another thread may fetch a half-written instruction or be
/// left inside the region at a stale instruction boundary. Callers patching
/// multi-byte code that may be executing must suspend the other threads first.
///
/// # Safety
/// The caller must ensure that `target` and `src` are valid pointers.
pub unsafe fn write_memory_atomic(target: *mut u8, src: *const u8, len: usize) -> Option<Vec<u8>> {
    if target.is_null() || src.is_null() || len == 0 {
        return None;
    }

    let mut orig = vec![0u8; len];
    if unsafe { write_pages(target, src, orig.as_mut_ptr(), len) } {
        Some(orig)
    } else {
        None
    }
}

/// Writes `len` bytes from `src` into `target` without allocating, preserving
/// execute permission per page, restoring each page's own protection and
/// flushing the instruction cache. Returns `true` on success.
///
/// Like [`write_memory_atomic`] this does no thread synchronization of its own,
/// but because it never touches the heap it is safe to call while other threads
/// are suspended (one of them may hold the heap lock).
///
/// # Safety
/// The caller must ensure that `target` and `src` are valid for `len` bytes.
pub(crate) unsafe fn write_code_bytes(target: *mut u8, src: *const u8, len: usize) -> bool {
    if target.is_null() || src.is_null() || len == 0 {
        return false;
    }

    unsafe { write_pages(target, src, std::ptr::null_mut(), len) }
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE, VirtualAlloc, VirtualFree,
        VirtualProtect, VirtualQuery,
    };

    use crate::mem::virtual_protect_same_execute;

    #[test]
    fn changes_protection_and_returns_old_protect() {
        unsafe {
            let size = 4096usize;

            // allocate a page with execute-readwrite permissions
            let ptr = VirtualAlloc(
                std::ptr::null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            ) as *mut u8;

            // Ensure the allocation succeeded
            assert!(!ptr.is_null());

            let mut old_protect = 0u32;

            // Change the protection to readwrite, but since the original page had execute permissions,
            // we expect it to keep them.
            let ok = virtual_protect_same_execute(
                ptr,
                size,
                PAGE_READWRITE,
                &mut old_protect as *mut u32,
            );

            // Ensure the protection change succeeded and that the old protection is what we set initially.
            assert_ne!(ok, 0);
            assert_eq!(old_protect, PAGE_EXECUTE_READWRITE);

            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let q = VirtualQuery(
                ptr as _,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            assert_ne!(q, 0);

            // The new protection should still include execute permissions.
            assert_eq!(mbi.Protect, PAGE_EXECUTE_READWRITE);

            let freed = VirtualFree(ptr as _, 0, MEM_RELEASE);
            assert_ne!(freed, 0);
        }
    }

    #[test]
    fn virtual_protect_same_execute_preserves_execute_permission() {
        unsafe {
            let page = VirtualAlloc(
                ptr::null(),
                4096,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READ,
            );
            assert!(!page.is_null(), "setup allocation failed");

            let mut old_protect = 0u32;
            let ok = crate::mem::virtual_protect_same_execute(
                page as *mut u8,
                4096,
                PAGE_READWRITE,
                &mut old_protect,
            );
            assert_ne!(ok, 0, "virtual_protect_same_execute failed");

            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let q = VirtualQuery(
                page,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            assert_ne!(q, 0, "VirtualQuery failed");

            let free_ok = VirtualFree(page, 0, MEM_RELEASE);
            assert_ne!(free_ok, 0, "VirtualFree failed");

            assert_eq!(
                mbi.Protect, PAGE_EXECUTE_READWRITE,
                "execute permission should have been preserved"
            );
        }
    }

    /// Reserves two adjacent pages with `first` / `second` protection and
    /// returns their base.
    unsafe fn two_pages(first: u32, second: u32) -> *mut u8 {
        unsafe {
            let base = VirtualAlloc(
                ptr::null(),
                0x2000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ) as *mut u8;
            assert!(!base.is_null(), "setup allocation failed");
            let mut old = 0u32;
            assert_ne!(VirtualProtect(base as _, 0x1000, first, &mut old), 0);
            assert_ne!(
                VirtualProtect(base.add(0x1000) as _, 0x1000, second, &mut old),
                0
            );
            base
        }
    }

    unsafe fn protect_of(addr: *const u8) -> u32 {
        unsafe {
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let q = VirtualQuery(
                addr as _,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            assert_ne!(q, 0, "VirtualQuery failed");
            mbi.Protect
        }
    }

    /// A write straddling a page boundary must restore each page's own
    /// protection, not stamp the first page's protection over both.
    #[test]
    fn page_straddling_writes_restore_each_page_protection() {
        let layouts = [
            (PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ),
            (PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE),
            (PAGE_READONLY, PAGE_EXECUTE_READ),
        ];
        let bytes = [0xC3u8, 0xCC, 0x90, 0x90];
        for (first, second) in layouts {
            for atomic in [false, true] {
                unsafe {
                    let base = two_pages(first, second);
                    let at = base.add(0xFFE);
                    if atomic {
                        let orig = crate::mem::write_memory_atomic(at, bytes.as_ptr(), 4)
                            .expect("write_memory_atomic failed");
                        assert_eq!(orig, [0, 0, 0, 0]);
                    } else {
                        assert!(crate::mem::write_code_bytes(at, bytes.as_ptr(), 4));
                    }
                    assert_eq!(std::slice::from_raw_parts(at, 4), bytes);
                    let (p1, p2) = (protect_of(base), protect_of(base.add(0x1000)));
                    assert_ne!(VirtualFree(base as _, 0, MEM_RELEASE), 0);
                    assert_eq!(
                        (p1, p2),
                        (first, second),
                        "page protections must be restored per page (atomic={atomic})"
                    );
                }
            }
        }
    }

    /// Execute permission must be preserved per page when a range covering a
    /// non-executable page and an executable one is made writable.
    #[test]
    fn virtual_protect_same_execute_preserves_execute_per_page() {
        unsafe {
            let base = two_pages(PAGE_READWRITE, PAGE_EXECUTE_READ);
            let mut old = 0u32;
            let ok = virtual_protect_same_execute(base.add(0xFFE), 4, PAGE_READWRITE, &mut old);
            let (p1, p2) = (protect_of(base), protect_of(base.add(0x1000)));
            assert_ne!(VirtualFree(base as _, 0, MEM_RELEASE), 0);
            assert_ne!(ok, 0);
            assert_eq!(old, PAGE_READWRITE, "old protection is the first page's");
            assert_eq!(p1, PAGE_READWRITE);
            assert_eq!(
                p2, PAGE_EXECUTE_READWRITE,
                "the executable second page must stay executable"
            );
        }
    }
}
