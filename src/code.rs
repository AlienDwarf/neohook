// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualQuery,
};

const MAX_JUMP_FOLLOWS: usize = 32;

/// Resolves a function pointer to the first real code address by following
/// common jump stubs and import thunks at the start of the function.
///
/// This mirrors the behavior needed for MSVC incremental-link thunks and PE
/// import/forwarder entry stubs, where the exported or referenced entry point
/// is only a `jmp` to the actual implementation.
///
/// Returns null when `pointer` is null. If no recognized jump stub is present,
/// the original pointer is returned.
///
/// # Safety
///
/// `pointer` and any recognized thunk target slots must refer to readable
/// process memory. Invalid pointers can still cause undefined behavior on
/// platforms where the OS allows the query but a later read faults.
pub unsafe fn detour_code_from_pointer(pointer: *const u8) -> *mut u8 {
    if pointer.is_null() {
        return std::ptr::null_mut();
    }

    let mut current = pointer;
    let mut seen = [0usize; MAX_JUMP_FOLLOWS];
    for seen_len in 0..MAX_JUMP_FOLLOWS {
        let addr = current as usize;
        if seen[..seen_len].contains(&addr) {
            break;
        }
        seen[seen_len] = addr;

        let Some(next) = (unsafe { detour_code_from_pointer_once(current) }) else {
            break;
        };

        if next.is_null() {
            break;
        }

        current = next;
    }

    current as *mut u8
}

unsafe fn detour_code_from_pointer_once(src: *const u8) -> Option<*const u8> {
    let op0 = unsafe { read_value::<u8>(src)? };

    match op0 {
        // jmp rel32
        0xE9 => {
            let rel = unsafe { read_value::<i32>(src.add(1))? } as isize;
            Some(unsafe { src.offset(5 + rel) })
        }
        // jmp rel8
        0xEB => {
            let rel = unsafe { read_value::<i8>(src.add(1))? } as isize;
            Some(unsafe { src.offset(2 + rel) })
        }
        // jmp r/m
        0xFF => unsafe { resolve_ff_jump(src, 0) },
        #[cfg(target_arch = "x86_64")]
        0x48 => {
            let op1 = unsafe { read_value::<u8>(src.add(1))? };
            let op2 = unsafe { read_value::<u8>(src.add(2))? };

            match (op1, op2) {
                // rex.w jmp qword ptr [rip+disp32]
                (0xFF, 0x25) => unsafe { resolve_rip_indirect_jump(src, 3) },
                // mov rax, imm64; jmp rax
                (0xB8, _) if unsafe { read_value::<u16>(src.add(10))? } == 0xE0FF => {
                    let target = unsafe { read_value::<u64>(src.add(2))? };
                    Some(target as *const u8)
                }
                _ => None,
            }
        }
        #[cfg(target_arch = "x86_64")]
        0x49 => {
            let op1 = unsafe { read_value::<u8>(src.add(1))? };
            // mov r10, imm64; jmp r10
            if op1 == 0xBA && unsafe { read_value::<u16>(src.add(10))? } == 0xE2FF {
                let target = unsafe { read_value::<u64>(src.add(2))? };
                Some(target as *const u8)
            } else {
                None
            }
        }
        #[cfg(target_arch = "x86")]
        0xB8 => {
            // mov eax, imm32; jmp eax
            if unsafe { read_value::<u16>(src.add(5))? } == 0xE0FF {
                let target = unsafe { read_value::<u32>(src.add(1))? };
                Some(target as *const u8)
            } else {
                None
            }
        }
        #[cfg(target_arch = "x86")]
        0x68 => {
            // push imm32; ret
            if unsafe { read_value::<u8>(src.add(5))? } == 0xC3 {
                let target = unsafe { read_value::<u32>(src.add(1))? };
                Some(target as *const u8)
            } else {
                None
            }
        }
        _ => None,
    }
}

unsafe fn resolve_ff_jump(src: *const u8, modrm_offset: usize) -> Option<*const u8> {
    let modrm = unsafe { read_value::<u8>(src.add(1 + modrm_offset))? };
    if (modrm & 0b0011_1000) != 0b0010_0000 {
        return None;
    }

    match modrm {
        #[cfg(target_arch = "x86_64")]
        0x25 => unsafe { resolve_rip_indirect_jump(src, 2 + modrm_offset) },
        #[cfg(target_arch = "x86")]
        0x25 => {
            let slot = unsafe { read_value::<u32>(src.add(2 + modrm_offset))? } as *const u8;
            let target = unsafe { read_value::<usize>(slot)? };
            Some(target as *const u8)
        }
        _ => None,
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn resolve_rip_indirect_jump(src: *const u8, disp_offset: usize) -> Option<*const u8> {
    let disp = unsafe { read_value::<i32>(src.add(disp_offset))? } as isize;
    let next_instruction = unsafe { src.add(disp_offset + 4) };
    let slot = unsafe { next_instruction.offset(disp) };
    let target = unsafe { read_value::<usize>(slot)? };
    Some(target as *const u8)
}

unsafe fn read_value<T: Copy>(ptr: *const u8) -> Option<T> {
    if !is_readable_range(ptr, std::mem::size_of::<T>()) {
        return None;
    }

    let mut value = std::mem::MaybeUninit::<T>::uninit();
    unsafe {
        std::ptr::copy_nonoverlapping(
            ptr,
            value.as_mut_ptr().cast::<u8>(),
            std::mem::size_of::<T>(),
        );
        Some(value.assume_init())
    }
}

fn is_readable_range(ptr: *const u8, len: usize) -> bool {
    if ptr.is_null() || len == 0 {
        return false;
    }

    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let queried = unsafe {
        VirtualQuery(
            ptr.cast(),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };

    if queried == 0 || mbi.State != MEM_COMMIT {
        return false;
    }

    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0 {
        return false;
    }

    let start = ptr as usize;
    let region_start = mbi.BaseAddress as usize;
    let Some(region_end) = region_start.checked_add(mbi.RegionSize) else {
        return false;
    };
    let Some(end) = start.checked_add(len) else {
        return false;
    };

    start >= region_start && end <= region_end
}

#[cfg(test)]
mod tests {
    use super::detour_code_from_pointer;
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc, VirtualFree,
    };

    unsafe fn alloc_page() -> *mut u8 {
        unsafe {
            VirtualAlloc(
                std::ptr::null(),
                4096,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            ) as *mut u8
        }
    }

    #[test]
    fn code_from_pointer_returns_null_for_null() {
        let resolved = unsafe { detour_code_from_pointer(std::ptr::null()) };
        assert!(resolved.is_null());
    }

    #[test]
    fn code_from_pointer_follows_relative_jump() {
        unsafe {
            let page = alloc_page();
            assert!(!page.is_null());

            let stub = page;
            let target = page.add(64);
            let rel = (target as isize)
                .wrapping_sub(stub as isize)
                .wrapping_sub(5) as i32;

            *stub = 0xE9;
            std::ptr::copy_nonoverlapping(rel.to_le_bytes().as_ptr(), stub.add(1), 4);

            assert_eq!(detour_code_from_pointer(stub), target);
            assert_ne!(VirtualFree(page.cast(), 0, MEM_RELEASE), 0);
        }
    }

    #[test]
    fn code_from_pointer_follows_indirect_import_thunk() {
        unsafe {
            let page = alloc_page();
            assert!(!page.is_null());

            let stub = page;
            let target = page.add(128);

            #[cfg(target_arch = "x86_64")]
            {
                let slot = stub.add(6) as *mut usize;
                *stub.add(0) = 0xFF;
                *stub.add(1) = 0x25;
                std::ptr::write_unaligned(stub.add(2) as *mut i32, 0);
                std::ptr::write_unaligned(slot, target as usize);
            }

            #[cfg(target_arch = "x86")]
            {
                let slot = page.add(32) as *mut usize;
                *stub.add(0) = 0xFF;
                *stub.add(1) = 0x25;
                std::ptr::write_unaligned(stub.add(2) as *mut u32, slot as u32);
                std::ptr::write_unaligned(slot, target as usize);
            }

            assert_eq!(detour_code_from_pointer(stub), target);
            assert_ne!(VirtualFree(page.cast(), 0, MEM_RELEASE), 0);
        }
    }
}
