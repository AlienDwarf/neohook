// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Inline hooks on functions shorter than the jump patch: the patch must never
//! spill past the function's last instruction into the code that follows.

#[cfg(all(test, windows))]
mod tests {
    use neohook::{DetourError, DetourTransaction};
    use std::arch::naked_asm;

    type RetFn = extern "C" fn() -> u32;

    /// Two back-to-back "functions": `xor eax, eax; ret` (3 bytes) immediately
    /// followed by `mov eax, 42; ret`, then int3 padding.
    #[unsafe(naked)]
    extern "C" fn tiny_then_neighbour() -> u32 {
        naked_asm!(
            "xor eax, eax",
            "ret",
            "mov eax, 42",
            "ret",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
        )
    }

    /// `xor eax, eax; ret` followed by 16 bytes of int3 padding.
    #[unsafe(naked)]
    extern "C" fn tiny_padded() -> u32 {
        naked_asm!(
            "xor eax, eax",
            "ret",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
            "int3",
        )
    }

    /// An early-exit prologue: `stc; jc 1f; ret; 1: mov eax, 42; ret`. The
    /// `ret` comes before the patch size is covered, but the branch jumps past
    /// it, so the code after the `ret` still belongs to this function.
    #[unsafe(naked)]
    extern "C" fn early_ret_with_branch_past_it() -> u32 {
        naked_asm!(
            "stc",
            "jc 2f",
            "ret",
            "2:",
            "mov eax, 42",
            "ret",
            "mov eax, 9",
            "ret",
        )
    }

    extern "C" fn detour_ret() -> u32 {
        std::hint::black_box(7)
    }

    fn snapshot(ptr: *const u8, len: usize) -> Vec<u8> {
        unsafe { std::slice::from_raw_parts(ptr, len).to_vec() }
    }

    #[test]
    fn hook_shorter_than_patch_does_not_clobber_next_function() {
        let first = tiny_then_neighbour as *mut u8;
        let before = snapshot(first, 9);
        assert_eq!(
            before,
            [0x31, 0xC0, 0xC3, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3]
        );

        let neighbour: RetFn = unsafe { std::mem::transmute(first.add(3)) };

        let mut tx = DetourTransaction::begin();
        let res = tx.attach(first, detour_ret as *const u8);
        let installed = match res {
            Ok(_) => tx.commit().expect("commit failed"),
            Err(_) => {
                tx.abort();
                Vec::new()
            }
        };

        let after = snapshot(first, 9);
        for hook in installed {
            let _ = hook.unhook();
        }

        assert!(
            matches!(res, Err(DetourError::InvalidParameter)),
            "attach must refuse a function shorter than the patch, got {res:?}"
        );
        assert_eq!(
            after, before,
            "the bytes of both functions must be unchanged"
        );
        assert_eq!(neighbour(), 42, "the following function must still work");
        assert_eq!(tiny_then_neighbour(), 0);
    }

    #[test]
    fn early_ret_with_a_branch_past_it_can_be_hooked() {
        let target = early_ret_with_branch_past_it as *mut u8;
        let before = snapshot(target, 10);
        assert_eq!(early_ret_with_branch_past_it(), 42);

        let mut tx = DetourTransaction::begin();
        let original = tx
            .attach(target, detour_ret as *const u8)
            .expect("a ret that a branch jumps past does not end the function");
        let hooks = tx.commit().expect("commit failed");

        let original: RetFn = unsafe { std::mem::transmute(original) };
        assert_eq!(
            early_ret_with_branch_past_it(),
            7,
            "target must be detoured"
        );
        assert_eq!(original(), 42, "trampoline must take the relocated branch");

        for hook in hooks {
            hook.unhook().expect("unhook failed");
        }
        assert_eq!(
            snapshot(target, 10),
            before,
            "unhook must restore the bytes"
        );
        assert_eq!(early_ret_with_branch_past_it(), 42);
    }

    #[test]
    fn hook_shorter_than_patch_with_padding_succeeds() {
        let target = tiny_padded as *mut u8;
        let before = snapshot(target, 18);

        let mut tx = DetourTransaction::begin();
        let original = tx
            .attach(target, detour_ret as *const u8)
            .expect("attach over int3 padding should succeed");
        let hooks = tx.commit().expect("commit failed");

        let original: RetFn = unsafe { std::mem::transmute(original) };
        assert_eq!(tiny_padded(), 7, "target must be detoured");
        assert_eq!(original(), 0, "trampoline must run the original code");

        for hook in hooks {
            hook.unhook().expect("unhook failed");
        }
        assert_eq!(tiny_padded(), 0);
        assert_eq!(
            snapshot(target, 18),
            before,
            "unhook must restore the bytes"
        );
    }
}
