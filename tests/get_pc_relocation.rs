// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The get-PC idiom (`call next; pop reg`) must observe the original return
//! address when it runs from a trampoline, so position-independent code that
//! derives addresses from it keeps working through the original function.

#[cfg(all(test, windows))]
mod tests {
    use neohook::DetourTransaction;
    use std::arch::naked_asm;

    type GetPcFn = extern "C" fn() -> usize;

    /// `call 2f; 2: pop eax/rax; ret` followed by int3 padding: returns the
    /// address of the `pop`, i.e. the function address + 5.
    #[unsafe(naked)]
    extern "C" fn get_pc() -> usize {
        #[cfg(target_arch = "x86")]
        naked_asm!(
            "call 2f", "2:", "pop eax", "ret", "int3", "int3", "int3", "int3", "int3", "int3",
            "int3", "int3", "int3", "int3", "int3", "int3", "int3", "int3", "int3", "int3",
        );
        #[cfg(target_arch = "x86_64")]
        naked_asm!(
            "call 2f", "2:", "pop rax", "ret", "int3", "int3", "int3", "int3", "int3", "int3",
            "int3", "int3", "int3", "int3", "int3", "int3", "int3", "int3", "int3", "int3",
        );
    }

    extern "C" fn detour() -> usize {
        std::hint::black_box(0)
    }

    #[test]
    fn get_pc_through_trampoline_sees_original_address() {
        let target = get_pc as *mut u8;
        let expected = target as usize + 5;
        assert_eq!(get_pc(), expected, "direct call");

        let mut tx = DetourTransaction::begin();
        let original = tx
            .attach(target, detour as *const u8)
            .expect("attach failed");
        let hooks = tx.commit().expect("commit failed");

        let original: GetPcFn = unsafe { std::mem::transmute(original) };
        let through_trampoline = original();
        let hooked = get_pc();

        for hook in hooks {
            hook.unhook().expect("unhook failed");
        }

        assert_eq!(hooked, 0, "target must be detoured");
        assert_eq!(
            through_trampoline, expected,
            "the get-PC idiom must see the original return address through the trampoline"
        );
        assert_eq!(get_pc(), expected, "direct call after unhook");
    }
}
