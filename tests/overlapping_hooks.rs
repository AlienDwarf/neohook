// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! An inline hook must not start inside the bytes another inline hook steals,
//! whether that hook is queued in the same transaction or already installed.
//! Patching both writes one jump over the other, or relocates the live jump of
//! the first hook into the trampoline of the second.

#[cfg(all(test, windows))]
mod tests {
    use neohook::{DetourError, DetourTransaction};
    use std::arch::naked_asm;

    type RetFn = extern "C" fn() -> u32;

    /// Three `nop`s followed by plain arithmetic returning 6. A 5-byte jump at
    /// the entry steals the `nop`s and the first `mov` (8 bytes), so offset 3 is
    /// an instruction boundary inside that range.
    #[unsafe(naked)]
    extern "C" fn overlap_target() -> u32 {
        naked_asm!(
            "nop",
            "nop",
            "nop",
            "mov eax, 1",
            "mov ecx, 2",
            "mov edx, 3",
            "add eax, ecx",
            "add eax, edx",
            "ret",
            "int3",
            "int3",
            "int3",
            "int3",
        )
    }

    extern "C" fn detour_a() -> u32 {
        std::hint::black_box(100)
    }

    extern "C" fn detour_b() -> u32 {
        std::hint::black_box(200)
    }

    fn call_target() -> u32 {
        let f: RetFn = overlap_target;
        std::hint::black_box(f)()
    }

    fn inner(target: *mut u8) -> *mut u8 {
        unsafe { target.add(3) }
    }

    #[test]
    fn overlapping_hooks_in_one_transaction_are_rejected() {
        let target = overlap_target as *mut u8;
        assert_eq!(call_target(), 6, "sanity before hook");

        let mut tx = DetourTransaction::begin();
        tx.attach(target, detour_a as *const u8)
            .expect("first attach failed");
        let overlap = tx.attach(inner(target), detour_b as *const u8);
        assert!(
            matches!(overlap, Err(DetourError::InvalidParameter)),
            "a hook inside a queued hook's stolen bytes must be rejected, got {overlap:?}"
        );
        tx.abort();

        assert_eq!(call_target(), 6, "an aborted transaction must not patch");
    }

    #[test]
    fn hook_inside_an_installed_hook_is_rejected() {
        let target = overlap_target as *mut u8;
        assert_eq!(call_target(), 6, "sanity before hook");

        let mut tx = DetourTransaction::begin();
        tx.attach(target, detour_a as *const u8)
            .expect("first attach failed");
        let hooks = tx.commit().expect("first commit failed");
        assert_eq!(call_target(), 100);

        let mut tx = DetourTransaction::begin();
        let overlap = tx.attach(inner(target), detour_b as *const u8);
        assert!(
            matches!(overlap, Err(DetourError::InvalidParameter)),
            "a hook inside an installed hook's stolen bytes must be rejected, got {overlap:?}"
        );
        tx.abort();
        assert_eq!(call_target(), 100, "the installed hook must stay intact");

        drop(hooks);
        assert_eq!(call_target(), 6);

        // Once the first hook is gone its bytes are free to hook again.
        let mut tx = DetourTransaction::begin();
        tx.attach(inner(target), detour_b as *const u8)
            .expect("attach after unhook failed");
        let hooks = tx.commit().expect("second commit failed");
        assert_eq!(call_target(), 200);
        drop(hooks);
        assert_eq!(call_target(), 6);
    }
}
