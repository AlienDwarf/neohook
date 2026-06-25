// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Inline-hook deduplication: queueing the same resolved target twice in one
//! transaction must not patch the live code twice. Following jump thunks can
//! collapse several entry points (e.g. a CRT function and its `_o_*` forwarder)
//! onto one body, and a double patch on that body corrupts it.

#[cfg(all(test, windows))]
mod tests {
    use neohook::{DetourError, DetourTransaction};

    #[inline(never)]
    fn target_for_dedup(a: i32, b: i32) -> i32 {
        std::hint::black_box(a) + std::hint::black_box(b) + std::hint::black_box(0)
    }

    #[inline(never)]
    fn target_for_conflict(a: i32, b: i32) -> i32 {
        std::hint::black_box(a) + std::hint::black_box(b) + std::hint::black_box(2)
    }

    #[inline(never)]
    fn universal_detour(_a: i32, _b: i32) -> i32 {
        std::hint::black_box(9999)
    }

    #[inline(never)]
    fn other_detour(_a: i32, _b: i32) -> i32 {
        std::hint::black_box(1234)
    }

    #[test]
    fn identical_hooks_collapse_to_one() {
        let target_ptr = target_for_dedup as *mut u8;
        let detour_ptr = universal_detour as *const u8;

        let mut tx = DetourTransaction::begin();
        let gateway_first = tx
            .attach(target_ptr, detour_ptr)
            .expect("first attach failed");
        // Same target, same detour: must dedup instead of queueing a second patch.
        let gateway_second = tx
            .attach(target_ptr, detour_ptr)
            .expect("second attach should dedup, not fail");

        assert_eq!(
            gateway_first, gateway_second,
            "an identical re-attach must return the same gateway"
        );

        let hooks = tx.commit().expect("commit failed");
        assert_eq!(
            hooks.len(),
            1,
            "identical hooks must collapse to a single installed hook"
        );

        assert_eq!(
            target_for_dedup(10, 10),
            9999,
            "the target should be detoured after commit"
        );

        for hook in hooks {
            hook.unhook().expect("unhook failed");
        }

        assert_eq!(
            target_for_dedup(10, 10),
            20,
            "unhooking the single hook must fully restore the target"
        );
    }

    #[test]
    fn same_target_different_detour_is_rejected() {
        let target_ptr = target_for_conflict as *mut u8;

        let mut tx = DetourTransaction::begin();
        tx.attach(target_ptr, universal_detour as *const u8)
            .expect("first attach failed");

        let conflict = tx.attach(target_ptr, other_detour as *const u8);
        assert!(
            matches!(conflict, Err(DetourError::InvalidParameter)),
            "the same target with a different detour must be rejected, got {conflict:?}"
        );

        tx.abort();

        assert_eq!(
            target_for_conflict(10, 10),
            22,
            "a rejected/aborted transaction must leave the target untouched"
        );
    }
}
