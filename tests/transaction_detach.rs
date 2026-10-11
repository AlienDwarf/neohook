#![cfg(windows)]

use neohook::DetourTransaction;
use neohook::api::*;
use std::hint::black_box;

#[inline(never)]
fn target_one(value: i32) -> i32 {
    black_box(value) + black_box(1)
}

#[inline(never)]
fn target_two(value: i32) -> i32 {
    black_box(value) + black_box(2)
}

#[inline(never)]
fn detour_one(value: i32) -> i32 {
    black_box(value) + black_box(100)
}

#[inline(never)]
fn detour_two(value: i32) -> i32 {
    black_box(value) + black_box(200)
}

#[test]
fn rust_transaction_detach_removes_only_selected_hook() {
    assert_eq!(target_one(1), 2);
    assert_eq!(target_two(1), 3);

    let mut attach_tx = DetourTransaction::begin();
    attach_tx.update_all_threads();
    attach_tx
        .attach(target_one as *mut u8, detour_one as *const u8)
        .expect("first attach should succeed");
    attach_tx
        .attach(target_two as *mut u8, detour_two as *const u8)
        .expect("second attach should succeed");
    let mut hooks = attach_tx.commit().expect("attach commit should succeed");

    assert_eq!(target_one(1), 101);
    assert_eq!(target_two(1), 201);

    let mut detach_tx = DetourTransaction::begin();
    detach_tx.update_all_threads();
    detach_tx
        .detach(&mut hooks[0])
        .expect("detach should queue");
    let new_hooks = detach_tx.commit().expect("detach commit should succeed");
    assert!(new_hooks.is_empty());

    assert_eq!(target_one(1), 2);
    assert_eq!(target_two(1), 201);

    drop(hooks);
    assert_eq!(target_one(1), 2);
    assert_eq!(target_two(1), 3);
}

#[test]
fn ffi_transaction_detach_removes_one_hook_from_handle() {
    unsafe {
        let attach_tx = detours_transaction_begin();
        assert!(!attach_tx.is_null());

        assert!(
            !detours_transaction_attach(attach_tx, target_one as *mut u8, detour_one as *const u8)
                .is_null()
        );
        assert!(
            !detours_transaction_attach(attach_tx, target_two as *mut u8, detour_two as *const u8)
                .is_null()
        );

        let handle = detours_transaction_commit(attach_tx);
        assert!(!handle.is_null());
        assert_eq!(detours_handle_len(handle), 2);
        assert_eq!(target_one(1), 101);
        assert_eq!(target_two(1), 201);

        let detach_tx = detours_transaction_begin();
        assert!(!detach_tx.is_null());
        assert_eq!(detours_transaction_detach(detach_tx, handle, 0), 1);
        assert_eq!(detours_transaction_detach(detach_tx, handle, 99), 0);

        let detach_result = detours_transaction_commit(detach_tx);
        assert!(!detach_result.is_null());
        assert_eq!(detours_handle_unhook_and_free(detach_result), 1);

        assert_eq!(detours_handle_len(handle), 2);
        assert_eq!(target_one(1), 2);
        assert_eq!(target_two(1), 201);

        assert_eq!(detours_handle_unhook_and_free(handle), 1);
        assert_eq!(target_one(1), 2);
        assert_eq!(target_two(1), 3);
    }
}

#[inline(never)]
fn slot_target_a(value: i32) -> i32 {
    black_box(value) + black_box(1)
}

#[inline(never)]
fn slot_target_b(value: i32) -> i32 {
    black_box(value) + black_box(2)
}

#[inline(never)]
fn slot_target_c(value: i32) -> i32 {
    black_box(value) + black_box(3)
}

#[inline(never)]
fn slot_detour_a(value: i32) -> i32 {
    black_box(value) + black_box(100)
}

#[inline(never)]
fn slot_detour_b(value: i32) -> i32 {
    black_box(value) + black_box(200)
}

#[inline(never)]
fn slot_detour_c(value: i32) -> i32 {
    black_box(value) + black_box(300)
}

#[test]
fn ffi_handle_indices_stay_stable_after_detach() {
    unsafe {
        let attach_tx = detours_transaction_begin();
        assert!(!attach_tx.is_null());
        for (target, detour) in [
            (slot_target_a as *mut u8, slot_detour_a as *const u8),
            (slot_target_b as *mut u8, slot_detour_b as *const u8),
            (slot_target_c as *mut u8, slot_detour_c as *const u8),
        ] {
            assert!(!detours_transaction_attach(attach_tx, target, detour).is_null());
        }
        let handle = detours_transaction_commit(attach_tx);
        assert!(!handle.is_null());
        assert_eq!(slot_target_a(1), 101);
        assert_eq!(slot_target_b(1), 201);
        assert_eq!(slot_target_c(1), 301);

        let detach_tx = detours_transaction_begin();
        assert_eq!(detours_transaction_detach(detach_tx, handle, 0), 1);
        let detach_result = detours_transaction_commit(detach_tx);
        assert!(!detach_result.is_null());
        assert_eq!(detours_handle_unhook_and_free(detach_result), 1);
        assert_eq!(slot_target_a(1), 2);

        // Index 1 must still name the hook on slot_target_b.
        assert_eq!(detours_handle_set_enabled(handle, 1, 0), 1);
        assert_eq!(slot_target_b(1), 3);
        assert_eq!(slot_target_c(1), 301);
        assert_eq!(detours_handle_set_enabled(handle, 1, 1), 1);
        assert_eq!(slot_target_b(1), 201);

        // The detached slot behaves like an out-of-range index.
        assert_eq!(detours_handle_len(handle), 3);
        assert!(detours_handle_get_original_ptr(handle, 0).is_null());
        assert_eq!(detours_handle_is_enabled(handle, 0), 0);
        assert_eq!(detours_handle_set_enabled(handle, 0, 1), 0);
        assert_eq!(slot_target_a(1), 2);
        let again = detours_transaction_begin();
        assert_eq!(detours_transaction_detach(again, handle, 0), 0);
        assert_eq!(detours_transaction_abort(again), 1);
        assert!(!detours_handle_get_original_ptr(handle, 2).is_null());
        assert_eq!(detours_handle_is_enabled(handle, 2), 1);

        assert_eq!(detours_handle_unhook_and_free(handle), 1);
        assert_eq!(slot_target_b(1), 3);
        assert_eq!(slot_target_c(1), 4);
    }
}
