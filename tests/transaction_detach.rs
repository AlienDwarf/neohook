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

        assert_eq!(detours_handle_len(handle), 1);
        assert_eq!(target_one(1), 2);
        assert_eq!(target_two(1), 201);

        assert_eq!(detours_handle_unhook_and_free(handle), 1);
        assert_eq!(target_one(1), 2);
        assert_eq!(target_two(1), 3);
    }
}
