#![cfg(windows)]

use neohook::DetourError;
use neohook::api::*;
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use std::hint::black_box;
use std::ptr;

#[inline(never)]
pub fn target_func(a: i32) -> i32 {
    let result = black_box(a) + black_box(1);
    black_box(result)
}

#[inline(never)]
pub fn detour_func(a: i32) -> i32 {
    black_box(a) + 100
}

#[test]
fn ffi_transaction_happy_path_and_null_guards() {
    let tx = detours_transaction_begin();
    assert!(!tx.is_null());

    let target = target_func as *mut u8;
    let tramp = detours_transaction_attach(tx, target, detour_func as *const u8);
    assert!(!tramp.is_null());

    let handle = detours_transaction_commit(tx);
    assert!(!handle.is_null());

    assert_eq!(detours_handle_len(handle), 1);

    let trampoline = detours_handle_get_trampoline(handle, 0);
    assert!(!trampoline.is_null());

    assert_eq!(detours_handle_unhook_and_free(handle), 1);

    assert!(detours_transaction_attach(ptr::null_mut(), ptr::null_mut(), ptr::null()).is_null());
    assert!(detours_transaction_commit(ptr::null_mut()).is_null());
    assert_eq!(detours_handle_len(ptr::null_mut()), 0);
    assert!(detours_handle_get_trampoline(ptr::null_mut(), 0).is_null());
    assert_eq!(detours_handle_unhook_and_free(ptr::null_mut()), 0);
}

#[test]
fn ffi_get_trampoline_returns_null_for_out_of_bounds_index() {
    let tx = detours_transaction_begin();
    assert!(!tx.is_null());

    let handle = detours_transaction_commit(tx);
    assert!(!handle.is_null());

    assert!(detours_handle_get_trampoline(handle, 99).is_null());

    assert_eq!(detours_handle_unhook_and_free(handle), 1);
}

#[test]
fn transaction_update_thread_accepts_current_thread() {
    let mut tx = DetourTransaction::begin();

    let result = tx.update_thread(unsafe { GetCurrentThreadId() });
    assert!(result.is_ok());
}

#[test]
fn transaction_update_thread_ignores_invalid_thread_id() {
    let mut tx = DetourTransaction::begin();

    let result = tx.update_thread(unsafe { GetCurrentThreadId() } + 99999);
    assert!(result.is_ok());
}

#[test]
fn transaction_update_thread_fails_after_abort() {
    let mut tx = DetourTransaction::begin();
    tx.abort();

    let result = tx.update_thread(unsafe { GetCurrentThreadId() });
    assert!(matches!(result, Err(DetourError::NotStarted)));
}

#[test]
fn transaction_attach_fails_for_invalid_parameters() {
    let mut tx = DetourTransaction::begin();

    let null_target = tx.attach(ptr::null_mut(), detour_func as *const u8);
    assert!(matches!(null_target, Err(DetourError::InvalidParameter)));

    let null_detour = tx.attach(target_func as *mut u8, ptr::null());
    assert!(matches!(null_detour, Err(DetourError::InvalidParameter)));
}

#[test]
fn transaction_attach_fails_after_abort() {
    let mut tx = DetourTransaction::begin();
    tx.abort();

    let result = tx.attach(target_func as *mut u8, detour_func as *const u8);
    assert!(matches!(result, Err(DetourError::NotStarted)));
}
