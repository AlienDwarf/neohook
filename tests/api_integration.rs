#![cfg(windows)]

use neohook::DetourError;
use neohook::api::*;
use std::hint::black_box;
use std::ptr;
use windows_sys::Win32::System::Threading::GetCurrentThreadId;

#[inline(never)]
pub fn target_func(a: i32) -> i32 {
    let result = black_box(a) + black_box(1);
    black_box(result)
}

#[inline(never)]
pub fn detour_func(a: i32) -> i32 {
    black_box(a) + 100
}

#[inline(never)]
extern "system" fn vtable_target() -> i32 {
    1
}

#[inline(never)]
extern "system" fn vtable_detour() -> i32 {
    2
}

#[repr(C)]
struct InstanceDemoObject {
    vptr: *mut u8,
}

#[inline(never)]
extern "system" fn instance_target() -> i32 {
    1
}

#[inline(never)]
extern "system" fn instance_detour() -> i32 {
    2
}

#[test]
fn ffi_transaction_happy_path_and_null_guards() {
    unsafe {
        let tx = detours_transaction_begin();
        assert!(!tx.is_null());

        let target = target_func as *mut u8;
        let tramp = detours_transaction_attach(tx, target, detour_func as *const u8);
        assert!(!tramp.is_null());

        let handle = detours_transaction_commit(tx);
        assert!(!handle.is_null());

        assert_eq!(detours_handle_len(handle), 1);

        let original = detours_handle_get_original_ptr(handle, 0);
        assert!(!original.is_null());

        assert_eq!(detours_handle_unhook_and_free(handle), 1);

        assert!(
            detours_transaction_attach(ptr::null_mut(), ptr::null_mut(), ptr::null()).is_null()
        );
        assert!(detours_transaction_commit(ptr::null_mut()).is_null());
        assert_eq!(detours_handle_len(ptr::null_mut()), 0);
        assert!(detours_handle_get_original_ptr(ptr::null_mut(), 0).is_null());
        assert_eq!(detours_handle_unhook_and_free(ptr::null_mut()), 0);
    }
}

#[test]
fn ffi_get_original_ptr_returns_null_for_out_of_bounds_index() {
    let tx = detours_transaction_begin();
    assert!(!tx.is_null());
    unsafe {
        let handle = detours_transaction_commit(tx);
        assert!(!handle.is_null());

        assert!(detours_handle_get_original_ptr(handle, 99).is_null());

        assert_eq!(detours_handle_unhook_and_free(handle), 1);
    }
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

#[test]
fn transaction_vtable_hook_happy_path_and_restore() {
    let mut vtable = [vtable_target as *mut u8];

    let mut tx = DetourTransaction::begin();
    let original = tx
        .attach_vtable(vtable.as_mut_ptr(), 0, vtable_detour as *const u8)
        .expect("attach_vtable should succeed");

    assert_eq!(original, vtable_target as *mut u8);

    let hooks = tx.commit().expect("commit should succeed");
    assert_eq!(hooks.len(), 1);

    let hooked: extern "system" fn() -> i32 = unsafe { std::mem::transmute(vtable[0]) };
    assert_eq!(hooked(), 2);

    drop(hooks);

    let restored: extern "system" fn() -> i32 = unsafe { std::mem::transmute(vtable[0]) };
    assert_eq!(restored(), 1);
}

#[test]
fn transaction_vtable_instance_hook_only_affects_one_object() {
    let mut vtable = [instance_target as *mut u8];

    let mut first = InstanceDemoObject {
        vptr: vtable.as_mut_ptr() as *mut u8,
    };
    let second = InstanceDemoObject {
        vptr: vtable.as_mut_ptr() as *mut u8,
    };

    let mut tx = DetourTransaction::begin();
    let original = tx
        .attach_vtable_instance(
            &mut first.vptr as *mut *mut u8,
            0,
            1,
            instance_detour as *const u8,
        )
        .expect("attach_vtable_instance should succeed");

    assert_eq!(original, instance_target as *mut u8);
    assert_eq!(second.vptr, vtable.as_mut_ptr() as *mut u8);

    let hooks = tx.commit().expect("commit should succeed");
    assert_eq!(hooks.len(), 1);

    let first_table = first.vptr as *mut *mut u8;
    let second_table = second.vptr as *mut *mut u8;
    let first_fn: extern "system" fn() -> i32 = unsafe { std::mem::transmute(*first_table) };
    let second_fn: extern "system" fn() -> i32 = unsafe { std::mem::transmute(*second_table) };

    println!("before first call");
    assert_eq!(first_fn(), 2);
    println!("before second call");
    assert_eq!(second_fn(), 1);

    println!("before drop hooks");
    drop(hooks);

    println!("before restore call");
    let restored_first: extern "system" fn() -> i32 = unsafe {
        std::mem::transmute(*(first.vptr as *mut *mut u8))
    };
    assert_eq!(restored_first(), 1);
}
