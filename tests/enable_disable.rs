#![cfg(windows)]

//! Coverage for enabling/disabling hooks without a full unhook.
//!
//! Disabling restores the original code/pointer while keeping the hook
//! installed, so it can be re-enabled cheaply. Each test toggles a hook back and
//! forth and checks the observable behavior.

use neohook::DetourTransaction;
use neohook::api::*;
use std::hint::black_box;

// --- inline -----------------------------------------------------------------

#[inline(never)]
fn inline_target(x: i32) -> i32 {
    black_box(x) + black_box(1)
}

#[inline(never)]
fn inline_detour(x: i32) -> i32 {
    black_box(x) + black_box(1000)
}

#[test]
fn inline_hook_disable_enable_roundtrip() {
    assert_eq!(inline_target(1), 2);

    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();
    tx.attach(inline_target as *mut u8, inline_detour as *const u8)
        .expect("attach should succeed");
    let mut hooks = tx.commit().expect("commit should succeed");

    assert!(hooks[0].is_enabled());
    assert_eq!(inline_target(1), 1001);

    hooks[0].disable().expect("disable should succeed");
    assert!(!hooks[0].is_enabled());
    assert_eq!(inline_target(1), 2);

    // Disabling again is a no-op.
    hooks[0]
        .disable()
        .expect("redundant disable should succeed");
    assert_eq!(inline_target(1), 2);

    hooks[0].enable().expect("enable should succeed");
    assert!(hooks[0].is_enabled());
    assert_eq!(inline_target(1), 1001);

    drop(hooks);
    assert_eq!(inline_target(1), 2);
}

// --- vtable -----------------------------------------------------------------

#[repr(C)]
struct Object {
    vptr: *mut u8,
}

#[inline(never)]
extern "system" fn vt_base() -> i32 {
    1
}

#[inline(never)]
extern "system" fn vt_detour() -> i32 {
    2
}

unsafe fn call_slot0(table: *mut u8) -> i32 {
    let entry = unsafe { *(table as *mut *mut u8).add(0) };
    let f: extern "system" fn() -> i32 = unsafe { std::mem::transmute(entry) };
    f()
}

#[test]
fn shared_vtable_disable_enable_roundtrip() {
    let mut vtable = [vt_base as *mut u8];

    let mut tx = DetourTransaction::begin();
    tx.attach_vtable(vtable.as_mut_ptr(), 0, vt_detour as *const u8)
        .expect("attach_vtable should succeed");
    let mut hooks = tx.commit().expect("commit should succeed");

    let table = vtable.as_mut_ptr() as *mut u8;
    assert_eq!(unsafe { call_slot0(table) }, 2);

    hooks[0].disable().expect("disable should succeed");
    assert!(!hooks[0].is_enabled());
    assert_eq!(unsafe { call_slot0(table) }, 1);

    hooks[0].enable().expect("enable should succeed");
    assert_eq!(unsafe { call_slot0(table) }, 2);

    drop(hooks);
    assert_eq!(unsafe { call_slot0(table) }, 1);
}

#[test]
fn instance_vtable_disable_enable_roundtrip() {
    let mut vtable = [vt_base as *mut u8];
    let mut obj = Object {
        vptr: vtable.as_mut_ptr() as *mut u8,
    };

    let mut tx = DetourTransaction::begin();
    tx.attach_vtable_instance(&mut obj.vptr as *mut *mut u8, 0, 1, vt_detour as *const u8)
        .expect("attach_vtable_instance should succeed");
    let mut hooks = tx.commit().expect("commit should succeed");

    assert_eq!(unsafe { call_slot0(obj.vptr) }, 2);

    hooks[0].disable().expect("disable should succeed");
    assert!(!hooks[0].is_enabled());
    // The object dispatches through its original table again.
    assert_eq!(obj.vptr, vtable.as_mut_ptr() as *mut u8);
    assert_eq!(unsafe { call_slot0(obj.vptr) }, 1);

    hooks[0].enable().expect("enable should succeed");
    assert_eq!(unsafe { call_slot0(obj.vptr) }, 2);

    drop(hooks);
    assert_eq!(obj.vptr, vtable.as_mut_ptr() as *mut u8);
    assert_eq!(unsafe { call_slot0(obj.vptr) }, 1);
}

// --- FFI ---------------------------------------------------------------------

#[test]
fn ffi_set_enabled_roundtrip() {
    let mut vtable = [vt_base as *mut u8];

    unsafe {
        let tx = detours_transaction_begin();
        assert!(!tx.is_null());
        let original =
            detours_transaction_attach_vtable(tx, vtable.as_mut_ptr(), 0, vt_detour as *const u8);
        assert_eq!(original, vt_base as *mut u8);

        let handle = detours_transaction_commit(tx);
        assert!(!handle.is_null());

        let table = vtable.as_mut_ptr() as *mut u8;
        assert_eq!(detours_handle_is_enabled(handle, 0), 1);
        assert_eq!(call_slot0(table), 2);

        assert_eq!(detours_handle_set_enabled(handle, 0, 0), 1);
        assert_eq!(detours_handle_is_enabled(handle, 0), 0);
        assert_eq!(call_slot0(table), 1);

        assert_eq!(detours_handle_set_enabled(handle, 0, 1), 1);
        assert_eq!(call_slot0(table), 2);

        // Out-of-bounds index and null handle are rejected.
        assert_eq!(detours_handle_set_enabled(handle, 99, 0), 0);
        assert_eq!(detours_handle_set_enabled(std::ptr::null_mut(), 0, 0), 0);

        assert_eq!(detours_handle_unhook_and_free(handle), 1);
        assert_eq!(call_slot0(table), 1);
    }
}
