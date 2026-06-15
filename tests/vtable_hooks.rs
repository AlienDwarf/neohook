#![cfg(windows)]

//! Focused coverage for the VTable hooking API.
//!
//! These tests exercise the parts that the happy-path integration tests do not:
//! parameter validation, the explicit (consuming) `unhook()` path, multi-slot
//! cloned VTables, the difference between shared and per-instance semantics, and
//! committing several hooks in a single transaction.

use neohook::{DetourError, DetourTransaction, Hook};
use std::ptr;

#[repr(C)]
struct DemoObject {
    vptr: *mut u8,
}

#[inline(never)]
extern "system" fn slot0() -> i32 {
    10
}

#[inline(never)]
extern "system" fn slot1() -> i32 {
    20
}

#[inline(never)]
extern "system" fn slot2() -> i32 {
    30
}

#[inline(never)]
extern "system" fn detour() -> i32 {
    99
}

unsafe fn call_slot(table: *mut u8, index: usize) -> i32 {
    let entry = unsafe { *(table as *mut *mut u8).add(index) };
    let f: extern "system" fn() -> i32 = unsafe { std::mem::transmute(entry) };
    f()
}

// ---------------------------------------------------------------------------
// Parameter validation
// ---------------------------------------------------------------------------

#[test]
fn attach_vtable_rejects_null_pointers() {
    let mut vtable = [slot0 as *mut u8];
    let mut tx = DetourTransaction::begin();

    assert!(matches!(
        tx.attach_vtable(ptr::null_mut(), 0, detour as *const u8),
        Err(DetourError::InvalidParameter)
    ));
    assert!(matches!(
        tx.attach_vtable(vtable.as_mut_ptr(), 0, ptr::null()),
        Err(DetourError::InvalidParameter)
    ));
}

#[test]
fn attach_vtable_fails_after_abort() {
    let mut vtable = [slot0 as *mut u8];
    let mut tx = DetourTransaction::begin();
    tx.abort();

    assert!(matches!(
        tx.attach_vtable(vtable.as_mut_ptr(), 0, detour as *const u8),
        Err(DetourError::NotStarted)
    ));
}

#[test]
fn attach_vtable_instance_rejects_invalid_parameters() {
    let mut vtable = [slot0 as *mut u8];
    let mut obj = DemoObject {
        vptr: vtable.as_mut_ptr() as *mut u8,
    };
    let mut tx = DetourTransaction::begin();

    // null object pointer
    assert!(matches!(
        tx.attach_vtable_instance(ptr::null_mut(), 0, 1, detour as *const u8),
        Err(DetourError::InvalidParameter)
    ));
    // null detour
    assert!(matches!(
        tx.attach_vtable_instance(&mut obj.vptr as *mut *mut u8, 0, 1, ptr::null()),
        Err(DetourError::InvalidParameter)
    ));
    // vtable_len == 0
    assert!(matches!(
        tx.attach_vtable_instance(&mut obj.vptr as *mut *mut u8, 0, 0, detour as *const u8),
        Err(DetourError::InvalidParameter)
    ));
    // index out of range (index == vtable_len)
    assert!(matches!(
        tx.attach_vtable_instance(&mut obj.vptr as *mut *mut u8, 1, 1, detour as *const u8),
        Err(DetourError::InvalidParameter)
    ));
}

#[test]
fn attach_vtable_instance_rejects_null_vtable_field() {
    let mut obj = DemoObject {
        vptr: ptr::null_mut(),
    };
    let mut tx = DetourTransaction::begin();

    assert!(matches!(
        tx.attach_vtable_instance(&mut obj.vptr as *mut *mut u8, 0, 1, detour as *const u8),
        Err(DetourError::InvalidParameter)
    ));
}

#[test]
fn attach_vtable_instance_fails_after_abort() {
    let mut vtable = [slot0 as *mut u8];
    let mut obj = DemoObject {
        vptr: vtable.as_mut_ptr() as *mut u8,
    };
    let mut tx = DetourTransaction::begin();
    tx.abort();

    assert!(matches!(
        tx.attach_vtable_instance(&mut obj.vptr as *mut *mut u8, 0, 1, detour as *const u8),
        Err(DetourError::NotStarted)
    ));
}

// ---------------------------------------------------------------------------
// Explicit unhook() path (the consuming API that restores + frees)
// ---------------------------------------------------------------------------

#[test]
fn shared_vtable_explicit_unhook_restores_slot() {
    let mut vtable = [slot0 as *mut u8];

    let mut tx = DetourTransaction::begin();
    tx.attach_vtable(vtable.as_mut_ptr(), 0, detour as *const u8)
        .expect("attach_vtable should succeed");
    let mut hooks = tx.commit().expect("commit should succeed");

    assert_eq!(unsafe { call_slot(vtable.as_mut_ptr() as *mut u8, 0) }, 99);

    let hook = hooks.pop().expect("one hook expected");
    assert!(matches!(hook, Hook::Vtable(_)));
    hook.unhook().expect("unhook should succeed");

    assert_eq!(unsafe { call_slot(vtable.as_mut_ptr() as *mut u8, 0) }, 10);
}

#[test]
fn instance_vtable_explicit_unhook_restores_object() {
    let mut vtable = [slot0 as *mut u8];
    let mut obj = DemoObject {
        vptr: vtable.as_mut_ptr() as *mut u8,
    };

    let mut tx = DetourTransaction::begin();
    let original = tx
        .attach_vtable_instance(&mut obj.vptr as *mut *mut u8, 0, 1, detour as *const u8)
        .expect("attach_vtable_instance should succeed");
    assert_eq!(original, slot0 as *mut u8);

    let mut hooks = tx.commit().expect("commit should succeed");
    assert_eq!(unsafe { call_slot(obj.vptr, 0) }, 99);

    let hook = hooks.pop().expect("one hook expected");
    assert!(matches!(hook, Hook::VtableInstance(_)));
    hook.unhook().expect("unhook should succeed");

    // After unhook the object points back at the original (untouched) table.
    assert_eq!(obj.vptr, vtable.as_mut_ptr() as *mut u8);
    assert_eq!(unsafe { call_slot(obj.vptr, 0) }, 10);
}

// ---------------------------------------------------------------------------
// Semantics: shared affects every object, instance affects exactly one
// ---------------------------------------------------------------------------

#[test]
fn shared_vtable_hook_affects_all_objects_sharing_the_table() {
    let mut vtable = [slot0 as *mut u8];
    let a = DemoObject {
        vptr: vtable.as_mut_ptr() as *mut u8,
    };
    let b = DemoObject {
        vptr: vtable.as_mut_ptr() as *mut u8,
    };

    let mut tx = DetourTransaction::begin();
    tx.attach_vtable(vtable.as_mut_ptr(), 0, detour as *const u8)
        .expect("attach_vtable should succeed");
    let hooks = tx.commit().expect("commit should succeed");

    // Both objects dispatch through the same patched slot.
    assert_eq!(unsafe { call_slot(a.vptr, 0) }, 99);
    assert_eq!(unsafe { call_slot(b.vptr, 0) }, 99);

    drop(hooks);

    assert_eq!(unsafe { call_slot(a.vptr, 0) }, 10);
    assert_eq!(unsafe { call_slot(b.vptr, 0) }, 10);
}

#[test]
fn instance_hook_leaves_original_table_untouched() {
    let mut vtable = [slot0 as *mut u8];
    let mut hooked = DemoObject {
        vptr: vtable.as_mut_ptr() as *mut u8,
    };
    let untouched = DemoObject {
        vptr: vtable.as_mut_ptr() as *mut u8,
    };

    let mut tx = DetourTransaction::begin();
    tx.attach_vtable_instance(&mut hooked.vptr as *mut *mut u8, 0, 1, detour as *const u8)
        .expect("attach_vtable_instance should succeed");
    let hooks = tx.commit().expect("commit should succeed");

    // The hooked object now points at a private clone...
    assert_ne!(hooked.vptr, vtable.as_mut_ptr() as *mut u8);
    assert_eq!(unsafe { call_slot(hooked.vptr, 0) }, 99);

    // ...while the shared original table and the other object are unaffected.
    assert_eq!(untouched.vptr, vtable.as_mut_ptr() as *mut u8);
    assert_eq!(unsafe { call_slot(untouched.vptr, 0) }, 10);
    assert_eq!(vtable[0], slot0 as *mut u8);

    drop(hooks);
    assert_eq!(unsafe { call_slot(hooked.vptr, 0) }, 10);
}

// ---------------------------------------------------------------------------
// Multi-slot clone correctness
// ---------------------------------------------------------------------------

#[test]
fn instance_hook_clones_full_table_and_patches_only_target_slot() {
    let mut vtable = [slot0 as *mut u8, slot1 as *mut u8, slot2 as *mut u8];
    let mut obj = DemoObject {
        vptr: vtable.as_mut_ptr() as *mut u8,
    };

    let mut tx = DetourTransaction::begin();
    let original = tx
        .attach_vtable_instance(&mut obj.vptr as *mut *mut u8, 1, 3, detour as *const u8)
        .expect("attach_vtable_instance should succeed");
    assert_eq!(original, slot1 as *mut u8);

    let mut hooks = tx.commit().expect("commit should succeed");

    // Only slot 1 is redirected; the surrounding slots survive the clone intact.
    assert_eq!(unsafe { call_slot(obj.vptr, 0) }, 10);
    assert_eq!(unsafe { call_slot(obj.vptr, 1) }, 99);
    assert_eq!(unsafe { call_slot(obj.vptr, 2) }, 30);

    // The returned original pointer still calls the real method.
    let original_fn: extern "system" fn() -> i32 = unsafe { std::mem::transmute(original) };
    assert_eq!(original_fn(), 20);

    let hook = hooks.pop().expect("one hook expected");
    hook.unhook().expect("unhook should succeed");
    assert_eq!(unsafe { call_slot(obj.vptr, 1) }, 20);
}

// ---------------------------------------------------------------------------
// Several hooks in one transaction
// ---------------------------------------------------------------------------

#[test]
fn multiple_vtable_hooks_in_one_transaction() {
    let mut shared_table = [slot0 as *mut u8];
    let mut instance_table = [slot1 as *mut u8];
    let mut obj = DemoObject {
        vptr: instance_table.as_mut_ptr() as *mut u8,
    };

    let mut tx = DetourTransaction::begin();
    tx.attach_vtable(shared_table.as_mut_ptr(), 0, detour as *const u8)
        .expect("attach_vtable should succeed");
    tx.attach_vtable_instance(&mut obj.vptr as *mut *mut u8, 0, 1, detour as *const u8)
        .expect("attach_vtable_instance should succeed");

    let hooks = tx.commit().expect("commit should succeed");
    assert_eq!(hooks.len(), 2);

    assert_eq!(unsafe { call_slot(shared_table.as_mut_ptr() as *mut u8, 0) }, 99);
    assert_eq!(unsafe { call_slot(obj.vptr, 0) }, 99);

    drop(hooks);

    assert_eq!(unsafe { call_slot(shared_table.as_mut_ptr() as *mut u8, 0) }, 10);
    assert_eq!(unsafe { call_slot(obj.vptr, 0) }, 20);
}
