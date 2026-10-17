// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(windows)]

//! A table slot (import, export or VTable entry) is owned by one hook at a
//! time. Stacking a second hook used to let the two unhooks run in the wrong
//! order and put a released detour, stub or VTable clone back in place.

use neohook::{DetourTransaction, Hook, enumerate_imports, find_function, get_module_handle};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

const EXPORT: &str = "RtlGetCurrentProcessorNumber";

unsafe extern "system" fn export_detour_a() -> u32 {
    1111
}

unsafe extern "system" fn export_detour_b() -> u32 {
    2222
}

fn hook_export(
    detour: unsafe extern "system" fn() -> u32,
) -> Result<Vec<Hook>, neohook::DetourError> {
    let ntdll = get_module_handle("ntdll.dll").expect("ntdll is loaded");
    let mut tx = DetourTransaction::begin();
    tx.attach_eat(ntdll as _, EXPORT, detour as *const u8)?;
    tx.commit()
}

#[test]
fn second_eat_hook_on_an_export_is_refused() {
    let original = find_function("ntdll.dll", EXPORT).expect("export exists");

    let first = hook_export(export_detour_a).expect("first hook installs");
    assert!(hook_export(export_detour_b).is_err());

    // Also within one transaction.
    let ntdll = get_module_handle("ntdll.dll").unwrap();
    let mut tx = DetourTransaction::begin();
    assert!(
        tx.attach_eat(ntdll as _, EXPORT, export_detour_b as *const u8)
            .is_err()
    );
    drop(tx);

    drop(first);
    assert_eq!(find_function("ntdll.dll", EXPORT), Some(original));

    // Released again: the export can be hooked anew.
    let again = hook_export(export_detour_b).expect("hook after unhook installs");
    drop(again);
    assert_eq!(find_function("ntdll.dll", EXPORT), Some(original));
}

#[test]
fn two_eat_hooks_on_one_export_in_one_transaction_are_refused() {
    let ntdll = get_module_handle("ntdll.dll").unwrap();
    let mut tx = DetourTransaction::begin();
    tx.attach_eat(ntdll as _, EXPORT, export_detour_a as *const u8)
        .expect("first attach queues");
    assert!(
        tx.attach_eat(ntdll as _, EXPORT, export_detour_b as *const u8)
            .is_err()
    );
}

#[test]
fn detached_eat_hook_frees_its_slot() {
    let mut first = hook_export(export_detour_a).expect("first hook installs");
    let mut tx = DetourTransaction::begin();
    tx.detach(&mut first[0]).expect("detach queues");
    tx.commit().expect("detach commits");

    // `first` is still alive, but no longer owns the slot.
    let second = hook_export(export_detour_b).expect("slot is free after detach");
    drop(first);
    let resolved = find_function("ntdll.dll", EXPORT).unwrap();
    let call: unsafe extern "system" fn() -> u32 = unsafe { std::mem::transmute(resolved) };
    assert_eq!(unsafe { call() }, 2222);
    drop(second);
}

unsafe extern "system" fn import_detour_a() {}
unsafe extern "system" fn import_detour_b() {}

#[test]
fn second_iat_hook_on_an_import_is_refused() {
    let exe = unsafe { GetModuleHandleW(std::ptr::null()) };
    let imports = unsafe { enumerate_imports(exe as _) }.expect("own imports parse");
    let import = imports
        .iter()
        .find(|i| i.name.is_some())
        .expect("the test binary imports something by name");
    let name = import.name.as_deref().unwrap();

    let mut tx = DetourTransaction::begin();
    tx.attach_iat(exe as _, &import.dll, name, import_detour_a as *const u8)
        .expect("first attach queues");
    assert!(
        tx.attach_iat(exe as _, &import.dll, name, import_detour_b as *const u8)
            .is_err()
    );
    tx.abort();
}

#[repr(C)]
struct Object {
    vptr: *mut usize,
}

extern "C" fn method_0(_: *const Object) -> i32 {
    10
}

extern "C" fn method_1(_: *const Object) -> i32 {
    11
}

extern "C" fn detour_a(_: *const Object) -> i32 {
    1
}

extern "C" fn detour_b(_: *const Object) -> i32 {
    2
}

fn call(object: &Object, index: usize) -> i32 {
    let f: extern "C" fn(*const Object) -> i32 =
        unsafe { std::mem::transmute(*object.vptr.add(index)) };
    f(object)
}

fn table() -> Box<[usize; 2]> {
    Box::new([
        method_0 as *const () as usize,
        method_1 as *const () as usize,
    ])
}

#[test]
fn second_shared_vtable_hook_on_a_slot_is_refused() {
    let mut vtable = table();
    let object = Object {
        vptr: vtable.as_mut_ptr(),
    };
    let vt = vtable.as_mut_ptr() as *mut *mut u8;

    let mut tx = DetourTransaction::begin();
    tx.attach_vtable(vt, 1, detour_a as *const u8).unwrap();
    let first = tx.commit().unwrap();

    let mut tx = DetourTransaction::begin();
    assert!(tx.attach_vtable(vt, 1, detour_b as *const u8).is_err());
    // Another slot of the same table is fine.
    tx.attach_vtable(vt, 0, detour_b as *const u8).unwrap();
    let second = tx.commit().unwrap();

    assert_eq!((call(&object, 0), call(&object, 1)), (2, 1));
    drop(first);
    drop(second);
    assert_eq!((call(&object, 0), call(&object, 1)), (10, 11));
}

fn hook_instance(
    object: &mut Object,
    index: usize,
    detour: *const u8,
) -> Result<Vec<Hook>, neohook::DetourError> {
    let mut tx = DetourTransaction::begin();
    tx.attach_vtable_instance(object as *mut Object as *mut *mut u8, index, 2, detour)?;
    tx.commit()
}

#[test]
fn instance_hooks_on_one_object_unhook_in_any_order() {
    let mut vtable = table();
    let original = vtable.as_mut_ptr();
    let mut object = Object { vptr: original };

    for first_out in [0, 1] {
        let a = hook_instance(&mut object, 0, detour_a as *const u8).unwrap();
        let b = hook_instance(&mut object, 1, detour_b as *const u8).unwrap();
        assert_eq!((call(&object, 0), call(&object, 1)), (1, 2));

        let (first, second) = if first_out == 0 { (a, b) } else { (b, a) };
        drop(first);
        assert_ne!(
            object.vptr, original,
            "the other hook still needs the clone"
        );
        let expected = if first_out == 0 { (10, 2) } else { (1, 11) };
        assert_eq!((call(&object, 0), call(&object, 1)), expected);
        drop(second);

        assert_eq!(object.vptr, original);
        assert_eq!((call(&object, 0), call(&object, 1)), (10, 11));
    }
}

#[test]
fn instance_slot_is_owned_even_while_disabled() {
    let mut vtable = table();
    let mut object = Object {
        vptr: vtable.as_mut_ptr(),
    };

    let mut first = hook_instance(&mut object, 0, detour_a as *const u8).unwrap();
    first[0].disable().unwrap();
    assert_eq!(call(&object, 0), 10);
    assert!(hook_instance(&mut object, 0, detour_b as *const u8).is_err());

    first[0].enable().unwrap();
    assert_eq!(call(&object, 0), 1);
    drop(first);
    assert_eq!(object.vptr, vtable.as_mut_ptr());
}

#[test]
fn two_instance_hooks_on_one_object_in_one_transaction() {
    let mut vtable = table();
    let mut object = Object {
        vptr: vtable.as_mut_ptr(),
    };
    let vptr = &mut object as *mut Object as *mut *mut u8;

    let mut tx = DetourTransaction::begin();
    tx.attach_vtable_instance(vptr, 0, 2, detour_a as *const u8)
        .unwrap();
    assert!(
        tx.attach_vtable_instance(vptr, 0, 2, detour_b as *const u8)
            .is_err()
    );
    tx.attach_vtable_instance(vptr, 1, 2, detour_b as *const u8)
        .unwrap();
    let hooks = tx.commit().unwrap();
    assert_eq!((call(&object, 0), call(&object, 1)), (1, 2));

    drop(hooks);
    assert_eq!(object.vptr, vtable.as_mut_ptr());
}
