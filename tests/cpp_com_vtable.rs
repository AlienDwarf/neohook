#![cfg(windows)]

//! C++ / COM style VTable hooking coverage.
//!
//! These tests model objects that follow the C++ / COM ABI: the object's first
//! member is a pointer to a table of `extern "system"` function pointers whose
//! first parameter is the object pointer itself (`this`). This is exactly how
//! MSVC lays out polymorphic C++ objects and how every COM interface pointer is
//! shaped, so hooking such a slot exercises the same machinery NeoHook uses
//! against real C++ / COM targets — including correct `this` plumbing and
//! chaining back into the original method.

use neohook::{DetourTransaction, Hook};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

// ---------------------------------------------------------------------------
// A polymorphic C++-style object: `int get_value()` and `int add(int)`.
// ---------------------------------------------------------------------------

#[repr(C)]
struct CppObject {
    vptr: *mut u8,
    value: i32,
}

extern "system" fn get_value(this: *mut CppObject) -> i32 {
    unsafe { (*this).value }
}

extern "system" fn add(this: *mut CppObject, x: i32) -> i32 {
    unsafe { (*this).value + x }
}

unsafe fn call_get_value(obj: *const CppObject) -> i32 {
    let slot = unsafe { *((*obj).vptr as *mut *mut u8).add(0) };
    let f: extern "system" fn(*mut CppObject) -> i32 = unsafe { std::mem::transmute(slot) };
    f(obj as *mut CppObject)
}

unsafe fn call_add(obj: *const CppObject, x: i32) -> i32 {
    let slot = unsafe { *((*obj).vptr as *mut *mut u8).add(1) };
    let f: extern "system" fn(*mut CppObject, i32) -> i32 = unsafe { std::mem::transmute(slot) };
    f(obj as *mut CppObject, x)
}

static SHARED_ORIGINAL: OnceLock<extern "system" fn(*mut CppObject) -> i32> = OnceLock::new();

extern "system" fn shared_detour(this: *mut CppObject) -> i32 {
    // Forward to the real method (using the right `this`) and adjust the result.
    let original = SHARED_ORIGINAL.get().expect("original must be set before dispatch");
    original(this) + 1000
}

#[test]
fn cpp_shared_vtable_hook_receives_this_and_chains_to_original() {
    let mut vtable: [*mut u8; 2] = [get_value as *mut u8, add as *mut u8];
    let a = CppObject {
        vptr: vtable.as_mut_ptr() as *mut u8,
        value: 7,
    };
    let b = CppObject {
        vptr: vtable.as_mut_ptr() as *mut u8,
        value: 100,
    };

    let mut tx = DetourTransaction::begin();
    let original = tx
        .attach_vtable(vtable.as_mut_ptr(), 0, shared_detour as *const u8)
        .expect("attach_vtable should succeed");
    SHARED_ORIGINAL
        .set(unsafe { std::mem::transmute::<*mut u8, extern "system" fn(*mut CppObject) -> i32>(original) })
        .ok();

    let hooks = tx.commit().expect("commit should succeed");

    // The detour received the correct `this` for each object and chained back
    // into the original virtual method.
    assert_eq!(unsafe { call_get_value(&a) }, 1007);
    assert_eq!(unsafe { call_get_value(&b) }, 1100);
    // A different virtual slot keeps working.
    assert_eq!(unsafe { call_add(&a, 5) }, 12);

    drop(hooks);
    assert_eq!(unsafe { call_get_value(&a) }, 7);
}

static INSTANCE_ORIGINAL: OnceLock<extern "system" fn(*mut CppObject) -> i32> = OnceLock::new();

extern "system" fn instance_detour(this: *mut CppObject) -> i32 {
    let original = INSTANCE_ORIGINAL
        .get()
        .expect("original must be set before dispatch");
    original(this) * 2
}

#[test]
fn cpp_per_instance_hook_isolates_single_object() {
    let mut vtable: [*mut u8; 2] = [get_value as *mut u8, add as *mut u8];
    let mut hooked = CppObject {
        vptr: vtable.as_mut_ptr() as *mut u8,
        value: 21,
    };
    let plain = CppObject {
        vptr: vtable.as_mut_ptr() as *mut u8,
        value: 21,
    };

    let mut tx = DetourTransaction::begin();
    let original = tx
        .attach_vtable_instance(
            &mut hooked.vptr as *mut *mut u8,
            0,
            2,
            instance_detour as *const u8,
        )
        .expect("attach_vtable_instance should succeed");
    INSTANCE_ORIGINAL
        .set(unsafe { std::mem::transmute::<*mut u8, extern "system" fn(*mut CppObject) -> i32>(original) })
        .ok();

    let mut hooks = tx.commit().expect("commit should succeed");

    assert_eq!(unsafe { call_get_value(&hooked) }, 42); // detoured: doubled
    assert_eq!(unsafe { call_get_value(&plain) }, 21); // sibling untouched
    assert_eq!(unsafe { call_add(&hooked, 1) }, 22); // other slot of the clone intact

    let hook = hooks.pop().expect("one hook expected");
    assert!(matches!(hook, Hook::VtableInstance(_)));
    hook.unhook().expect("unhook should succeed");

    assert_eq!(unsafe { call_get_value(&hooked) }, 21);
}

// ---------------------------------------------------------------------------
// A COM-style interface following the IUnknown layout.
//
//   slot 0: QueryInterface
//   slot 1: AddRef
//   slot 2: Release
//
// A real interface pointer obtained from `CoCreateInstance`/`QueryInterface`
// has this identical shape, so the same `attach_vtable`/`attach_vtable_instance`
// call hooks a live COM method.
// ---------------------------------------------------------------------------

#[repr(C)]
struct ComObject {
    vptr: *mut u8,
    ref_count: u32,
}

extern "system" fn query_interface(
    _this: *mut ComObject,
    _iid: *const u8,
    _out: *mut *mut u8,
) -> i32 {
    -1 // E_NOINTERFACE
}

extern "system" fn add_ref(this: *mut ComObject) -> u32 {
    unsafe {
        (*this).ref_count += 1;
        (*this).ref_count
    }
}

extern "system" fn release(this: *mut ComObject) -> u32 {
    unsafe {
        (*this).ref_count -= 1;
        (*this).ref_count
    }
}

unsafe fn call_add_ref(obj: *mut ComObject) -> u32 {
    let slot = unsafe { *((*obj).vptr as *mut *mut u8).add(1) };
    let f: extern "system" fn(*mut ComObject) -> u32 = unsafe { std::mem::transmute(slot) };
    f(obj)
}

static ADDREF_INTERCEPTS: AtomicU32 = AtomicU32::new(0);
static COM_ADDREF_ORIGINAL: OnceLock<extern "system" fn(*mut ComObject) -> u32> = OnceLock::new();

extern "system" fn add_ref_detour(this: *mut ComObject) -> u32 {
    ADDREF_INTERCEPTS.fetch_add(1, Ordering::SeqCst);
    let original = COM_ADDREF_ORIGINAL
        .get()
        .expect("original must be set before dispatch");
    original(this)
}

#[test]
fn com_iunknown_addref_hook_intercepts_and_forwards() {
    let mut vtable: [*mut u8; 3] = [
        query_interface as *mut u8,
        add_ref as *mut u8,
        release as *mut u8,
    ];
    let mut obj = ComObject {
        vptr: vtable.as_mut_ptr() as *mut u8,
        ref_count: 0,
    };

    let mut tx = DetourTransaction::begin();
    let original = tx
        .attach_vtable(vtable.as_mut_ptr(), 1, add_ref_detour as *const u8)
        .expect("attach_vtable should succeed");
    COM_ADDREF_ORIGINAL
        .set(unsafe { std::mem::transmute::<*mut u8, extern "system" fn(*mut ComObject) -> u32>(original) })
        .ok();

    let hooks = tx.commit().expect("commit should succeed");

    // AddRef is intercepted but still forwarded, so the real refcount advances.
    assert_eq!(unsafe { call_add_ref(&mut obj) }, 1);
    assert_eq!(unsafe { call_add_ref(&mut obj) }, 2);
    assert_eq!(ADDREF_INTERCEPTS.load(Ordering::SeqCst), 2);

    drop(hooks);

    // After unhook the detour is no longer in the path.
    assert_eq!(unsafe { call_add_ref(&mut obj) }, 3);
    assert_eq!(ADDREF_INTERCEPTS.load(Ordering::SeqCst), 2);
}
