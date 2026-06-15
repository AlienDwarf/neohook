#![cfg(windows)]

//! Hooking a COM-style interface vtable.
//!
//! A COM interface pointer is, by definition, a pointer to a pointer to a table
//! of `extern "system"` function pointers whose first parameter is the interface
//! pointer itself (`this`). The first three slots of every COM interface are the
//! `IUnknown` methods:
//!
//! ```text
//!   slot 0: QueryInterface
//!   slot 1: AddRef
//!   slot 2: Release
//! ```
//!
//! This example builds a faithful COM layout in-process so it runs without the
//! COM runtime, but the exact same call works on a real interface pointer
//! returned by `CoCreateInstance` / `QueryInterface`: pass the interface pointer
//! as `object_vptr` and the method's vtable index. Here we hook `AddRef`
//! per-instance, so only this one object's reference counting is intercepted.

use neohook::DetourTransaction;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

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

static ADDREF_CALLS: AtomicU32 = AtomicU32::new(0);
static ORIGINAL_ADDREF: OnceLock<extern "system" fn(*mut ComObject) -> u32> = OnceLock::new();

extern "system" fn add_ref_detour(this: *mut ComObject) -> u32 {
    ADDREF_CALLS.fetch_add(1, Ordering::SeqCst);
    // Forward to the real AddRef so the object's refcount stays correct.
    let original = ORIGINAL_ADDREF.get().expect("original AddRef set");
    original(this)
}

unsafe fn add_ref_through_vtable(obj: *mut ComObject) -> u32 {
    let slot = unsafe { *((*obj).vptr as *mut *mut u8).add(1) };
    let f: extern "system" fn(*mut ComObject) -> u32 = unsafe { std::mem::transmute(slot) };
    f(obj)
}

fn main() {
    let mut vtable: [*mut u8; 3] = [
        query_interface as *mut u8,
        add_ref as *mut u8,
        release as *mut u8,
    ];

    let mut hooked = ComObject {
        vptr: vtable.as_mut_ptr() as *mut u8,
        ref_count: 0,
    };
    let mut other = ComObject {
        vptr: vtable.as_mut_ptr() as *mut u8,
        ref_count: 0,
    };

    let mut tx = DetourTransaction::begin();
    let original = tx
        .attach_vtable_instance(
            &mut hooked.vptr as *mut *mut u8,
            1, // AddRef
            3, // IUnknown has (at least) 3 slots
            add_ref_detour as *const u8,
        )
        .expect("attach_vtable_instance failed");
    ORIGINAL_ADDREF
        .set(unsafe {
            std::mem::transmute::<*mut u8, extern "system" fn(*mut ComObject) -> u32>(original)
        })
        .ok();

    let hooks = tx.commit().expect("commit failed");

    let r1 = unsafe { add_ref_through_vtable(&mut hooked) };
    let r2 = unsafe { add_ref_through_vtable(&mut hooked) };
    let other_ref = unsafe { add_ref_through_vtable(&mut other) };

    println!("hooked AddRef -> refcount {r1}, then {r2}");
    println!("other  AddRef -> refcount {other_ref} (not hooked)");
    println!(
        "intercepted AddRef calls: {}",
        ADDREF_CALLS.load(Ordering::SeqCst)
    );

    drop(hooks);

    let r3 = unsafe { add_ref_through_vtable(&mut hooked) };
    println!("after unhook: hooked AddRef -> refcount {r3}");
    println!(
        "intercepted AddRef calls (unchanged): {}",
        ADDREF_CALLS.load(Ordering::SeqCst)
    );
}
