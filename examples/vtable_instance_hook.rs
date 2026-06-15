#![cfg(windows)]

use neohook::DetourTransaction;

#[repr(C)]
struct DemoObject {
    vptr: *mut u8,
}

#[inline(never)]
extern "system" fn original_method() -> i32 {
    1
}

#[inline(never)]
extern "system" fn detour_method() -> i32 {
    2
}

fn main() {
    let mut vtable = [original_method as *mut u8];

    let mut first = DemoObject {
        vptr: vtable.as_mut_ptr() as *mut u8,
    };
    let second = DemoObject {
        vptr: vtable.as_mut_ptr() as *mut u8,
    };

    let mut tx = DetourTransaction::begin();
    let original = tx
        .attach_vtable_instance(
            &mut first.vptr as *mut *mut u8,
            0,
            1,
            detour_method as *const u8,
        )
        .expect("attach_vtable_instance failed");

    let hooks = tx.commit().expect("commit failed");

    let first_fn: extern "system" fn() -> i32 =
        unsafe { std::mem::transmute(*(first.vptr as *mut *mut u8)) };
    let second_fn: extern "system" fn() -> i32 =
        unsafe { std::mem::transmute(*(second.vptr as *mut *mut u8)) };
    let original_fn: extern "system" fn() -> i32 = unsafe { std::mem::transmute(original) };

    println!("first object hooked result: {}", first_fn());
    println!("second object original result: {}", second_fn());
    println!("original slot result: {}", original_fn());

    drop(hooks);

    let restored_fn: extern "system" fn() -> i32 =
        unsafe { std::mem::transmute(*(first.vptr as *mut *mut u8)) };
    println!("restored first object result: {}", restored_fn());
}
