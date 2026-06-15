#![cfg(windows)]

use neohook::DetourTransaction;

#[inline(never)]
extern "system" fn original_method() -> i32 {
    1
}

#[inline(never)]
extern "system" fn detour_method() -> i32 {
    2
}

fn main() {
    // Demonstration with a synthetic VTable array.
    let mut vtable = [original_method as *mut u8];

    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();

    let original = tx
        .attach_vtable(vtable.as_mut_ptr(), 0, detour_method as *const u8)
        .expect("attach_vtable failed");

    let hooks = tx.commit().expect("commit failed");

    let current_fn: extern "system" fn() -> i32 = unsafe { std::mem::transmute(vtable[0]) };
    let original_fn: extern "system" fn() -> i32 = unsafe { std::mem::transmute(original) };

    println!("hooked slot result: {}", current_fn());
    println!("original slot result: {}", original_fn());

    drop(hooks);

    let restored_fn: extern "system" fn() -> i32 = unsafe { std::mem::transmute(vtable[0]) };
    println!("restored slot result: {}", restored_fn());
}
