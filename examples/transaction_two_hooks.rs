use neohook::TransactionCore;
use std::error::Error;

type MathFn = extern "system" fn(i32, i32) -> i32;

static mut ORIGINAL_ADD: Option<MathFn> = None;
static mut ORIGINAL_SUB: Option<MathFn> = None;

#[inline(never)]
extern "system" fn add(a: i32, b: i32) -> i32 {
    a + b
}

#[inline(never)]
extern "system" fn sub(a: i32, b: i32) -> i32 {
    a - b
}

extern "system" fn add_detour(a: i32, b: i32) -> i32 {
    let original = unsafe { ORIGINAL_ADD.expect("missing ORIGINAL_ADD") };
    original(a, b) + 100
}

extern "system" fn sub_detour(a: i32, b: i32) -> i32 {
    let original = unsafe { ORIGINAL_SUB.expect("missing ORIGINAL_SUB") };
    original(a, b) - 100
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("before: add(7, 2) = {}", add(7, 2));
    println!("before: sub(7, 2) = {}", sub(7, 2));
    assert_eq!(add(7, 2), 9);
    assert_eq!(sub(7, 2), 5);

    let mut tx = TransactionCore::begin();
    tx.update_all_threads();

    let add_trampoline = tx.attach(add as *mut u8, add_detour as *const u8)?;
    let sub_trampoline = tx.attach(sub as *mut u8, sub_detour as *const u8)?;

    let hooks = tx.commit()?;

    unsafe {
        ORIGINAL_ADD = Some(std::mem::transmute::<*mut u8, MathFn>(add_trampoline));
        ORIGINAL_SUB = Some(std::mem::transmute::<*mut u8, MathFn>(sub_trampoline));
    }

    println!("after:  add(7, 2) = {}", add(7, 2));
    println!("after:  sub(7, 2) = {}", sub(7, 2));

    for hook in hooks {
        hook.unhook()?;
    }

    println!("after unhook: add(7, 2) = {}", add(7, 2));
    println!("after unhook: sub(7, 2) = {}", sub(7, 2));

    Ok(())
}
