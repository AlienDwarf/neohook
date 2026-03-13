// Expected output:
/*
    before hooks: compute(5) = 6
    [A] before original chain, x = 5
    [A] after original chain, result = 6
    after hook A: compute(5) = 16
    [A] before original chain, x = 5
    [B] before previous original, x = 5
    [B] after previous original, result = 6
    [A] after original chain, result = 12
    after hook B: compute(5) = 22
    [A] before original chain, x = 5
    [A] after original chain, result = 6
    after unhook B: compute(5) = 16
    after unhook A: compute(5) = 6
*/
use neohook::TransactionCore;
use std::error::Error;

type ComputeFn = extern "system" fn(i32) -> i32;

static mut ORIGINAL_A: Option<ComputeFn> = None;
static mut ORIGINAL_B: Option<ComputeFn> = None;

#[inline(never)]
extern "system" fn compute(x: i32) -> i32 {
    x + 1
}

extern "system" fn detour_a(x: i32) -> i32 {
    println!("[A] before original chain, x = {}", x);

    let next = unsafe { ORIGINAL_A.expect("missing ORIGINAL_A") };
    let result = next(x);

    println!("[A] after original chain, result = {}", result);
    result + 10
}

extern "system" fn detour_b(x: i32) -> i32 {
    println!("[B] before previous original, x = {}", x);

    let next = unsafe { ORIGINAL_B.expect("missing ORIGINAL_B") };
    let result = next(x);

    println!("[B] after previous original, result = {}", result);
    result * 2
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("before hooks: compute(5) = {}", compute(5));

    // First hook: compute -> detour_a
    let mut tx1 = TransactionCore::begin();
    tx1.update_all_threads();

    let gateway_a = tx1.attach(compute as *mut u8, detour_a as *const u8)?;
    let hooks_a = tx1.commit()?;

    unsafe {
        ORIGINAL_A = Some(std::mem::transmute::<*mut u8, ComputeFn>(gateway_a));
    }

    println!("after hook A: compute(5) = {}", compute(5));

    // Second hook: hook the gateway returned by the first hook
    let mut tx2 = TransactionCore::begin();
    tx2.update_all_threads();

    let gateway_b = tx2.attach(gateway_a, detour_b as *const u8)?;
    let hooks_b = tx2.commit()?;

    unsafe {
        ORIGINAL_B = Some(std::mem::transmute::<*mut u8, ComputeFn>(gateway_b));
    }

    println!("after hook B: compute(5) = {}", compute(5));

    for hook in hooks_b {
        hook.unhook()?;
    }

    println!("after unhook B: compute(5) = {}", compute(5));

    for hook in hooks_a {
        hook.unhook()?;
    }

    println!("after unhook A: compute(5) = {}", compute(5));
    Ok(())
}
