// Mid-function / arbitrary-address detour with full register context.
//
// Unlike an entry-point hook, a mid-function detour can be placed at *any*
// instruction boundary and is reached with arbitrary registers live. NeoHook
// snapshots the CPU state, hands your handler a `HookContext` it can read and
// modify, restores it, then resumes the original instructions.
//
// This example detours a function and rewrites its argument register in flight
// (x86_64), demonstrating that edits to the context take effect.
//
// Run with:  cargo run --example midhook

use neohook::{HookContext, MidHook};

#[inline(never)]
extern "system" fn price_for(quantity: u64) -> u64 {
    // Pretend this is some routine deep inside a larger program.
    std::hint::black_box(quantity).wrapping_mul(100)
}

#[cfg(target_arch = "x86_64")]
unsafe extern "system" fn discount_handler(ctx: *mut HookContext) {
    // Win64 passes the first integer argument in RCX. Give every order +5 units
    // for free by bumping the quantity before the multiplication runs.
    let ctx = unsafe { &mut *ctx };
    println!("  [handler] observed quantity = {}", ctx.rcx);
    ctx.rcx = ctx.rcx.wrapping_add(5);
}

#[cfg(target_arch = "x86")]
unsafe extern "system" fn discount_handler(ctx: *mut HookContext) {
    // On x86 `extern "system"` arguments arrive on the stack, so this handler
    // just observes a register instead of rewriting the argument.
    let ctx = unsafe { &*ctx };
    println!("  [handler] eax = {:#x}", ctx.eax);
}

fn main() {
    println!("price_for(2) before hook = {}", price_for(2)); // 200

    let hook = unsafe { MidHook::install(price_for as *const u8, discount_handler) }
        .expect("mid-function hook failed");

    let hooked = price_for(2);
    println!("price_for(2) while hooked = {hooked}");
    #[cfg(target_arch = "x86_64")]
    println!("  (expected 700 = (2 + 5) * 100)");

    hook.unhook().expect("unhook failed");
    println!("price_for(2) after unhook = {}", price_for(2)); // 200
}
