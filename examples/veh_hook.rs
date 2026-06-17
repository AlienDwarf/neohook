// Demonstrates VEH (Vectored Exception Handler) hooking.
//
// A VEH hook does not patch a single byte of the target. It arms a hardware
// execution breakpoint (debug register) on the target address and installs a
// vectored exception handler that redirects the instruction pointer to the
// detour when the breakpoint fires. The function body is never modified.
/* Expected output:
    before hook: secret() = 1234
    installed VEH hook on secret()
    [veh detour] intercepted secret()
    after hook:  secret() = 9999
    after unhook: secret() = 1234
*/
use neohook::VehHook;
use std::error::Error;

#[inline(never)]
extern "system" fn secret() -> u32 {
    std::hint::black_box(1234)
}

extern "system" fn secret_detour() -> u32 {
    println!("[veh detour] intercepted secret()");
    9999
}

fn call_secret() -> u32 {
    // Force an indirect call through the real symbol so the breakpoint fires
    // instead of the optimizer inlining the known return value.
    let f = std::hint::black_box(secret as extern "system" fn() -> u32);
    f()
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("before hook: secret() = {}", call_secret());

    let hook = unsafe {
        VehHook::install(
            secret as *const () as *const u8,
            secret_detour as *const () as *const u8,
        )
    }?;
    println!("installed VEH hook on secret()");

    println!("after hook:  secret() = {}", call_secret());

    hook.unhook()?;
    println!("after unhook: secret() = {}", call_secret());

    Ok(())
}
