// Demonstrates the tracing / logging detour generator.
//
// `detour_trace!` installs an inline hook that logs every call - its arguments
// and return value - and forwards to the original, without writing the logging
// detour by hand. Records go to a process-wide sink: the default prints to
// stderr, but you can install your own to route them into a logging framework.
/* Expected output (the [neohook::trace] lines are written to stderr):
    add(2, 3) = 5
    [neohook::trace] (tid NNNN) add(2, 3) -> 5
    --- custom sink installed ---
    greet(21) = 42
    [trace] greet(21) => 42
    --- signature-free trace_raw! (HookContext) ---
    raw_sum(...) = 30
    [trace] raw_sum(0x10, 0x20) => <entry>
*/
use neohook::{detour_trace, trace, trace_raw};
use std::error::Error;

#[inline(never)]
extern "system" fn add(a: i32, b: i32) -> i32 {
    std::hint::black_box(a) + std::hint::black_box(b)
}

#[inline(never)]
extern "system" fn greet(times: u32) -> u32 {
    std::hint::black_box(times) * 2
}

#[inline(never)]
extern "system" fn raw_sum(a: u64, b: u64) -> u64 {
    std::hint::black_box(a).wrapping_add(std::hint::black_box(b))
}

fn call_raw(f: extern "system" fn(u64, u64) -> u64, a: u64, b: u64) -> u64 {
    let f = std::hint::black_box(f);
    f(a, b)
}

// Indirect calls so the optimizer dispatches through the patched entry points.
fn call_add(f: extern "system" fn(i32, i32) -> i32, a: i32, b: i32) -> i32 {
    let f = std::hint::black_box(f);
    f(a, b)
}

fn call_greet(f: extern "system" fn(u32) -> u32, n: u32) -> u32 {
    let f = std::hint::black_box(f);
    f(n)
}

fn main() -> Result<(), Box<dyn Error>> {
    // 1) Default sink: each traced call is printed to stderr.
    let _h_add = detour_trace!(add, "system" fn(a: i32, b: i32) -> i32)?;
    println!("add(2, 3) = {}", call_add(add, 2, 3));

    // 2) Custom sink: route records into your own format / logger.
    println!("--- custom sink installed ---");
    trace::set_sink(|r| println!("[trace] {}({}) => {}", r.function, r.args, r.ret));

    let _h_greet = detour_trace!(greet, "system" fn(times: u32) -> u32)?;
    println!("greet(21) = {}", call_greet(greet, 21));

    // 3) Signature-free tracing built on HookContext: no ABI/types declared, the
    //    integer argument registers are dumped as hex at entry (no return value).
    println!("--- signature-free trace_raw! (HookContext) ---");
    let _h_raw = trace_raw!(raw_sum, args = 2)?;
    println!("raw_sum(...) = {}", call_raw(raw_sum, 0x10, 0x20));

    trace::clear_sink();
    Ok(())
}
