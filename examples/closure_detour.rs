// Demonstrates a closure detour - a hook whose body is a Rust closure that
// captures environment. No C/C++ hooking library can express this well: their detours
// must be bare function pointers. The closure receives the original function as
// its first argument, so it can still forward to it.
/* Expected output:
    before hook: add(2, 3) = 5
    after hook:  add(2, 3) = 50   (intercepted, call #1)
    after hook:  add(4, 5) = 90   (intercepted, call #2)
    total intercepted calls: 2
    after unhook: add(2, 3) = 5
*/
use neohook::detour_closure;
use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

#[inline(never)]
extern "system" fn add(a: i32, b: i32) -> i32 {
    std::hint::black_box(a) + std::hint::black_box(b)
}

fn call(a: i32, b: i32) -> i32 {
    let f = std::hint::black_box(add as extern "system" fn(i32, i32) -> i32);
    f(a, b)
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("before hook: add(2, 3) = {}", call(2, 3));

    // captured state shared with the closure - the whole point of closures.
    let counter = Arc::new(AtomicU32::new(0));
    let counter_in = Arc::clone(&counter);

    let hooks = detour_closure!(
        add,
        "system" fn(a: i32, b: i32) -> i32,
        move |orig, a, b| {
            counter_in.fetch_add(1, Ordering::Relaxed);
            orig(a, b) * 10 // forward to the original, then transform
        },
    )?;

    println!(
        "after hook:  add(2, 3) = {}   (intercepted, call #1)",
        call(2, 3)
    );
    println!(
        "after hook:  add(4, 5) = {}   (intercepted, call #2)",
        call(4, 5)
    );
    println!(
        "total intercepted calls: {}",
        counter.load(Ordering::Relaxed)
    );

    drop(hooks); // RAII restores the original bytes.
    println!("after unhook: add(2, 3) = {}", call(2, 3));

    Ok(())
}
