// expect: E0277
use neohook::detour_closure;
use std::cell::Cell;

#[inline(never)]
extern "system" fn target(a: i32) -> i32 {
    a
}

fn main() {
    // The closure can run on several threads at once, so its state must be Sync.
    let calls = Cell::new(0);
    let _ = detour_closure!(target, "system" fn(a: i32) -> i32, move |orig, a| {
        calls.set(calls.get() + 1);
        orig(a)
    });
}
