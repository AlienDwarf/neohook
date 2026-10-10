// expect: E0594
#![allow(unused)]

use neohook::detour_closure;

#[inline(never)]
extern "system" fn target(a: i32) -> i32 {
    a
}

fn main() {
    // Concurrent calls would alias `&mut calls`, so mutable captures are rejected.
    let mut calls = 0;
    let _ = detour_closure!(target, "system" fn(a: i32) -> i32, move |orig, a| {
        calls += 1;
        orig(a)
    });
}
