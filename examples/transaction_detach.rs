use neohook::DetourTransaction;
use std::error::Error;
use std::hint::black_box;

#[inline(never)]
fn first_target(value: i32) -> i32 {
    black_box(value) + 1
}

#[inline(never)]
fn second_target(value: i32) -> i32 {
    black_box(value) + 2
}

#[inline(never)]
fn first_detour(value: i32) -> i32 {
    black_box(value) + 100
}

#[inline(never)]
fn second_detour(value: i32) -> i32 {
    black_box(value) + 200
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut attach_tx = DetourTransaction::begin();
    attach_tx.update_all_threads();
    attach_tx.attach(first_target as *mut u8, first_detour as *const u8)?;
    attach_tx.attach(second_target as *mut u8, second_detour as *const u8)?;
    let mut hooks = attach_tx.commit()?;

    println!(
        "both hooked: first={}, second={}",
        first_target(1),
        second_target(1)
    );

    let mut detach_tx = DetourTransaction::begin();
    detach_tx.update_all_threads();
    detach_tx.detach(&mut hooks[0])?;
    detach_tx.commit()?;

    println!(
        "first detached: first={}, second={}",
        first_target(1),
        second_target(1)
    );

    Ok(())
}
