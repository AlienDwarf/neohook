#![cfg(windows)]

use neohook::{detour_helper, detour_inline};
use std::hint::black_box;
use std::sync::OnceLock;

static ORIGINAL_ADD: OnceLock<extern "C" fn(i32, i32) -> i32> = OnceLock::new();

#[inline(never)]
fn add_values(a: i32, b: i32) -> i32 {
    let result = black_box(a) + black_box(b);
    black_box(result)
}

#[inline(never)]
fn simple_detour_add(a: i32, b: i32) -> i32 {
    black_box((a + b) * 10)
}

fn detour_add(a: i32, b: i32) -> i32 {
    let original = ORIGINAL_ADD.get().expect("original trampoline not set");
    let original_result = original(a, b);
    black_box(original_result * 10)
}

#[test]
fn test_macro_inline_simple() {
    let original_result = add_values(2, 2);
    assert_eq!(original_result, 4);

    {
        let _hooks =
            detour_inline!(add_values, simple_detour_add).expect("inline macro hooking failed");

        let hooked_result = add_values(2, 2);
        assert_eq!(hooked_result, 40);
    }

    assert_eq!(add_values(2, 2), 4);
}

#[test]
fn test_macro_helper_sets_original_and_hooks() {
    assert_eq!(add_values(2, 2), 4);

    {
        let _hooks = detour_helper!(
            ORIGINAL_ADD,
            add_values,
            detour_add,
            extern "C" fn(i32, i32) -> i32
        )
        .expect("detour_helper hooking failed");

        assert_eq!(add_values(2, 2), 40);

        let original = ORIGINAL_ADD.get().expect("trampoline not stored");
        assert_eq!(original(3, 4), 7);
    }
    // RAII. hooks went out of scope, should be unhooked now so we should get the original result again
    assert_eq!(add_values(2, 2), 4);
}
