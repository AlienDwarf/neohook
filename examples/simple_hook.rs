use neohook::detour_inline;

#[inline(never)]
fn double_value(value: i32) -> i32 {
    std::hint::black_box(value) * 2 // Use black_box to prevent compiler optimization. This simple function is to small to be hooked without it
}

fn hook_double_value(value: i32) -> i32 {
    value * -2
}

fn main() {
    let value = 5;
    println!("Original result: {}", double_value(value)); // Should print 10

    let _hook = detour_inline!(double_value, hook_double_value).expect("Failed to hook double_value");
    
    println!("Hooked result: {}", double_value(value)); // Should print -10

    // Hooks will be automatically removed when `hook` goes out of scope
    // To prevent this we can intentionally leak with std::mem::forget
    // or we can use a global static variable (recommended to use OnceLock)
}