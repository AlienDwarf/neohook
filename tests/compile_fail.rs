#![cfg(windows)]

//! Misuse that must be rejected at compile time.
//!
//! The expected diagnostics in `tests/ui/*.stderr` change with rustc releases,
//! so this runs only on the toolchain pinned in CI:
//! `cargo +1.99.0 test --test compile_fail -- --ignored`.

#[test]
#[ignore = "compiler diagnostics are pinned to one toolchain; see module docs"]
fn compile_fail() {
    trybuild::TestCases::new().compile_fail("tests/ui/*.rs");
}
