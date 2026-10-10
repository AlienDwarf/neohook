#![cfg(windows)]

//! Misuse that must be rejected at compile time. The expected diagnostics in
//! `tests/ui/*.stderr` match the toolchain pinned in `rust-toolchain.toml`.

#[test]
fn compile_fail() {
    trybuild::TestCases::new().compile_fail("tests/ui/*.rs");
}
