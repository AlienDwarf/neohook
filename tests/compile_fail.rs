#![cfg(windows)]

//! Misuse that must be rejected at compile time.

#[test]
fn compile_fail() {
    trybuild::TestCases::new().compile_fail("tests/ui/*.rs");
}
