#![cfg(windows)]

//! End-to-end round-trip against real OS exports.
//!
//! The broad `src/export_sweep.rs` test proves the relocator *accepts* tens of
//! thousands of real prologues, but it never runs the relocated bytes. This
//! test closes that gap for a small, curated set of exports that are safe to
//! hook and call inside the test process
//!
//! Only no-argument, side-effect-free `WINAPI` getters are used

use neohook::{DetourTransaction, detour_code_from_pointer, find_function};

/// Number of prologue bytes captured before hooking and compared after
/// unhooking. Comfortably larger than any installed patch (5 bytes for the
/// near jump, up to 14 for the absolute form).
const PROLOGUE_SNAPSHOT: usize = 24;

type WinapiGetter = extern "system" fn() -> u32;

unsafe fn snapshot(code: *const u8, len: usize) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts(code, len).to_vec() }
}

/// Hooks `module!name`, drives the detour / trampoline / restore cycle, and
/// asserts every step. `detour` must return `sentinel`.
fn roundtrip(module: &str, name: &str, detour: WinapiGetter, sentinel: u32) {
    let export =
        find_function(module, name).unwrap_or_else(|| panic!("could not resolve {module}!{name}"));
    let code = unsafe { detour_code_from_pointer(export) };
    assert!(
        !code.is_null(),
        "{module}!{name} resolved to a null code pointer"
    );

    // Establish the return value and prologue *before* touching it.
    let func: WinapiGetter = unsafe { std::mem::transmute(code) };
    let real = func();
    assert_ne!(
        real, sentinel,
        "{module}!{name} happened to return the sentinel; pick another sentinel"
    );
    let before = unsafe { snapshot(code, PROLOGUE_SNAPSHOT) };

    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();
    let trampoline = tx
        .attach(code, detour as *const u8)
        .unwrap_or_else(|e| panic!("attach {module}!{name} failed: {e:?}"));
    let hooks = tx
        .commit()
        .unwrap_or_else(|e| panic!("commit {module}!{name} failed: {e:?}"));

    // Direct calls now through the detour...
    assert_eq!(
        func(),
        sentinel,
        "{module}!{name}: detour did not intercept a direct call"
    );

    // ...and the trampoline has relocated original .
    let original: WinapiGetter = unsafe { std::mem::transmute(trampoline) };
    assert_eq!(
        original(),
        real,
        "{module}!{name}: trampoline returned the wrong value - relocation is semantically broken"
    );

    // Unhook via RAII and confirm restored.
    drop(hooks);
    assert_eq!(
        func(),
        real,
        "{module}!{name}: original behavior not restored after unhook"
    );

    let after = unsafe { snapshot(code, PROLOGUE_SNAPSHOT) };
    assert_eq!(
        before, after,
        "{module}!{name}: prologue not restored byte-for-byte"
    );
}

extern "system" fn detour_process_id() -> u32 {
    0x00C0_FFEE
}

extern "system" fn detour_thread_id() -> u32 {
    0x00BA_DBED
}

#[test]
fn roundtrip_get_current_process_id() {
    roundtrip(
        "kernel32.dll",
        "GetCurrentProcessId",
        detour_process_id,
        0x00C0_FFEE,
    );
}

#[test]
fn roundtrip_get_current_thread_id() {
    roundtrip(
        "kernel32.dll",
        "GetCurrentThreadId",
        detour_thread_id,
        0x00BA_DBED,
    );
}
