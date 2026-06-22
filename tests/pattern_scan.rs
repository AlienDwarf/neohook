#![cfg(windows)]

//! Integration tests for pattern (signature) scanning and signature-based hook
//! resolution.

use std::sync::OnceLock;

use neohook::{
    DetourError, DetourTransaction, Pattern, get_module_handle, scan, scan_all, scan_module,
    scan_range,
};
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW};

// A local function whose prologue we turn into a signature, then hook.
#[inline(never)]
extern "system" fn add_numbers(a: i32, b: i32) -> i32 {
    std::hint::black_box(a) + std::hint::black_box(b) + std::hint::black_box(7)
}

type AddFn = extern "system" fn(i32, i32) -> i32;
static ORIG_ADD: OnceLock<AddFn> = OnceLock::new();

extern "system" fn add_detour(a: i32, b: i32) -> i32 {
    let original = ORIG_ADD.get().expect("original trampoline set");
    original(a, b) * 100
}

/// File name (without path) of the test executable, e.g. `pattern_scan-XXXX.exe`.
fn main_module_name() -> String {
    let mut buf = [0u16; 1024];
    let len =
        unsafe { GetModuleFileNameW(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32) };
    assert!(len > 0, "GetModuleFileNameW failed");
    let full = String::from_utf16_lossy(&buf[..len as usize]);
    full.rsplit(['\\', '/']).next().unwrap_or(&full).to_string()
}

fn main_module() -> HMODULE {
    let h = unsafe { GetModuleHandleW(std::ptr::null()) };
    assert!(!h.is_null(), "main module handle must not be null");
    h
}

/// Builds an all-fixed signature from the first `len` bytes at `addr`.
fn signature_from(addr: *const u8, len: usize) -> Pattern {
    let prologue = unsafe { std::slice::from_raw_parts(addr, len) };
    let ida = prologue
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ");
    Pattern::parse(&ida).expect("derived signature should parse")
}

#[test]
fn scan_finds_pattern_in_a_plain_slice() {
    let haystack = [0x90u8, 0x48, 0x8B, 0xC1, 0xE8, 0x11, 0x48, 0x8B, 0xD2, 0xE8];
    let pat = Pattern::parse("48 8B ?? E8").unwrap();

    assert_eq!(scan(&haystack, &pat), Some(1));
    assert_eq!(scan_all(&haystack, &pat), vec![1, 6]);
}

#[test]
fn scan_range_round_trips_a_local_function() {
    let target = add_numbers as *const u8;
    let pat = signature_from(target, 16);

    // Scan a window that comfortably contains the function.
    let found = unsafe { scan_range(target, 256, &pat) }.expect("signature should resolve");
    assert_eq!(
        found, target,
        "scan_range should land on the function start"
    );
}

#[test]
fn scan_module_resolves_a_local_function() {
    let target = add_numbers as *const u8;
    let pat = signature_from(target, 20);

    let found = unsafe { scan_module(main_module(), &pat) }.expect("signature should resolve");
    assert_eq!(found, target);
}

#[test]
fn attach_pattern_hooks_a_local_function_end_to_end() {
    // Baseline behaviour before hooking.
    assert_eq!(add_numbers(2, 3), 12); // 2 + 3 + 7

    let module = main_module_name();
    let target = add_numbers as *const u8;
    // A 24-byte all-fixed signature is unique enough to land on exactly this
    // function within the test executable.
    let pat = signature_from(target, 24);
    let signature = (0..pat.len())
        .map(|i| {
            let byte = unsafe { *target.add(i) };
            format!("{byte:02X}")
        })
        .collect::<Vec<_>>()
        .join(" ");

    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();
    let trampoline = tx
        .attach_pattern(&module, &signature, add_detour as *const u8)
        .expect("attach_pattern should resolve and queue the hook");
    ORIG_ADD
        .set(unsafe { std::mem::transmute::<*mut u8, AddFn>(trampoline) })
        .expect("trampoline should be set once");

    let hooks = tx.commit().expect("commit should succeed");

    // The detour multiplies the original result by 100.
    assert_eq!(add_numbers(2, 3), 1200); // (2 + 3 + 7) * 100

    drop(hooks); // RAII unhook restores the original bytes.
    assert_eq!(add_numbers(2, 3), 12);
}

#[test]
fn attach_pattern_reports_a_parse_error() {
    let mut tx = DetourTransaction::begin();
    let err = tx
        .attach_pattern("kernel32.dll", "48 ZZ", add_detour as *const u8)
        .expect_err("an invalid signature should fail");
    assert!(
        matches!(err, DetourError::Pattern(_)),
        "expected a Pattern error, got {err:?}"
    );
}

#[test]
fn attach_pattern_reports_not_found() {
    let mut tx = DetourTransaction::begin();
    let err = tx
        .attach_pattern(
            "kernel32.dll",
            "DE AD BE EF DE AD BE EF DE AD BE EF DE AD BE EF",
            add_detour as *const u8,
        )
        .expect_err("an absent signature should fail");
    assert!(
        matches!(err, DetourError::PatternNotFound),
        "expected PatternNotFound, got {err:?}"
    );
}

#[test]
fn scan_module_by_name_matches_get_module_handle_path() {
    // A signature taken from a real kernel32 export must resolve to that export.
    let target =
        neohook::find_function("kernel32.dll", "GetProcAddress").expect("GetProcAddress resolves");
    let pat = signature_from(target, 12);

    let h = get_module_handle("kernel32.dll").expect("kernel32 handle");
    let found = unsafe { scan_module(h, &pat) }.expect("signature resolves in kernel32");
    assert_eq!(found, target);
}
