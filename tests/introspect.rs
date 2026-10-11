#![cfg(windows)]

//! Integration tests for the module / PE introspection API.

use neohook::{
    enumerate_exports, enumerate_imports, enumerate_modules, find_function,
    find_function_by_ordinal, get_entry_point, get_module_handle, get_module_size,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, LoadLibraryW};

fn kernel32() -> HMODULE {
    get_module_handle("kernel32.dll").expect("kernel32.dll should be loaded")
}

#[test]
fn enumerate_modules_lists_kernel32() {
    let modules = enumerate_modules();
    assert!(!modules.is_empty(), "expected at least one loaded module");

    let found = modules
        .iter()
        .any(|m| m.name.eq_ignore_ascii_case("kernel32.dll") && !m.base.is_null());
    assert!(found, "kernel32.dll should appear in the module list");
}

#[test]
fn entry_point_lies_within_the_module_image() {
    let h = kernel32();
    let entry = get_entry_point(h).expect("kernel32 should have an entry point") as usize;

    let base = h as usize;
    let end = base + get_module_size(h) as usize;
    assert!(
        entry >= base && entry < end,
        "entry point {entry:#x} outside [{base:#x}, {end:#x})"
    );
}

#[test]
fn entry_point_of_null_resolves_main_executable() {
    assert!(
        get_entry_point(std::ptr::null_mut()).is_some(),
        "null handle should resolve the main executable entry point"
    );
}

#[test]
fn exports_contain_getprocaddress() {
    let exports = unsafe { enumerate_exports(kernel32()) }.expect("kernel32 exports");
    assert!(!exports.is_empty());

    let gpa = exports
        .iter()
        .find(|e| e.name.as_deref() == Some("GetProcAddress"))
        .expect("GetProcAddress should be exported by kernel32");
    assert!(!gpa.address.is_null());
}

#[test]
fn imports_of_test_executable_are_non_empty() {
    let h = unsafe { GetModuleHandleW(std::ptr::null()) };
    assert!(!h.is_null());

    let imports = unsafe { enumerate_imports(h) }.expect("self imports");
    assert!(
        !imports.is_empty(),
        "the test executable should import from system DLLs"
    );
    // Every import names a source DLL.
    assert!(imports.iter().all(|i| !i.dll.is_empty()));
}

#[test]
fn find_function_by_ordinal_matches_named_lookup() {
    // Pick a non-forwarded, named kernel32 export and round-trip it through the
    // ordinal-based resolver. For a non-forwarded export, GetProcAddress by name
    // and by ordinal must agree.
    let exports = unsafe { enumerate_exports(kernel32()) }.expect("kernel32 exports");

    let sample = exports
        .iter()
        .find(|e| e.name.is_some() && e.forwarder.is_none() && e.ordinal <= u16::MAX as u32)
        .expect("kernel32 should have a named, non-forwarded export");

    let name = sample.name.as_deref().unwrap();
    let by_name = find_function("kernel32.dll", name).expect("named lookup should resolve");
    let by_ordinal = find_function_by_ordinal("kernel32.dll", sample.ordinal as u16)
        .expect("ordinal lookup should resolve");

    assert_eq!(
        by_name, by_ordinal,
        "name and ordinal lookups should resolve to the same address for {name}"
    );
}

#[test]
fn introspection_rejects_invalid_module() {
    let mut stack_value = 0u32;
    let fake = (&mut stack_value as *mut u32).cast::<core::ffi::c_void>() as HMODULE;

    assert!(unsafe { enumerate_exports(fake) }.is_err());
    assert!(unsafe { enumerate_imports(fake) }.is_err());
    assert!(get_entry_point(fake).is_none());
}

#[test]
fn enumerate_modules_is_never_empty_while_modules_load() {
    // Snapshots fail transiently while another thread changes the module list.
    let stop = Arc::new(AtomicBool::new(false));
    let churn = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let dlls: Vec<Vec<u16>> = ["version.dll", "winmm.dll", "msimg32.dll"]
                .iter()
                .map(|d| d.encode_utf16().chain(std::iter::once(0)).collect())
                .collect();
            while !stop.load(Ordering::Relaxed) {
                for dll in &dlls {
                    let h = unsafe { LoadLibraryW(dll.as_ptr()) };
                    if !h.is_null() {
                        unsafe { FreeLibrary(h) };
                    }
                }
            }
        })
    };

    let start = Instant::now();
    let mut calls = 0;
    let mut empty = 0;
    while calls < 5000 && start.elapsed() < Duration::from_millis(2500) {
        if enumerate_modules().is_empty() {
            empty += 1;
        }
        calls += 1;
    }

    stop.store(true, Ordering::Relaxed);
    churn.join().expect("churn thread");
    assert_eq!(empty, 0, "{empty} of {calls} snapshots were empty");
}
