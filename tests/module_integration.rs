#![cfg(windows)]

use neohook::module;
use windows_sys::Win32::Foundation::HMODULE;

#[test]
fn get_module_size_returns_plausible_size_for_known_module() {
    let h_kernel32 =
        module::get_module_handle("kernel32.dll").expect("failed to get kernel32.dll handle");

    let size = module::get_module_size(h_kernel32);

    assert!(
        size > 0x10000,
        "kernel32.dll size looks implausibly small: {size}"
    );
}

#[test]
fn get_module_size_returns_zero_for_invalid_handles() {
    let null_size = module::get_module_size(std::ptr::null_mut());
    assert_eq!(null_size, 0, "null module handle should return size 0");

    let mut stack_value = 0u32;
    let fake_module = (&mut stack_value as *mut u32).cast::<core::ffi::c_void>() as HMODULE;

    let fake_size = module::get_module_size(fake_module);
    assert_eq!(fake_size, 0, "non-module address should return size 0");
}

#[test]
fn find_function_returns_address_for_existing_export() {
    let addr = module::find_function("kernel32.dll", "GetTickCount")
        .expect("expected GetTickCount to be found in kernel32.dll");

    assert!(
        !addr.is_null(),
        "resolved function pointer must not be null"
    );
}

#[test]
fn find_function_returns_none_for_missing_export() {
    let addr = module::find_function("kernel32.dll", "DefinitelyNotARealWindowsExport_123");
    assert!(addr.is_none(), "missing export should return None");
}

#[test]
fn find_function_returns_none_for_missing_module() {
    let addr = module::find_function("fantasy_dll_999.dll", "SomeFunc");
    assert!(addr.is_none(), "missing DLL should return None");
}

#[test]
fn get_module_handle_returns_none_for_missing_module() {
    let handle = module::get_module_handle("fantasy_dll_999.dll");
    assert!(handle.is_none(), "missing DLL should return None");
}

#[test]
fn find_function_returns_none_for_invalid_function_name_string() {
    let invalid_func_name = "Get\0TickCount";

    let addr = module::find_function("kernel32.dll", invalid_func_name);
    assert!(
        addr.is_none(),
        "embedded NUL in function name should return None"
    );
}
