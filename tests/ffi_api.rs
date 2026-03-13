#![cfg(windows)]

use neohook::api::*;
use std::ffi::CString;
use std::hint::black_box;
use std::ptr;
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::GetCurrentThreadId;

#[inline(never)]
extern "system" fn target_func(a: i32) -> i32 {
    let result = black_box(a) + black_box(1);
    black_box(result)
}

#[inline(never)]
extern "system" fn detour_func(a: i32) -> i32 {
    black_box(a) + 100
}

extern "system" fn dummy_iat_detour() -> u32 {
    0
}

#[test]
fn ffi_inline_transaction_happy_path_and_null_guards() {
    let tx = detours_transaction_begin();
    assert!(!tx.is_null());

    let trampoline =
        detours_transaction_attach(tx, target_func as *mut u8, detour_func as *const u8);
    assert!(!trampoline.is_null());

    let handle = detours_transaction_commit(tx);
    assert!(!handle.is_null());

    assert_eq!(detours_handle_len(handle), 1);

    let original = detours_handle_get_original_ptr(handle, 0);
    assert!(!original.is_null());

    assert_eq!(detours_handle_unhook_and_free(handle), 1);

    assert!(detours_transaction_attach(ptr::null_mut(), ptr::null_mut(), ptr::null()).is_null());
    assert!(detours_transaction_commit(ptr::null_mut()).is_null());
    assert_eq!(detours_handle_len(ptr::null_mut()), 0);
    assert!(detours_handle_get_original_ptr(ptr::null_mut(), 0).is_null());
    assert_eq!(detours_handle_unhook_and_free(ptr::null_mut()), 0);
}

#[test]
fn ffi_get_original_ptr_returns_null_for_out_of_bounds_index() {
    let tx = detours_transaction_begin();
    assert!(!tx.is_null());

    let handle = detours_transaction_commit(tx);
    assert!(!handle.is_null());

    assert!(detours_handle_get_original_ptr(handle, 99).is_null());

    assert_eq!(detours_handle_unhook_and_free(handle), 1);
}

#[test]
fn ffi_update_thread_accepts_current_thread_id() {
    let tx = detours_transaction_begin();
    assert!(!tx.is_null());

    let current_tid = unsafe { GetCurrentThreadId() };
    assert_eq!(detours_transaction_update_thread(tx, current_tid), 1);

    let handle = detours_transaction_commit(tx);
    assert!(!handle.is_null());
    assert_eq!(detours_handle_unhook_and_free(handle), 1);
}

#[test]
fn ffi_update_thread_rejects_null_transaction() {
    let current_tid = unsafe { GetCurrentThreadId() };
    assert_eq!(detours_transaction_update_thread(ptr::null_mut(), current_tid), 0);
}

#[test]
fn ffi_update_all_threads_accepts_valid_transaction() {
    let tx = detours_transaction_begin();
    assert!(!tx.is_null());

    assert_eq!(detours_transaction_update_all_threads(tx), 1);

    let handle = detours_transaction_commit(tx);
    assert!(!handle.is_null());
    assert_eq!(detours_handle_unhook_and_free(handle), 1);
}

#[test]
fn ffi_abort_consumes_transaction() {
    let tx = detours_transaction_begin();
    assert!(!tx.is_null());

    assert_eq!(detours_transaction_abort(tx), 1);
    assert_eq!(detours_transaction_abort(ptr::null_mut()), 0);
}

#[test]
fn ffi_iat_attach_rejects_invalid_module_handles() {
    let tx = detours_transaction_begin();
    assert!(!tx.is_null());

    let dll = CString::new("kernel32.dll").unwrap();
    let func = CString::new("GetTickCount").unwrap();

    let mut dummy_data = 0u32;
    let fake_module = (&mut dummy_data as *mut u32).cast::<core::ffi::c_void>();

    let res_fake = detours_transaction_attach_iat(
        tx,
        fake_module,
        dll.as_ptr(),
        func.as_ptr(),
        dummy_iat_detour as *const u8,
    );
    assert_eq!(res_fake, 0);

    let res_null = detours_transaction_attach_iat(
        tx,
        ptr::null_mut(),
        dll.as_ptr(),
        func.as_ptr(),
        dummy_iat_detour as *const u8,
    );
    assert_eq!(res_null, 0);

    assert_eq!(detours_transaction_abort(tx), 1);
}

#[test]
fn ffi_iat_attach_can_prepare_known_import_if_present() {
    let tx = detours_transaction_begin();
    assert!(!tx.is_null());

    let h_exe: HMODULE = unsafe { GetModuleHandleW(ptr::null()) };
    assert!(!h_exe.is_null());

    let candidates = [
        ("KERNEL32.dll", "GetProcAddress"),
        ("KERNEL32.dll", "GetModuleHandleW"),
        ("KERNEL32.dll", "TerminateProcess"),
    ];

    let mut attached = false;

    for (dll, func) in candidates {
        let dll = CString::new(dll).unwrap();
        let func = CString::new(func).unwrap();

        let ok = detours_transaction_attach_iat(
            tx,
            h_exe.cast(),
            dll.as_ptr(),
            func.as_ptr(),
            dummy_iat_detour as *const u8,
        );

        if ok == 1 {
            attached = true;
            break;
        }
    }

    if !attached {
        assert_eq!(detours_transaction_abort(tx), 1);
        return;
    }

    let handle = detours_transaction_commit(tx);
    assert!(!handle.is_null());

    assert_eq!(detours_handle_len(handle), 1);
    assert!(!detours_handle_get_original_ptr(handle, 0).is_null());

    assert_eq!(detours_handle_unhook_and_free(handle), 1);
}