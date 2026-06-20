#![cfg(windows)]

//! FFI coverage for the C entry points that wrap module / PE introspection,
//! signature scanning, relative-reference resolving, and the standalone hook
//! engines (VEH, INT3, mid-function, delay). These thin `extern "C"` shims are
//! exercised here the same way a C consumer would call them: through raw
//! pointers and NULL-terminated strings, including the null / invalid-UTF-8
//! rejection paths.

use neohook::api::*;
use neohook::{HookContext, MidHookHandler};
use std::ffi::{CStr, CString};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

// --- shared targets ----------------------------------------------------------

#[inline(never)]
extern "system" fn scan_me(a: i32, b: i32) -> i32 {
    std::hint::black_box(a) + std::hint::black_box(b) + std::hint::black_box(7)
}

#[inline(never)]
extern "system" fn scan_detour(_a: i32, _b: i32) -> i32 {
    4242
}

#[inline(never)]
extern "system" fn veh_target() -> u32 {
    std::hint::black_box(1234)
}

extern "system" fn veh_detour() -> u32 {
    9999
}

#[inline(never)]
extern "system" fn int3_target() -> u32 {
    std::hint::black_box(7)
}

extern "system" fn int3_detour() -> u32 {
    77
}

#[inline(never)]
extern "system" fn mid_target(x: u64) -> u64 {
    std::hint::black_box(x).wrapping_add(1)
}

static MID_RAN: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn mid_handler(_ctx: *mut HookContext) {
    MID_RAN.store(true, Ordering::SeqCst);
}

/// A NUL-terminated C string whose body is not valid UTF-8, used to drive the
/// `CStr::to_str()` rejection branches of the FFI shims.
fn invalid_utf8_cstr() -> &'static CStr {
    c"\xff\xfe"
}

fn kernel32() -> HMODULE {
    let h = unsafe { GetModuleHandleW(windows_sys::core::w!("kernel32.dll")) };
    assert!(!h.is_null(), "kernel32 must be loaded");
    h
}

/// Builds an all-fixed IDA signature from the first `len` bytes at `addr`.
fn signature_from(addr: *const u8, len: usize) -> CString {
    let bytes = unsafe { std::slice::from_raw_parts(addr, len) };
    let ida = bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ");
    CString::new(ida).unwrap()
}

// --- detours_code_from_pointer ----------------------------------------------

#[test]
fn ffi_code_from_pointer_handles_real_and_null() {
    unsafe {
        let resolved = detours_code_from_pointer(scan_me as *const u8);
        assert!(!resolved.is_null(), "a real code pointer must resolve");
        assert!(detours_code_from_pointer(ptr::null()).is_null());
    }
}

// --- module enumeration ------------------------------------------------------

#[test]
fn ffi_enumerate_modules_exposes_fields_and_frees() {
    unsafe {
        let handle = detours_enumerate_modules();
        assert!(!handle.is_null());

        let len = detours_modules_len(handle);
        assert!(len > 0, "the process has at least one module");

        // Every entry must surface a base, a non-empty name, and a plausible size.
        let mut saw_named = false;
        for i in 0..len {
            let base = detours_modules_base(handle, i);
            assert!(!base.is_null());
            let _size = detours_modules_size(handle, i);
            let name = detours_modules_name(handle, i);
            assert!(!name.is_null());
            if !CStr::from_ptr(name).to_bytes().is_empty() {
                saw_named = true;
            }
        }
        assert!(saw_named);

        // Out-of-bounds index is a defined null / zero, not a panic.
        assert!(detours_modules_base(handle, len + 100).is_null());
        assert_eq!(detours_modules_size(handle, len + 100), 0);
        assert!(detours_modules_name(handle, len + 100).is_null());

        detours_modules_free(handle);

        // Null-handle guards.
        assert_eq!(detours_modules_len(ptr::null_mut()), 0);
        assert!(detours_modules_base(ptr::null_mut(), 0).is_null());
        assert_eq!(detours_modules_size(ptr::null_mut(), 0), 0);
        assert!(detours_modules_name(ptr::null_mut(), 0).is_null());
        detours_modules_free(ptr::null_mut()); // no-op, must not crash
    }
}

// --- entry point -------------------------------------------------------------

#[test]
fn ffi_get_entry_point_for_null_and_kernel32() {
    unsafe {
        // Null module => main executable entry point.
        assert!(!detours_get_entry_point(ptr::null_mut()).is_null());
        // A real module also has an entry point.
        assert!(!detours_get_entry_point(kernel32() as *mut _).is_null());
    }
}

// --- exports -----------------------------------------------------------------

#[test]
fn ffi_enumerate_exports_exposes_fields_and_frees() {
    unsafe {
        let handle = detours_enumerate_exports(kernel32() as *mut _);
        assert!(!handle.is_null());

        let len = detours_exports_len(handle);
        assert!(len > 0, "kernel32 exports a lot");

        let mut saw_name = false;
        let mut saw_address = false;
        for i in 0..len {
            let _ord = detours_exports_ordinal(handle, i);
            if !detours_exports_name(handle, i).is_null() {
                saw_name = true;
            }
            if !detours_exports_address(handle, i).is_null() {
                saw_address = true;
            }
            // forwarder is allowed to be null for most entries; just touch it.
            let _ = detours_exports_forwarder(handle, i);
        }
        assert!(saw_name && saw_address);

        // Out-of-bounds.
        assert_eq!(detours_exports_ordinal(handle, len + 100), 0);
        assert!(detours_exports_name(handle, len + 100).is_null());
        assert!(detours_exports_address(handle, len + 100).is_null());
        assert!(detours_exports_forwarder(handle, len + 100).is_null());

        detours_exports_free(handle);

        // Null guards.
        assert_eq!(detours_exports_len(ptr::null_mut()), 0);
        assert_eq!(detours_exports_ordinal(ptr::null_mut(), 0), 0);
        assert!(detours_exports_name(ptr::null_mut(), 0).is_null());
        assert!(detours_exports_address(ptr::null_mut(), 0).is_null());
        assert!(detours_exports_forwarder(ptr::null_mut(), 0).is_null());
        detours_exports_free(ptr::null_mut());
    }
}

#[test]
fn ffi_enumerate_exports_rejects_invalid_module() {
    let mut junk = [0u8; 64];
    unsafe {
        let handle = detours_enumerate_exports(junk.as_mut_ptr() as *mut _);
        assert!(handle.is_null(), "garbage PE headers must be rejected");
    }
}

// --- imports -----------------------------------------------------------------

#[test]
fn ffi_enumerate_imports_exposes_fields_and_frees() {
    let h_exe: HMODULE = unsafe { GetModuleHandleW(ptr::null()) };
    assert!(!h_exe.is_null());
    unsafe {
        let handle = detours_enumerate_imports(h_exe as *mut _);
        assert!(!handle.is_null());

        let len = detours_imports_len(handle);
        assert!(len > 0, "the test exe imports from at least one DLL");

        let mut saw_dll = false;
        for i in 0..len {
            let dll = detours_imports_dll(handle, i);
            assert!(!dll.is_null());
            if !CStr::from_ptr(dll).to_bytes().is_empty() {
                saw_dll = true;
            }
            // A given import is either by-name or by-ordinal.
            let ord = detours_imports_ordinal(handle, i);
            let name = detours_imports_name(handle, i);
            assert!(
                ord != u32::MAX || !name.is_null(),
                "an import must have a name or an ordinal"
            );
            let _ = detours_imports_address(handle, i);
        }
        assert!(saw_dll);

        // Out-of-bounds: ordinal sentinel is u32::MAX.
        assert!(detours_imports_dll(handle, len + 100).is_null());
        assert!(detours_imports_name(handle, len + 100).is_null());
        assert_eq!(detours_imports_ordinal(handle, len + 100), u32::MAX);
        assert!(detours_imports_address(handle, len + 100).is_null());

        detours_imports_free(handle);

        // Null guards.
        assert_eq!(detours_imports_len(ptr::null_mut()), 0);
        assert!(detours_imports_dll(ptr::null_mut(), 0).is_null());
        assert!(detours_imports_name(ptr::null_mut(), 0).is_null());
        assert_eq!(detours_imports_ordinal(ptr::null_mut(), 0), u32::MAX);
        assert!(detours_imports_address(ptr::null_mut(), 0).is_null());
        detours_imports_free(ptr::null_mut());
    }
}

#[test]
fn ffi_enumerate_imports_rejects_invalid_module() {
    let mut junk = [0u8; 64];
    unsafe {
        assert!(detours_enumerate_imports(junk.as_mut_ptr() as *mut _).is_null());
    }
}

// --- find_function / find_function_by_ordinal --------------------------------

#[test]
fn ffi_find_function_resolves_and_guards() {
    let module = CString::new("kernel32.dll").unwrap();
    let func = CString::new("GetProcAddress").unwrap();
    unsafe {
        assert!(!detours_find_function(module.as_ptr(), func.as_ptr()).is_null());

        // Null guards.
        assert!(detours_find_function(ptr::null(), func.as_ptr()).is_null());
        assert!(detours_find_function(module.as_ptr(), ptr::null()).is_null());

        // Invalid UTF-8 in either argument.
        assert!(detours_find_function(invalid_utf8_cstr().as_ptr(), func.as_ptr()).is_null());
        assert!(detours_find_function(module.as_ptr(), invalid_utf8_cstr().as_ptr()).is_null());

        // Missing export resolves to null.
        let missing = CString::new("NotAnExport_zzz").unwrap();
        assert!(detours_find_function(module.as_ptr(), missing.as_ptr()).is_null());
    }
}

#[test]
fn ffi_find_function_by_ordinal_resolves_and_guards() {
    let module = CString::new("kernel32.dll").unwrap();
    unsafe {
        // Resolve a real ordinal by walking the export table, then look it up.
        let handle = detours_enumerate_exports(kernel32() as *mut _);
        assert!(!handle.is_null());
        let len = detours_exports_len(handle);
        let mut resolved_any = false;
        for i in 0..len {
            if detours_exports_name(handle, i).is_null() {
                continue; // by-ordinal-only entries are fine too, but skip for stability
            }
            let ord = detours_exports_ordinal(handle, i);
            if ord == 0 || ord > u16::MAX as u32 {
                continue;
            }
            if !detours_find_function_by_ordinal(module.as_ptr(), ord as u16).is_null() {
                resolved_any = true;
                break;
            }
        }
        detours_exports_free(handle);
        assert!(resolved_any, "at least one kernel32 ordinal should resolve");

        // Guards.
        assert!(detours_find_function_by_ordinal(ptr::null(), 1).is_null());
        assert!(detours_find_function_by_ordinal(invalid_utf8_cstr().as_ptr(), 1).is_null());
        // An absurd ordinal does not resolve.
        assert!(detours_find_function_by_ordinal(module.as_ptr(), u16::MAX).is_null());
    }
}

// --- scanning ----------------------------------------------------------------

#[test]
fn ffi_scan_range_finds_local_function_and_guards() {
    let target = scan_me as *const u8;
    let sig = signature_from(target, 16);
    unsafe {
        let found = detours_scan_range(target, 256, sig.as_ptr());
        assert_eq!(found, target);

        // Guards: null start, null pattern, invalid utf8, bad signature.
        assert!(detours_scan_range(ptr::null(), 256, sig.as_ptr()).is_null());
        assert!(detours_scan_range(target, 256, ptr::null()).is_null());
        assert!(detours_scan_range(target, 256, invalid_utf8_cstr().as_ptr()).is_null());
        let bad = CString::new("48 ZZ").unwrap();
        assert!(detours_scan_range(target, 256, bad.as_ptr()).is_null());
    }
}

#[test]
fn ffi_scan_module_finds_local_function_and_guards() {
    let h_exe: HMODULE = unsafe { GetModuleHandleW(ptr::null()) };
    let target = scan_me as *const u8;
    let sig = signature_from(target, 24);
    unsafe {
        let found = detours_scan_module(h_exe as *mut _, sig.as_ptr());
        assert_eq!(found, target);

        assert!(detours_scan_module(h_exe as *mut _, ptr::null()).is_null());
        assert!(detours_scan_module(h_exe as *mut _, invalid_utf8_cstr().as_ptr()).is_null());
        let bad = CString::new("48 ZZ").unwrap();
        assert!(detours_scan_module(h_exe as *mut _, bad.as_ptr()).is_null());
    }
}

#[test]
fn ffi_scan_module_by_name_finds_kernel32_export_and_guards() {
    let module = CString::new("kernel32.dll").unwrap();
    let target = neohook::find_function("kernel32.dll", "GetProcAddress").unwrap();
    let sig = signature_from(target, 12);
    unsafe {
        let found = detours_scan_module_by_name(module.as_ptr(), sig.as_ptr());
        assert_eq!(found, target);

        assert!(detours_scan_module_by_name(ptr::null(), sig.as_ptr()).is_null());
        assert!(detours_scan_module_by_name(module.as_ptr(), ptr::null()).is_null());
        assert!(detours_scan_module_by_name(invalid_utf8_cstr().as_ptr(), sig.as_ptr()).is_null());
        assert!(
            detours_scan_module_by_name(module.as_ptr(), invalid_utf8_cstr().as_ptr()).is_null()
        );
        let bad = CString::new("48 ZZ").unwrap();
        assert!(detours_scan_module_by_name(module.as_ptr(), bad.as_ptr()).is_null());
    }
}

// --- attach_pattern / attach_export (transaction shims) ----------------------

#[test]
fn ffi_attach_pattern_end_to_end_and_guards() {
    use std::sync::OnceLock;
    type AddFn = extern "system" fn(i32, i32) -> i32;
    static ORIG: OnceLock<AddFn> = OnceLock::new();

    extern "system" fn detour(a: i32, b: i32) -> i32 {
        ORIG.get().unwrap()(a, b) * 10
    }

    let mut buf = [0u16; 1024];
    let len = unsafe {
        windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW(
            ptr::null_mut(),
            buf.as_mut_ptr(),
            buf.len() as u32,
        )
    };
    let full = String::from_utf16_lossy(&buf[..len as usize]);
    let module_name = full.rsplit(['\\', '/']).next().unwrap().to_string();
    let module = CString::new(module_name).unwrap();

    let target = scan_me as *const u8;
    let sig = signature_from(target, 24);

    assert_eq!(scan_me(2, 3), 12); // 2 + 3 + 7

    unsafe {
        let tx = detours_transaction_begin();
        detours_transaction_update_all_threads(tx);
        let tramp = detours_transaction_attach_pattern(
            tx,
            module.as_ptr(),
            sig.as_ptr(),
            detour as *const u8,
        );
        assert!(!tramp.is_null());
        ORIG.set(std::mem::transmute::<*mut u8, AddFn>(tramp))
            .unwrap();
        let handle = detours_transaction_commit(tx);
        assert!(!handle.is_null());

        assert_eq!(scan_me(2, 3), 120, "(2 + 3 + 7) * 10 via the patched body");

        detours_handle_unhook_and_free(handle);
        assert_eq!(scan_me(2, 3), 12, "restored");

        // Guards.
        assert!(
            detours_transaction_attach_pattern(
                ptr::null_mut(),
                module.as_ptr(),
                sig.as_ptr(),
                scan_detour as *const u8
            )
            .is_null()
        );
        let tx2 = detours_transaction_begin();
        assert!(
            detours_transaction_attach_pattern(
                tx2,
                invalid_utf8_cstr().as_ptr(),
                sig.as_ptr(),
                scan_detour as *const u8
            )
            .is_null()
        );
        assert!(
            detours_transaction_attach_pattern(
                tx2,
                module.as_ptr(),
                invalid_utf8_cstr().as_ptr(),
                scan_detour as *const u8
            )
            .is_null()
        );
        detours_transaction_abort(tx2);
    }
}

#[test]
fn ffi_attach_export_guards() {
    let module = CString::new("kernel32.dll").unwrap();
    let func = CString::new("GetProcAddress").unwrap();
    unsafe {
        // Null tx / null strings.
        assert!(
            detours_transaction_attach_export(
                ptr::null_mut(),
                module.as_ptr(),
                func.as_ptr(),
                scan_detour as *const u8
            )
            .is_null()
        );

        let tx = detours_transaction_begin();
        assert!(
            detours_transaction_attach_export(
                tx,
                invalid_utf8_cstr().as_ptr(),
                func.as_ptr(),
                scan_detour as *const u8
            )
            .is_null()
        );
        assert!(
            detours_transaction_attach_export(
                tx,
                module.as_ptr(),
                invalid_utf8_cstr().as_ptr(),
                scan_detour as *const u8
            )
            .is_null()
        );
        // Unknown export => null.
        let missing = CString::new("NoSuchExport_zzz").unwrap();
        assert!(
            detours_transaction_attach_export(
                tx,
                module.as_ptr(),
                missing.as_ptr(),
                scan_detour as *const u8
            )
            .is_null()
        );
        detours_transaction_abort(tx);
    }
}

// --- resolve -----------------------------------------------------------------

#[test]
fn ffi_resolve_call_and_rip_relative_guard_on_null() {
    unsafe {
        // Null / non-branch input resolves to null rather than crashing.
        assert!(detours_resolve_call_target(ptr::null()).is_null());
        assert!(detours_resolve_rip_relative(ptr::null()).is_null());
    }
}

#[test]
fn ffi_resolve_relative_decodes_a_synthetic_call() {
    // E8 rel32: a 5-byte near call whose displacement is +0 lands right after it.
    let code = [0xE8u8, 0x00, 0x00, 0x00, 0x00];
    unsafe {
        let target = detours_resolve_relative(code.as_ptr(), 1, 5);
        assert_eq!(target, code.as_ptr().add(5));

        // And the decoder path resolves the same near call.
        let decoded = detours_resolve_call_target(code.as_ptr());
        assert_eq!(decoded, code.as_ptr().add(5));
    }
}

// --- VEH ---------------------------------------------------------------------

#[test]
fn ffi_veh_install_redirects_and_unhooks() {
    fn call() -> u32 {
        let f = std::hint::black_box(veh_target as extern "system" fn() -> u32);
        f()
    }
    assert_eq!(call(), 1234);
    unsafe {
        let hook = detours_veh_install(veh_target as *const u8, veh_detour as *const u8);
        assert!(!hook.is_null());
        assert_eq!(call(), 9999, "VEH detour should win");
        assert_eq!(detours_veh_unhook(hook), 1);
        assert_eq!(call(), 1234, "restored after unhook");

        // Null guards.
        assert!(detours_veh_install(ptr::null(), veh_detour as *const u8).is_null());
        assert_eq!(detours_veh_unhook(ptr::null_mut()), 0);
    }
}

// --- INT3 --------------------------------------------------------------------

#[test]
fn ffi_int3_install_redirects_and_unhooks() {
    fn call() -> u32 {
        let f = std::hint::black_box(int3_target as extern "system" fn() -> u32);
        f()
    }
    assert_eq!(call(), 7);
    unsafe {
        let hook = detours_int3_install(int3_target as *const u8, int3_detour as *const u8);
        assert!(!hook.is_null());
        assert_eq!(call(), 77, "INT3 detour should win");
        assert_eq!(detours_int3_unhook(hook), 1);
        assert_eq!(call(), 7, "restored after unhook");

        // Null guard on unhook.
        assert_eq!(detours_int3_unhook(ptr::null_mut()), 0);
    }
}

// --- mid-function ------------------------------------------------------------

#[test]
fn ffi_midhook_install_runs_handler_and_unhooks() {
    MID_RAN.store(false, Ordering::SeqCst);
    let handler: MidHookHandler = mid_handler;
    unsafe {
        let hook = detours_midhook_install(mid_target as *const u8, handler);
        assert!(!hook.is_null());

        let _ = mid_target(41);
        assert!(MID_RAN.load(Ordering::SeqCst), "handler must fire");

        assert_eq!(detours_midhook_unhook(hook), 1);

        MID_RAN.store(false, Ordering::SeqCst);
        let _ = mid_target(41);
        assert!(
            !MID_RAN.load(Ordering::SeqCst),
            "handler must not fire after unhook"
        );

        // Null guards.
        assert!(detours_midhook_install(ptr::null(), handler).is_null());
        assert_eq!(detours_midhook_unhook(ptr::null_mut()), 0);
    }
}

// --- delay / on-load ---------------------------------------------------------

#[test]
fn ffi_delay_register_for_loaded_module_and_guards() {
    // kernel32 is already loaded, so the delay hook installs immediately and
    // reports active. We target a rarely-called export to avoid side effects.
    let module = CString::new("kernel32.dll").unwrap();
    let func = CString::new("GetProcAddress").unwrap();
    unsafe {
        let hook = detours_delay_register(module.as_ptr(), func.as_ptr(), scan_detour as *const u8);
        // Registration against an already-loaded module should succeed.
        assert!(!hook.is_null());
        assert_eq!(detours_delay_is_active(hook), 1, "loaded module => active");
        assert_eq!(detours_delay_unhook(hook), 1);

        // Guards.
        assert!(
            detours_delay_register(ptr::null(), func.as_ptr(), scan_detour as *const u8).is_null()
        );
        assert!(
            detours_delay_register(module.as_ptr(), ptr::null(), scan_detour as *const u8)
                .is_null()
        );
        assert!(
            detours_delay_register(
                invalid_utf8_cstr().as_ptr(),
                func.as_ptr(),
                scan_detour as *const u8
            )
            .is_null()
        );
        assert!(
            detours_delay_register(
                module.as_ptr(),
                invalid_utf8_cstr().as_ptr(),
                scan_detour as *const u8
            )
            .is_null()
        );
        assert_eq!(detours_delay_is_active(ptr::null()), 0);
        assert_eq!(detours_delay_unhook(ptr::null_mut()), 0);
    }
}

// --- transaction detach via FFI ---------------------------------------------

#[test]
fn ffi_transaction_detach_guards() {
    unsafe {
        // Null tx / null handle are rejected.
        assert_eq!(
            detours_transaction_detach(ptr::null_mut(), ptr::null_mut(), 0),
            0
        );
        let tx = detours_transaction_begin();
        assert_eq!(detours_transaction_detach(tx, ptr::null_mut(), 0), 0);
        detours_transaction_abort(tx);
    }
}

// --- set_enabled / is_enabled out-of-bounds ----------------------------------

#[test]
fn ffi_handle_enable_helpers_guard_oob_and_null() {
    unsafe {
        let tx = detours_transaction_begin();
        let tramp = detours_transaction_attach(tx, scan_me as *mut u8, scan_detour as *const u8);
        assert!(!tramp.is_null());
        let handle = detours_transaction_commit(tx);
        assert!(!handle.is_null());

        // Valid round-trip.
        assert_eq!(detours_handle_is_enabled(handle, 0), 1);
        assert_eq!(detours_handle_set_enabled(handle, 0, 0), 1);
        assert_eq!(detours_handle_is_enabled(handle, 0), 0);
        assert_eq!(detours_handle_set_enabled(handle, 0, 1), 1);

        // Out-of-bounds index.
        assert_eq!(detours_handle_set_enabled(handle, 99, 1), 0);
        assert_eq!(detours_handle_is_enabled(handle, 99), 0);

        // Null handle.
        assert_eq!(detours_handle_set_enabled(ptr::null_mut(), 0, 1), 0);
        assert_eq!(detours_handle_is_enabled(ptr::null_mut(), 0), 0);

        detours_handle_unhook_and_free(handle);
    }
}
