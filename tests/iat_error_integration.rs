#![cfg(windows)]

use neohook::DetourTransaction;
use std::ptr;
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

fn wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

extern "system" fn dummy_detour() -> u32 {
    0
}

#[test]
fn iat_attach_rejects_invalid_module_handles() {
    let mut tx = DetourTransaction::begin();

    // Stack memory is not a valid PE module base.
    let mut dummy_data = 0u32;
    let fake_module = (&mut dummy_data as *mut u32).cast();

    let res_fake = tx.attach_iat(
        fake_module,
        "kernel32.dll",
        "GetTickCount",
        dummy_detour as *const u8,
    );
    assert!(res_fake.is_err());

    let res_null = tx.attach_iat(
        ptr::null_mut(),
        "kernel32.dll",
        "GetTickCount",
        dummy_detour as *const u8,
    );
    assert!(res_null.is_err());
}

#[test]
fn iat_attach_rejects_nonexistent_import_name() {
    let mut tx = DetourTransaction::begin();

    let kernel32_w = wide_null("kernel32.dll");
    let h_k32 = unsafe { GetModuleHandleW(kernel32_w.as_ptr()) };
    assert!(!h_k32.is_null());

    let res = tx.attach_iat(
        h_k32,
        "kernel32.dll",
        "FunctionThatDoesNotExist_123",
        dummy_detour as *const u8,
    );

    assert!(res.is_err());
}

#[test]
fn iat_attach_can_hook_known_import_if_present() {
    let mut tx = DetourTransaction::begin();

    let h_exe: HMODULE = unsafe { GetModuleHandleW(ptr::null()) };
    assert!(!h_exe.is_null());

    // This is a best-effort integration smoke test.
    // Depending on the test binary and toolchain, a specific import may or may not
    // be present in the executable import table.
    let candidates = [
        ("KERNEL32.dll", "GetProcAddress"),
        ("KERNEL32.dll", "GetModuleHandleW"),
        ("KERNEL32.dll", "TerminateProcess"),
    ];

    let mut attached = false;

    for (dll, func) in candidates {
        let res = tx.attach_iat(h_exe, dll, func, dummy_detour as *const u8);

        if res.is_ok() {
            attached = true;
            break;
        }
    }

    if !attached {
        return;
    }

    let mut hooks = tx.commit().expect("commit failed");
    assert_eq!(hooks.len(), 1);

    let hook = hooks.pop().expect("missing installed IAT hook");
    assert!(!hook.original_ptr().is_null());

    hook.unhook().expect("failed to unhook IAT hook");
}
