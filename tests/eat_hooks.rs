#![cfg(windows)]

//! Integration tests for EAT (Export Address Table) hooking.
//!
//! EAT hooks redirect the *exporting* module's export table, so only consumers
//! that resolve the export through `GetProcAddress` (or by walking the EAT)
//! after installation observe the detour. That makes these tests self-contained:
//! they only affect lookups they perform themselves.

use neohook::{TransactionCore, enumerate_exports, get_module_handle};
use std::ffi::CString;
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::GetProcAddress;

type GetTickCountFn = unsafe extern "system" fn() -> u32;

const SENTINEL: u32 = 0xDEAD_BEEF;

unsafe extern "system" fn get_tick_count_detour() -> u32 {
    SENTINEL
}

fn kernel32() -> HMODULE {
    get_module_handle("kernel32.dll").expect("kernel32.dll should be loaded")
}

/// Resolves an export freshly through GetProcAddress - the lookup an EAT hook
/// redirects.
unsafe fn resolve(module: HMODULE, name: &str) -> GetTickCountFn {
    let cname = CString::new(name).unwrap();
    let addr = unsafe { GetProcAddress(module, cname.as_ptr() as *const u8) }
        .expect("GetProcAddress should resolve the export") as *const u8;
    unsafe { std::mem::transmute::<*const u8, GetTickCountFn>(addr) }
}

#[test]
fn eat_hook_redirects_getprocaddress_and_restores() {
    let module = kernel32();

    let before = unsafe { resolve(module, "GetTickCount")() };
    assert_ne!(
        before, SENTINEL,
        "precondition: real function must not return the sentinel"
    );

    let mut tx = TransactionCore::begin();
    tx.attach_eat(module, "GetTickCount", get_tick_count_detour as *const u8)
        .expect("attach_eat should queue the hook");
    let hooks = tx.commit().expect("commit should install the EAT hook");

    // A fresh resolution now lands on the detour (directly or via the jump stub).
    let hooked = unsafe { resolve(module, "GetTickCount")() };
    assert_eq!(
        hooked, SENTINEL,
        "EAT lookup should hit the detour after commit"
    );

    // The recorded original pointer still reaches the real function body.
    let original =
        unsafe { std::mem::transmute::<*const u8, GetTickCountFn>(hooks[0].original_ptr()) };
    assert_ne!(
        unsafe { original() },
        SENTINEL,
        "original_ptr must bypass the detour"
    );

    for hook in hooks {
        hook.unhook().expect("unhook should succeed");
    }

    let after = unsafe { resolve(module, "GetTickCount")() };
    assert_ne!(
        after, SENTINEL,
        "EAT lookup should be restored after unhook"
    );
}

#[test]
fn eat_hook_disable_enable_round_trip() {
    let module = kernel32();

    let mut tx = TransactionCore::begin();
    tx.attach_eat(module, "GetTickCount", get_tick_count_detour as *const u8)
        .expect("attach_eat should queue the hook");
    let mut hooks = tx.commit().expect("commit should install the EAT hook");

    assert_eq!(unsafe { resolve(module, "GetTickCount")() }, SENTINEL);

    hooks[0]
        .disable()
        .expect("disable should restore the original RVA");
    assert_ne!(
        unsafe { resolve(module, "GetTickCount")() },
        SENTINEL,
        "disabled hook should expose the original export"
    );
    assert!(!hooks[0].is_enabled());

    hooks[0]
        .enable()
        .expect("enable should re-point at the detour");
    assert_eq!(
        unsafe { resolve(module, "GetTickCount")() },
        SENTINEL,
        "re-enabled hook should redirect again"
    );
    assert!(hooks[0].is_enabled());

    for hook in hooks {
        hook.unhook().expect("unhook should succeed");
    }
    assert_ne!(unsafe { resolve(module, "GetTickCount")() }, SENTINEL);
}

#[test]
fn attach_eat_rejects_missing_export() {
    let module = kernel32();
    let mut tx = TransactionCore::begin();
    let result = tx.attach_eat(
        module,
        "DefinitelyNotARealExport_123",
        get_tick_count_detour as *const u8,
    );
    assert!(
        result.is_err(),
        "missing export should be rejected at attach time"
    );
}

#[test]
fn attach_eat_rejects_invalid_module() {
    let mut stack_value = 0u32;
    let fake = (&mut stack_value as *mut u32).cast::<core::ffi::c_void>() as HMODULE;

    let mut tx = TransactionCore::begin();
    let result = tx.attach_eat(fake, "GetTickCount", get_tick_count_detour as *const u8);
    assert!(result.is_err(), "invalid module should be rejected");
}

#[test]
fn attach_eat_rejects_null_detour() {
    let module = kernel32();
    let mut tx = TransactionCore::begin();
    let result = tx.attach_eat(module, "GetTickCount", std::ptr::null());
    assert!(result.is_err(), "null detour should be rejected");
}

#[test]
fn attach_eat_rejects_forwarder_export() {
    let module = kernel32();

    // kernel32 forwards a number of exports to kernelbase/ntdll. Pick one so we
    // can confirm that forwarders (which have no code slot) are rejected.
    let exports = unsafe { enumerate_exports(module) }.expect("kernel32 exports");
    let Some(forwarder) = exports
        .iter()
        .find(|e| e.forwarder.is_some() && e.name.is_some())
    else {
        // No forwarded named export on this OS build; nothing to assert.
        return;
    };

    let name = forwarder.name.as_deref().unwrap();
    let mut tx = TransactionCore::begin();
    let result = tx.attach_eat(module, name, get_tick_count_detour as *const u8);
    assert!(
        result.is_err(),
        "forwarder export {name} should be rejected"
    );
}
