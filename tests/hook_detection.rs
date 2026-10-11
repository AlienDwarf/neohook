#![cfg(windows)]

//! Hook detection against hooks whose kind and destination are known:
//! neohook's own inline, INT3, VEH, IAT and EAT hooks, plus a clean process.

use neohook::{
    DetectError, DetectedHookKind, DetourTransaction, Int3Hook, VehHook, check_export,
    check_function, get_module_handle, scan_module_hooks,
};
use std::hint::black_box;
use std::sync::Mutex;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

// The hooks below patch shared code and arm per-process state.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn unsafe_check(func: *const u8) -> Result<Option<neohook::DetectedHook>, DetectError> {
    unsafe { check_function(func) }
}

/// File name of the test executable, as the detection reports module names.
fn exe_name() -> String {
    std::env::current_exe()
        .unwrap()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

#[inline(never)]
extern "system" fn clean_target(x: u32) -> u32 {
    black_box(x).wrapping_mul(3).wrapping_add(7)
}

#[inline(never)]
extern "system" fn inline_target(x: u32) -> u32 {
    black_box(x).wrapping_mul(5).wrapping_add(1)
}

#[inline(never)]
extern "system" fn int3_target(x: u32) -> u32 {
    black_box(x).wrapping_mul(7).wrapping_add(2)
}

#[inline(never)]
extern "system" fn veh_target(x: u32) -> u32 {
    black_box(x).wrapping_mul(11).wrapping_add(3)
}

#[inline(never)]
extern "system" fn detour(x: u32) -> u32 {
    black_box(x).wrapping_add(1000)
}

extern "system" fn export_detour() -> u32 {
    0x1234
}

#[test]
fn unhooked_function_is_clean() {
    let _serial = serial();
    assert_eq!(unsafe_check(clean_target as *const u8), Ok(None));
    assert_eq!(check_export("kernel32.dll", "GetTickCount"), Ok(None));
}

#[test]
fn invalid_input_is_reported() {
    assert_eq!(
        unsafe_check(std::ptr::null()),
        Err(DetectError::NullPointer)
    );
    assert_eq!(
        check_export("kernel32.dll", "NoSuchExportAnywhere"),
        Err(DetectError::NotFound)
    );
    assert_eq!(
        scan_module_hooks("no_such_module_here.dll"),
        Err(DetectError::NotFound)
    );

    let page = unsafe {
        windows_sys::Win32::System::Memory::VirtualAlloc(
            std::ptr::null(),
            0x1000,
            windows_sys::Win32::System::Memory::MEM_COMMIT
                | windows_sys::Win32::System::Memory::MEM_RESERVE,
            windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE,
        )
    };
    let result = unsafe_check(page as *const u8);
    unsafe {
        windows_sys::Win32::System::Memory::VirtualFree(
            page,
            0,
            windows_sys::Win32::System::Memory::MEM_RELEASE,
        )
    };
    assert_eq!(result, Err(DetectError::NotInModule));
}

#[test]
fn inline_hook_is_found_with_its_destination() {
    let _serial = serial();
    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();
    tx.attach(inline_target as *mut u8, detour as *const u8)
        .expect("attach");
    let hooks = tx.commit().expect("commit");

    let found = unsafe_check(inline_target as *const u8);
    drop(hooks);

    let hook = found.expect("check").expect("the inline hook is found");
    assert_eq!(hook.kind, DetectedHookKind::InlineJump);
    let detour_code = unsafe { neohook::detour_code_from_pointer(detour as *const u8) };
    assert_eq!(hook.destination, Some(detour_code as *const u8));
    assert_eq!(hook.destination_module, Some(exe_name()));

    assert_eq!(
        unsafe_check(inline_target as *const u8),
        Ok(None),
        "clean again after unhook"
    );
}

#[test]
fn int3_hook_is_found() {
    let _serial = serial();
    let target = unsafe { neohook::detour_code_from_pointer(int3_target as *const u8) };
    let hook = unsafe { Int3Hook::install(target, detour as *const u8) }.expect("install");
    let found = unsafe_check(int3_target as *const u8);
    hook.unhook().unwrap();

    let found = found.expect("check").expect("the breakpoint is found");
    assert_eq!(found.kind, DetectedHookKind::Breakpoint);
    assert_eq!(found.address, target as *const u8);
}

#[test]
fn veh_hook_is_found_in_the_debug_registers() {
    let _serial = serial();
    let target = unsafe { neohook::detour_code_from_pointer(veh_target as *const u8) };
    let hook = unsafe { VehHook::install(target, detour as *const u8) }.expect("install");
    let found = unsafe_check(veh_target as *const u8);
    hook.unhook().unwrap();

    let found = found
        .expect("check")
        .expect("the hardware breakpoint is found");
    assert_eq!(found.kind, DetectedHookKind::HardwareBreakpoint);
    assert_eq!(found.address, target as *const u8);
    assert_eq!(unsafe_check(veh_target as *const u8), Ok(None));
}

#[test]
fn iat_hook_is_found_by_a_module_scan() {
    let _serial = serial();
    // Called once so the test binary imports it.
    assert_ne!(
        unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() },
        0
    );
    let exe = unsafe { GetModuleHandleW(std::ptr::null()) };
    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();
    tx.attach_iat(
        exe,
        "KERNEL32.dll",
        "GetCurrentProcessId",
        export_detour as *const u8,
    )
    .expect("attach_iat");
    let hooks = tx.commit().expect("commit");

    let found = scan_module_hooks(&exe_name());
    drop(hooks);

    let found = found.expect("scan");
    let hook = found
        .iter()
        .find(|h| h.kind == DetectedHookKind::ImportRedirect)
        .expect("the import redirect is found");
    assert!(
        hook.function
            .as_deref()
            .is_some_and(|f| f.ends_with("!GetCurrentProcessId")),
        "{hook:?}"
    );
    assert_eq!(hook.destination, Some(export_detour as *const u8));
    assert_eq!(hook.destination_module, Some(exe_name()));
    assert_eq!(
        found.len(),
        1,
        "nothing else in the test binary is hooked: {found:?}"
    );
}

#[test]
fn eat_hook_is_found() {
    let _serial = serial();
    // A module nothing else in this test binary loads.
    let module = "winmm.dll";
    assert!(neohook::find_function(module, "timeGetTime").is_some());
    let h_module = get_module_handle(module).expect("loaded");

    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();
    tx.attach_eat(h_module, "timeGetTime", export_detour as *const u8)
        .expect("attach_eat");
    let hooks = tx.commit().expect("commit");

    let found = check_export(module, "timeGetTime");
    let scanned = scan_module_hooks(module);
    drop(hooks);

    let hook = found.expect("check").expect("the export redirect is found");
    assert_eq!(hook.kind, DetectedHookKind::ExportRedirect);
    assert_eq!(hook.function.as_deref(), Some("timeGetTime"));
    let scanned = scanned.expect("scan");
    assert!(
        scanned
            .iter()
            .any(|h| h.kind == DetectedHookKind::ExportRedirect
                && h.function.as_deref() == Some("timeGetTime")),
        "{scanned:?}"
    );
    assert_eq!(check_export(module, "timeGetTime"), Ok(None));
}

#[test]
fn unhooked_modules_scan_clean() {
    let _serial = serial();
    // Nothing hooks the test binary itself.
    assert_eq!(scan_module_hooks(&exe_name()), Ok(vec![]));
    // System DLLs can carry real hooks on a machine with security software, so
    // only check that scanning them works.
    for module in ["ntdll.dll", "kernel32.dll", "kernelbase.dll"] {
        assert!(scan_module_hooks(module).is_ok(), "{module}");
    }
}
