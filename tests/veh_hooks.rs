#![cfg(windows)]

//! Integration tests for VEH (hardware-breakpoint) hooking.

use neohook::VehHook;
use std::sync::mpsc;

#[inline(never)]
extern "system" fn target_fn() -> u32 {
    std::hint::black_box(1234)
}

extern "system" fn detour_fn() -> u32 {
    9999
}

/// Indirect call through the real symbol so the breakpoint actually fires
/// (rather than the optimizer folding in the known return value).
fn call_target() -> u32 {
    let f = std::hint::black_box(target_fn as extern "system" fn() -> u32);
    f()
}

fn target_ptr() -> *const u8 {
    target_fn as *const () as *const u8
}

fn detour_ptr() -> *const u8 {
    detour_fn as *const () as *const u8
}

#[test]
fn veh_hook_redirects_and_restores_on_calling_thread() {
    assert_eq!(call_target(), 1234, "precondition");

    let hook =
        unsafe { VehHook::install(target_ptr(), detour_ptr()) }.expect("install should succeed");
    assert_eq!(hook.target(), target_ptr());
    assert_eq!(hook.detour(), detour_ptr());

    assert_eq!(call_target(), 9999, "calling thread should hit the detour");

    hook.unhook().expect("unhook should succeed");
    assert_eq!(
        call_target(),
        1234,
        "original must be restored after unhook"
    );
}

#[test]
fn veh_hook_drop_restores() {
    {
        let _hook = unsafe { VehHook::install(target_ptr(), detour_ptr()) }
            .expect("install should succeed");
        assert_eq!(call_target(), 9999);
        // _hook drops here, clearing the breakpoint.
    }
    assert_eq!(
        call_target(),
        1234,
        "dropping the guard should restore the original"
    );
}

#[test]
fn veh_hook_covers_threads_that_exist_at_install_time() {
    // A worker thread is spawned first, then parked until after the hook is
    // installed, so it is armed by install-time thread enumeration.
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let (result_tx, result_rx) = mpsc::channel::<u32>();

    let worker = std::thread::spawn(move || {
        // Signal that the thread exists, then wait for the hook to be installed.
        ready_tx.send(()).unwrap();
        go_rx.recv().unwrap();
        result_tx.send(call_target()).unwrap();
    });

    ready_rx.recv().unwrap();

    let hook =
        unsafe { VehHook::install(target_ptr(), detour_ptr()) }.expect("install should succeed");

    go_tx.send(()).unwrap();
    let worker_result = result_rx.recv().unwrap();

    hook.unhook().expect("unhook should succeed");
    worker.join().unwrap();

    assert_eq!(
        worker_result, 9999,
        "a pre-existing thread should also be redirected by the VEH hook"
    );
}

#[test]
fn veh_hook_rejects_null_pointers() {
    assert!(unsafe { VehHook::install(std::ptr::null(), detour_ptr()) }.is_err());
    assert!(unsafe { VehHook::install(target_ptr(), std::ptr::null()) }.is_err());
}
