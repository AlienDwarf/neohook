// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(windows)]

//! A delay hook whose module is unloaded must drop its stale INT3 hook: it is
//! no longer active, it is installed again when the module is reloaded, and
//! removing it never writes into whatever is mapped at the old address.
//!
//! Each scenario runs in a child process: it needs a process in which
//! `winmm.dll` was never loaded, and the buggy path writes into foreign memory.

use neohook::DelayHook;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::FreeLibrary;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_READWRITE, VirtualAlloc,
    VirtualFree, VirtualQuery,
};

const CHILD_ENV: &str = "NEOHOOK_DELAY_UNLOAD_CHILD";
const TIMEOUT: Duration = Duration::from_secs(30);
const FAKE: u32 = 0xABCD_1234;

type TimeGetTime = unsafe extern "system" fn() -> u32;

unsafe extern "system" fn fake_time() -> u32 {
    FAKE
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn winmm_loaded() -> bool {
    !unsafe { GetModuleHandleW(wide("winmm.dll").as_ptr()) }.is_null()
}

/// Loads winmm.dll and returns its `timeGetTime` export.
fn load_time_get_time() -> TimeGetTime {
    let module = unsafe { LoadLibraryW(wide("winmm.dll").as_ptr()) };
    assert!(!module.is_null(), "winmm.dll should load");
    let proc = unsafe { GetProcAddress(module, c"timeGetTime".as_ptr() as *const u8) }
        .expect("timeGetTime should resolve");
    unsafe { std::mem::transmute(proc) }
}

/// Frees winmm.dll until it is no longer mapped.
fn unload_winmm() {
    for _ in 0..64 {
        let module = unsafe { GetModuleHandleW(wide("winmm.dll").as_ptr()) };
        if module.is_null() {
            return;
        }
        unsafe { FreeLibrary(module) };
    }
    panic!("winmm.dll stays loaded");
}

fn register() -> DelayHook {
    assert!(!winmm_loaded(), "winmm.dll must not be loaded at start");
    unsafe { DelayHook::register("winmm.dll", "timeGetTime", fake_time as *const u8) }
        .expect("register")
}

fn reload_is_hooked_again() {
    let hook = register();
    let time_get_time = load_time_get_time();
    assert!(hook.is_active(), "active after the first load");
    assert_eq!(unsafe { time_get_time() }, FAKE, "first load is hooked");

    unload_winmm();
    assert!(!hook.is_active(), "inactive once the module is unloaded");

    let time_get_time = load_time_get_time();
    assert!(hook.is_active(), "active again after the reload");
    assert_eq!(unsafe { time_get_time() }, FAKE, "reload is hooked again");

    drop(hook);
    assert_ne!(unsafe { time_get_time() }, FAKE, "unhooked after drop");
}

fn drop_after_unload_leaves_old_address_alone() {
    let hook = register();
    let time_get_time = load_time_get_time();
    assert_eq!(unsafe { time_get_time() }, FAKE, "load is hooked");
    let target = time_get_time as usize;

    unload_winmm();

    // Map fresh memory over the old target, as an unrelated allocation might.
    let page = target & !0xFFF;
    let mem = unsafe {
        VirtualAlloc(
            page as *const _,
            0x1000,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    assert!(!mem.is_null(), "the old target range should be free");
    assert!(
        mem as usize <= page,
        "allocation covers the old target page"
    );
    unsafe { std::ptr::write_bytes(page as *mut u8, 0x5A, 0x1000) };

    drop(hook);

    let byte = unsafe { std::ptr::read_volatile(target as *const u8) };
    let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let queried = unsafe {
        VirtualQuery(
            target as *const _,
            &mut info,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    unsafe { VirtualFree(mem, 0, MEM_RELEASE) };

    assert_eq!(byte, 0x5A, "dropping the hook wrote into foreign memory");
    assert_ne!(queried, 0, "VirtualQuery");
    assert_eq!(info.Protect, PAGE_READWRITE, "foreign protection changed");
}

/// Runs `name` in a child process, or `body` if this is that child.
fn run_in_child(name: &str, body: fn()) {
    if std::env::var(CHILD_ENV).is_ok() {
        body();
        return;
    }

    let exe = std::env::current_exe().expect("current_exe");
    let mut child = Command::new(exe)
        .args([name, "--exact", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn child test process");

    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("wait for child") {
            assert!(status.success(), "child failed: {status}");
            return;
        }
        if start.elapsed() > TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("child did not finish within {TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn delay_hook_is_reinstalled_after_module_reload() {
    run_in_child(
        "delay_hook_is_reinstalled_after_module_reload",
        reload_is_hooked_again,
    );
}

#[test]
fn delay_hook_drop_after_unload_leaves_old_address_alone() {
    run_in_child(
        "delay_hook_drop_after_unload_leaves_old_address_alone",
        drop_after_unload_leaves_old_address_alone,
    );
}
