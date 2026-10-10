#![cfg(windows)]

//! Every code write lifts the page protection, writes, and puts the saved
//! protection back. Two such writes on the same page from different threads
//! must not interleave: one thread can restore read-only execute while the
//! other is still writing (an access violation), or restore the writable
//! protection the other one saved (a page left writable).
//!
//! Each race runs in a child process, so a crash is reported as a failed test
//! instead of taking the whole test binary down.

use neohook::{DetourTransaction, Hook, Int3Hook};
use std::hint::black_box;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    VirtualAlloc, VirtualProtect, VirtualQuery,
};

const CHILD_ENV: &str = "NEOHOOK_CODE_PAGE_RACE_CHILD";
const TIMEOUT: Duration = Duration::from_secs(20);
const RACE_TIME: Duration = Duration::from_secs(2);
/// Offset of the second function on the shared page.
const SECOND: usize = 0x80;

/// Runs `body` in a fresh copy of this test binary and fails if it crashes,
/// panics, or does not finish within [`TIMEOUT`].
fn run_in_child(test_name: &str, body: fn()) {
    if std::env::var(CHILD_ENV).as_deref() == Ok(test_name) {
        body();
        return;
    }

    let exe = std::env::current_exe().expect("current_exe");
    let mut child = Command::new(exe)
        .args([test_name, "--exact", "--test-threads=1"])
        .env(CHILD_ENV, test_name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn child test process");

    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("wait for child") {
            assert!(status.success(), "child race failed: {status}");
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

/// Two never-called functions (NOP sleds ending in `ret`) on one read-only
/// executable page.
fn shared_page() -> usize {
    unsafe {
        let page = VirtualAlloc(
            std::ptr::null(),
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        ) as *mut u8;
        assert!(!page.is_null(), "allocate shared page");
        for offset in [0, SECOND] {
            std::ptr::write_bytes(page.add(offset), 0x90, 32);
            *page.add(offset + 32) = 0xC3;
        }
        let mut old = 0u32;
        assert_ne!(
            VirtualProtect(page.cast(), 0x1000, PAGE_EXECUTE_READ, &mut old),
            0,
            "make shared page read-only"
        );
        page as usize
    }
}

fn page_protection(page: usize) -> u32 {
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let q = unsafe {
        VirtualQuery(
            page as *const _,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    assert_ne!(q, 0, "VirtualQuery");
    mbi.Protect
}

#[inline(never)]
extern "system" fn detour(x: u32) -> u32 {
    black_box(x).wrapping_add(3)
}

/// Hooks `target`, toggles the hook a few times and unhooks it, over and over.
fn churn_inline(target: usize) {
    let start = Instant::now();
    while start.elapsed() < RACE_TIME {
        let mut tx = DetourTransaction::begin();
        tx.attach(target as *mut u8, detour as *const u8)
            .expect("attach");
        let mut hooks: Vec<Hook> = tx.commit().expect("commit");
        for _ in 0..16 {
            hooks[0].disable().expect("disable");
            hooks[0].enable().expect("enable");
        }
        hooks.pop().expect("one hook").unhook().expect("unhook");
    }
}

/// Installs and removes an INT3 hook on `target`, over and over.
fn churn_int3(target: usize) {
    let start = Instant::now();
    while start.elapsed() < RACE_TIME {
        let hook = unsafe { Int3Hook::install(target as *const u8, detour as *const u8) }
            .expect("install");
        hook.unhook().expect("unhook");
    }
}

fn race(first: fn(usize), second: fn(usize)) {
    let page = shared_page();
    let other = std::thread::spawn(move || second(page + SECOND));
    first(page);
    other.join().expect("second writer");

    assert_eq!(
        page_protection(page),
        PAGE_EXECUTE_READ,
        "a racing write left the code page writable"
    );
}

#[test]
fn inline_hooks_on_one_page_do_not_race() {
    run_in_child("inline_hooks_on_one_page_do_not_race", || {
        race(churn_inline, churn_inline)
    });
}

#[test]
fn inline_and_int3_hooks_on_one_page_do_not_race() {
    run_in_child("inline_and_int3_hooks_on_one_page_do_not_race", || {
        race(churn_inline, churn_int3)
    });
}
