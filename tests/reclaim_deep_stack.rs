#![cfg(windows)]

//! A retired trampoline a thread will still return into must stay quarantined,
//! even when that return address sits far below the top of the stack.
//!
//! A hook whose stolen bytes contain a `call` relocates that call into the
//! trampoline, so the callee's return address points into the trampoline. If
//! the callee then runs deep, a reclaim pass that only inspects a window above
//! each stack pointer sees no reference and releases the stub; the thread
//! faults with 0xC0000005 the moment it returns.
//!
//! The scenario runs in a child process so that fault is reported as a test
//! failure instead of taking the test runner down with it.

use neohook::DetourTransaction;
use std::arch::naked_asm;
use std::hint::black_box;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Win32::System::Memory::{MEM_FREE, MEMORY_BASIC_INFORMATION, VirtualQuery};

const CHILD_ENV: &str = "NEOHOOK_RECLAIM_DEEP_STACK_CHILD";
const TEST_NAME: &str = "reclaim_keeps_a_trampoline_a_deep_frame_returns_into";
const TIMEOUT: Duration = Duration::from_secs(30);

/// Recursion frames between the parked stack pointer and the return address
/// into the trampoline. Each frame touches 4 KiB, so the return address ends up
/// far past any small fixed scan window.
const FRAMES: usize = 16;

static PARKED: AtomicBool = AtomicBool::new(false);
static RELEASE: AtomicBool = AtomicBool::new(false);
static RETURNED: AtomicBool = AtomicBool::new(false);

/// Recurses `FRAMES` deep, then parks until the main thread releases it.
#[inline(never)]
fn recurse(depth: usize) {
    let mut frame = [0u8; 4096];
    black_box(&mut frame);
    if depth > 0 {
        recurse(depth - 1);
    } else {
        PARKED.store(true, Ordering::Release);
        while !RELEASE.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    black_box(&mut frame);
}

extern "C" fn park_deep() {
    recurse(FRAMES);
}

/// A target whose very first bytes contain a `call`, so the relocated copy of
/// that call lives in the trampoline and the callee returns into it.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn deep_target() {
    naked_asm!(
        // Shadow space plus the 8 bytes that realign the stack for the callee.
        "sub rsp, 40",
        "call {park}",
        "add rsp, 40",
        // Padding so a 14-byte absolute patch also steals the call.
        "mov r10, 0x1122334455667788",
        "ret",
        park = sym park_deep,
    );
}

#[cfg(target_arch = "x86")]
#[unsafe(naked)]
unsafe extern "C" fn deep_target() {
    naked_asm!(
        // Keeps the callee's entry alignment the same as a compiled call site.
        "sub esp, 12",
        "call {park}",
        "add esp, 12",
        "ret",
        park = sym park_deep,
    );
}

extern "C" fn deep_detour() {}

fn scenario() {
    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();
    let tramp = tx
        .attach(
            deep_target as *const () as *mut u8,
            deep_detour as *const () as *const u8,
        )
        .expect("attach the deep target");
    let hooks = tx.commit().expect("commit the deep target");

    let tramp_addr = tramp as usize;
    let call_original: unsafe extern "C" fn() =
        unsafe { std::mem::transmute::<*mut u8, unsafe extern "C" fn()>(tramp) };

    // Calls the original through the trampoline and parks deep inside it.
    let worker = std::thread::spawn(move || {
        unsafe { call_original() };
        RETURNED.store(true, Ordering::Release);
    });

    let start = Instant::now();
    while !PARKED.load(Ordering::Acquire) {
        assert!(start.elapsed() < TIMEOUT, "the worker never parked");
        std::thread::sleep(Duration::from_millis(5));
    }

    // Retires the trampoline, then runs a reclaim pass while the worker still
    // holds a return address into it.
    drop(hooks);
    neohook::reclaim();

    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let queried = unsafe {
        VirtualQuery(
            tramp_addr as *const _,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    assert_ne!(queried, 0, "VirtualQuery on the retired trampoline failed");
    let released = mbi.State == MEM_FREE;

    // Returning into a released trampoline faults and kills the child.
    RELEASE.store(true, Ordering::Release);
    worker.join().expect("worker thread");

    assert!(
        RETURNED.load(Ordering::Acquire),
        "the worker did not return through the trampoline"
    );
    assert!(
        !released,
        "reclaim released a trampoline a parked thread was about to return into"
    );
}

#[test]
fn reclaim_keeps_a_trampoline_a_deep_frame_returns_into() {
    if std::env::var(CHILD_ENV).is_ok() {
        scenario();
        return;
    }

    let exe = std::env::current_exe().expect("current_exe");
    let mut child = Command::new(exe)
        .args([TEST_NAME, "--exact", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn child test process");

    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("wait for child") {
            assert!(status.success(), "child scenario failed: {status}");
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
