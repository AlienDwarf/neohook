// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! While a commit holds the other threads suspended it must not wait on any
//! lock one of them could own: not one of neohook's own mutexes, and not the
//! process heap lock. Otherwise a thread frozen mid-unhook or mid-allocation
//! wedges the transaction forever.
//!
//! Each race runs in a child process. A deadlock would also freeze any watchdog
//! thread in the same process (the transaction suspends it too), so the parent
//! kills the child and fails once a timeout passes instead.

use crate::DetourTransaction;
use std::hint::black_box;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc,
};

const CHILD_ENV: &str = "NEOHOOK_SUSPEND_WINDOW_CHILD";
const TIMEOUT: Duration = Duration::from_secs(12);
/// Each race stops after this many commits or [`RACE_TIME`], whichever comes
/// first. Without the fix the child hangs within a few rounds.
const ROUNDS: usize = 300;
const RACE_TIME: Duration = Duration::from_secs(6);

/// Runs `body` in a fresh copy of this test binary and fails if it does not
/// finish successfully within [`TIMEOUT`].
fn run_in_child(test_name: &str, body: fn()) {
    let full_name = format!("suspend_window::{test_name}");
    if std::env::var(CHILD_ENV).as_deref() == Ok(full_name.as_str()) {
        body();
        return;
    }

    let exe = std::env::current_exe().expect("current_exe");
    let mut child = Command::new(exe)
        .args([full_name.as_str(), "--exact", "--test-threads=1"])
        .env(CHILD_ENV, &full_name)
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
            panic!("transaction deadlocked: child did not finish within {TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Hooks a scratch function over and over with every other thread suspended,
/// while `background` runs in a loop on another thread.
fn race_against(background: fn()) {
    let target = scratch_function();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_in = Arc::clone(&stop);
    let worker = std::thread::spawn(move || {
        while !stop_in.load(Ordering::Relaxed) {
            background();
        }
    });

    let start = Instant::now();
    for _ in 0..ROUNDS {
        if start.elapsed() > RACE_TIME {
            break;
        }
        let mut tx = DetourTransaction::begin();
        tx.update_all_threads();
        tx.attach(target, detour as *const u8)
            .expect("attach scratch target");
        let hooks = tx.commit().expect("commit scratch target");
        drop(hooks);
    }

    stop.store(true, Ordering::Relaxed);
    worker.join().expect("background thread");
}

/// A never-called function body (a NOP sled ending in `ret`) on its own page.
fn scratch_function() -> *mut u8 {
    let page = unsafe {
        VirtualAlloc(
            std::ptr::null(),
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    } as *mut u8;
    assert!(!page.is_null(), "allocate scratch page");
    unsafe {
        std::ptr::write_bytes(page, 0x90, 32);
        *page.add(32) = 0xC3;
    }
    page
}

#[inline(never)]
extern "system" fn detour(x: u32) -> u32 {
    black_box(x).wrapping_add(20)
}

/// Takes the gateway registry lock over and over, as dropping or unhooking an
/// inline hook does, without holding the transaction lock.
fn churn_gateway_registry() {
    crate::transaction::unregister_managed_gateway(0x1234 as *mut u8);
}

/// Allocates and frees blocks of varying size, so the heap lock is often held
/// at the moment the other thread suspends it.
fn churn_heap() {
    for size in (1..4096).step_by(61) {
        drop(black_box(vec![1u8; size]));
    }
    // Let the committing thread win the heap lock now and then, so it is not
    // merely starved.
    std::thread::yield_now();
}

#[test]
fn commit_survives_concurrent_gateway_registry_use() {
    run_in_child("commit_survives_concurrent_gateway_registry_use", || {
        race_against(churn_gateway_registry)
    });
}

#[test]
fn commit_survives_concurrent_heap_use() {
    run_in_child("commit_survives_concurrent_heap_use", || {
        race_against(churn_heap)
    });
}

/// A one-export PE image in a read-only view of a pagefile section. Its export
/// table is readable but can never be made writable, so an EAT hook on it gets
/// all the way to the slot write and fails there.
#[cfg(target_arch = "x86_64")]
fn read_only_module() -> windows_sys::Win32::Foundation::HMODULE {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Diagnostics::Debug::{
        IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR64_MAGIC,
    };
    use windows_sys::Win32::System::Memory::{
        FILE_MAP_READ, FILE_MAP_WRITE, MapViewOfFile, PAGE_READWRITE,
    };

    // Declared here: windows-sys only exposes it with its `Win32_Security`
    // feature, which the crate does not otherwise need.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileMappingW(
            file: windows_sys::Win32::Foundation::HANDLE,
            attributes: *const core::ffi::c_void,
            protect: u32,
            size_high: u32,
            size_low: u32,
            name: *const u16,
        ) -> windows_sys::Win32::Foundation::HANDLE;
    }
    use windows_sys::Win32::System::SystemServices::{
        IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
    };

    const NT: usize = 0x40;
    const EXPORTS: u32 = 0x200;
    const FUNCTIONS: u32 = 0x300;
    const NAMES: u32 = 0x310;
    const ORDINALS: u32 = 0x320;
    const NAME: u32 = 0x340;

    unsafe {
        let section = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            std::ptr::null(),
            PAGE_READWRITE,
            0,
            0x1000,
            std::ptr::null(),
        );
        assert!(!section.is_null(), "create section");
        let rw = MapViewOfFile(section, FILE_MAP_WRITE, 0, 0, 0).Value as *mut u8;
        assert!(!rw.is_null(), "map writable view");

        let dos = rw as *mut IMAGE_DOS_HEADER;
        (*dos).e_magic = IMAGE_DOS_SIGNATURE;
        (*dos).e_lfanew = NT as i32;
        let nt = rw.add(NT) as *mut IMAGE_NT_HEADERS64;
        (*nt).Signature = IMAGE_NT_SIGNATURE;
        (*nt).OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        (*nt).OptionalHeader.SizeOfImage = 0x1000;
        (*nt).OptionalHeader.NumberOfRvaAndSizes = 16;
        let dir = &mut (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
        dir.VirtualAddress = EXPORTS;
        dir.Size = 0x100;

        let exports = rw.add(EXPORTS as usize) as *mut IMAGE_EXPORT_DIRECTORY;
        (*exports).NumberOfFunctions = 1;
        (*exports).NumberOfNames = 1;
        (*exports).AddressOfFunctions = FUNCTIONS;
        (*exports).AddressOfNames = NAMES;
        (*exports).AddressOfNameOrdinals = ORDINALS;
        *(rw.add(FUNCTIONS as usize) as *mut u32) = 0x800;
        *(rw.add(NAMES as usize) as *mut u32) = NAME;
        *(rw.add(ORDINALS as usize) as *mut u16) = 0;
        let name = c"Fake".to_bytes_with_nul();
        std::ptr::copy_nonoverlapping(name.as_ptr(), rw.add(NAME as usize), name.len());

        let ro = MapViewOfFile(section, FILE_MAP_READ, 0, 0, 0).Value;
        assert!(!ro.is_null(), "map read-only view");
        ro as windows_sys::Win32::Foundation::HMODULE
    }
}

/// An EAT hook whose detour needs a jump stub, and whose slot write fails inside
/// the commit, must not release the stub until the threads run again: that
/// takes the stub quarantine lock, which a suspended thread may hold.
#[cfg(target_arch = "x86_64")]
#[test]
fn failed_eat_write_releases_its_stub_after_resume() {
    run_in_child("failed_eat_write_releases_its_stub_after_resume", || {
        let module = read_only_module();
        let mut tx = crate::transaction::TransactionCore::begin();
        // Below the module base, so the slot cannot encode it and a stub is built.
        tx.attach_eat(module, "Fake", 0x10 as *const u8)
            .expect("attach_eat on the read-only module");

        let held = Arc::new(AtomicBool::new(false));
        let held_in = Arc::clone(&held);
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            tid_tx
                .send(unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() })
                .expect("send thread id");
            crate::reclaim::hold_quarantine(&held_in, Duration::from_secs(1));
        });
        let holder_tid = tid_rx.recv().expect("holder thread id");
        while !held.load(Ordering::Acquire) {
            std::thread::yield_now();
        }

        tx.update_thread(holder_tid).expect("track holder");
        let err = tx.commit().expect_err("the slot write must fail");
        assert!(
            matches!(
                err,
                crate::DetourError::CommitFailed {
                    kind: crate::HookKind::Eat,
                    ..
                }
            ),
            "unexpected error: {err:?}"
        );
        holder.join().expect("holder thread");
    });
}
