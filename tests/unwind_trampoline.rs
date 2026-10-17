// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(all(windows, target_arch = "x86_64"))]

//! Unwinding through a trampoline must reach the caller.
//!
//! The trampoline runs the target's relocated prologue. While a call inside
//! the stolen bytes is running, the return address on the stack points into
//! the trampoline. x64 unwinding needs a `RUNTIME_FUNCTION` for every frame;
//! without one the unwinder treats the trampoline frame as a leaf, reads the
//! wrong return address, and an exception raised below it can never reach a
//! handler above it - the process is torn down instead.
//!
//! The target is generated code with its own unwind data, so its prologue is
//! known exactly: `sub rsp, 0x28; call [rip + slot]; add rsp, 0x28; ret`. The
//! call in it goes to `callee`, which either walks the stack with
//! `RtlVirtualUnwind` or panics (a Rust panic is an SEH exception on Windows).

use neohook::DetourTransaction;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, IMAGE_RUNTIME_FUNCTION_ENTRY, RtlAddFunctionTable, RtlCaptureContext,
    RtlDeleteFunctionTable, RtlLookupFunctionEntry, RtlVirtualUnwind, UNW_FLAG_NHANDLER,
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc, VirtualFree,
};

const CHILD_ENV: &str = "NEOHOOK_UNWIND_TRAMPOLINE_CHILD";
const PANIC_TEST: &str = "a_panic_unwinds_through_a_trampoline";
const TIMEOUT: Duration = Duration::from_secs(30);

const FRAMES: usize = 8;
static WALKED: [AtomicUsize; FRAMES] = [const { AtomicUsize::new(0) }; FRAMES];
static PANIC: AtomicBool = AtomicBool::new(false);

/// Called from the stolen prologue. Records the instruction pointers of the
/// frames above it as the unwinder computes them, or panics.
extern "C-unwind" fn callee() {
    if PANIC.load(Ordering::Relaxed) {
        panic!("unwinding through the trampoline");
    }
    #[repr(align(16))]
    struct Aligned(CONTEXT);
    let mut ctx: Aligned = unsafe { std::mem::zeroed() };
    unsafe { RtlCaptureContext(&mut ctx.0) };
    for slot in &WALKED {
        let mut base = 0u64;
        let function =
            unsafe { RtlLookupFunctionEntry(ctx.0.Rip, &mut base, std::ptr::null_mut()) };
        if function.is_null() {
            // A leaf: the return address is on top of the stack.
            ctx.0.Rip = unsafe { *(ctx.0.Rsp as *const u64) };
            ctx.0.Rsp += 8;
        } else {
            let mut handler_data = std::ptr::null_mut();
            let mut establisher = 0u64;
            unsafe {
                RtlVirtualUnwind(
                    UNW_FLAG_NHANDLER,
                    base,
                    ctx.0.Rip,
                    function,
                    &mut ctx.0,
                    &mut handler_data,
                    &mut establisher,
                    std::ptr::null_mut(),
                )
            };
        }
        slot.store(ctx.0.Rip as usize, Ordering::Relaxed);
    }
}

extern "C-unwind" fn detour() {}

/// Calls `f` (the trampoline), so a return address into this test binary
/// sits above the trampoline frame. Returns whether a panic was caught.
#[inline(never)]
fn driver(f: extern "C-unwind" fn()) -> bool {
    let caught = std::panic::catch_unwind(|| f()).is_err();
    std::hint::black_box(caught)
}

/// Generated code plus its dynamic unwind data, released on drop.
struct Generated {
    page: *mut u8,
    table: *mut IMAGE_RUNTIME_FUNCTION_ENTRY,
}

impl Generated {
    fn new() -> Self {
        let page = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                0x1000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        } as *mut u8;
        assert!(!page.is_null());
        let code: [u8; 20] = [
            0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28
            0xFF, 0x15, 0x36, 0x00, 0x00, 0x00, // call [rip + 0x36] -> page + 0x40
            0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28
            0xC3, // ret
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        ];
        // UNWIND_INFO: version 1, prologue 4 bytes, one code: at offset 4,
        // UWOP_ALLOC_SMALL of (4 + 1) * 8 = 0x28 bytes.
        let unwind_info: [u8; 8] = [0x01, 0x04, 0x01, 0x00, 0x04, 0x42, 0x00, 0x00];
        unsafe {
            std::ptr::copy_nonoverlapping(code.as_ptr(), page, code.len());
            (page.add(0x40) as *mut usize).write(callee as *const () as usize);
            std::ptr::copy_nonoverlapping(unwind_info.as_ptr(), page.add(0x80), 8);
        }
        let table = unsafe { page.add(0xC0) } as *mut IMAGE_RUNTIME_FUNCTION_ENTRY;
        unsafe {
            table.write(std::mem::zeroed());
            (*table).BeginAddress = 0;
            (*table).EndAddress = 15;
            (*table).Anonymous.UnwindData = 0x80;
            assert!(RtlAddFunctionTable(table, 1, page as u64));
        }
        Self { page, table }
    }
}

impl Drop for Generated {
    fn drop(&mut self) {
        unsafe {
            RtlDeleteFunctionTable(self.table);
            VirtualFree(self.page.cast(), 0, MEM_RELEASE);
        }
    }
}

/// Hooks the generated function and calls its trampoline through `driver`.
/// Returns whether a panic was caught, and the trampoline's address.
fn through_trampoline() -> (bool, usize) {
    let generated = Generated::new();
    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();
    let trampoline = tx
        .attach(generated.page, detour as *const u8)
        .expect("attach the generated function");
    let hooks = tx.commit().expect("commit");

    let original: extern "C-unwind" fn() = unsafe { std::mem::transmute(trampoline) };
    let caught = driver(original);
    drop(hooks);
    neohook::reclaim();
    (caught, trampoline as usize)
}

#[test]
fn virtual_unwind_through_a_trampoline_reaches_the_caller() {
    if std::env::var(CHILD_ENV).is_ok() {
        return;
    }
    let (_, trampoline) = through_trampoline();
    let frames: Vec<usize> = WALKED.iter().map(|f| f.load(Ordering::Relaxed)).collect();
    let in_trampoline = frames
        .iter()
        .position(|&f| f > trampoline && f < trampoline + 0x100)
        .unwrap_or_else(|| panic!("no frame in the trampoline: {frames:x?}"));
    // Whatever called the trampoline lives in this test binary.
    let caller = frames[in_trampoline + 1];
    let exe =
        unsafe { windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(std::ptr::null()) };
    let size = neohook::get_module_size(exe) as usize;
    assert!(
        caller >= exe as usize && caller < exe as usize + size,
        "the walk did not get past the trampoline: {frames:x?}"
    );
}

#[test]
fn a_panic_unwinds_through_a_trampoline() {
    if std::env::var(CHILD_ENV).is_ok() {
        PANIC.store(true, Ordering::Relaxed);
        // Silence the panic message; the test checks that it was caught.
        std::panic::set_hook(Box::new(|_| {}));
        let (caught, _) = through_trampoline();
        assert!(caught, "the panic was not caught above the trampoline");
        return;
    }

    let exe = std::env::current_exe().expect("current_exe");
    let mut child = Command::new(exe)
        .args([PANIC_TEST, "--exact", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn child test process");
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("wait for child") {
            assert!(
                status.success(),
                "unwinding through the trampoline killed the process: {status}"
            );
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
