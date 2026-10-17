// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(all(windows, target_arch = "x86_64"))]

//! Unwinding from a mid-hook handler must pass through the stub to the hooked
//! function and on to its caller.
//!
//! The stub is entered by a jump, saves the CPU state on the stack, aligns the
//! stack and calls the handler. Without unwind data for the stub, a walk that
//! starts in the handler - an exception, a debugger's call stack - stops at
//! the stub.

use neohook::{HookContext, MidHook};
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, RtlCaptureContext, RtlLookupFunctionEntry, RtlVirtualUnwind, UNW_FLAG_NHANDLER,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

const FRAMES: usize = 8;
static WALKED: [AtomicUsize; FRAMES] = [const { AtomicUsize::new(0) }; FRAMES];

/// Records the instruction pointers of the frames above the handler as the
/// unwinder computes them.
extern "C" fn handler(_ctx: *mut HookContext) {
    #[repr(align(16))]
    struct Aligned(CONTEXT);
    let mut ctx: Aligned = unsafe { std::mem::zeroed() };
    unsafe { RtlCaptureContext(&mut ctx.0) };
    for slot in &WALKED {
        let mut base = 0u64;
        let function =
            unsafe { RtlLookupFunctionEntry(ctx.0.Rip, &mut base, std::ptr::null_mut()) };
        if function.is_null() {
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

fn in_module(address: usize) -> bool {
    use windows_sys::Win32::System::LibraryLoader::{
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        GetModuleHandleExW,
    };
    let mut module = std::ptr::null_mut();
    unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            address as *const u16,
            &mut module,
        ) != 0
    }
}

/// Start of the function containing `address`, from its unwind data.
fn function_start(address: usize) -> Option<usize> {
    let mut base = 0u64;
    let function =
        unsafe { RtlLookupFunctionEntry(address as u64, &mut base, std::ptr::null_mut()) };
    (!function.is_null()).then(|| base as usize + unsafe { (*function).BeginAddress } as usize)
}

#[inline(never)]
extern "system" fn target(x: u32) -> u32 {
    black_box(x).wrapping_mul(9).wrapping_add(4)
}

#[test]
fn unwinding_from_a_handler_reaches_the_hooked_function_and_its_caller() {
    let site = unsafe { neohook::detour_code_from_pointer(target as *const u8) };
    let hook = unsafe { MidHook::install(site, handler) }.expect("install");
    assert_eq!(black_box(target as extern "system" fn(u32) -> u32)(1), 13);
    hook.unhook().unwrap();

    // The stub is the first frame outside any module.
    let frames: Vec<usize> = WALKED.iter().map(|f| f.load(Ordering::Relaxed)).collect();
    let in_stub = frames
        .iter()
        .position(|&f| f != 0 && !in_module(f))
        .unwrap_or_else(|| panic!("no frame in the stub: {frames:x?}"));
    assert_eq!(
        frames[in_stub + 1],
        site as usize,
        "the stub frame unwinds to the hooked site: {frames:x?}"
    );
    // The next frame is the caller: in this binary, but in another function.
    let exe = unsafe { GetModuleHandleW(std::ptr::null()) };
    let size = neohook::get_module_size(exe) as usize;
    let caller = frames[in_stub + 2];
    assert!(
        caller >= exe as usize && caller < exe as usize + size,
        "the walk did not reach the hooked function's caller: {frames:x?}"
    );
    assert_ne!(
        function_start(caller),
        function_start(site as usize),
        "the walk did not leave the hooked function: {frames:x?}"
    );
}
