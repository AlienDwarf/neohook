// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A callable "gateway" to the original function for breakpoint-style hooks.
//!
//! [`crate::veh::VehHook`] and [`crate::int3::Int3Hook`] redirect a function by
//! trapping at its entry rather than overwriting the prologue with a jump. That
//! makes them *full-replacement* hooks: the detour runs *instead of* the
//! original, with no obvious way to call through to it. Calling the target again
//! from the detour on the same thread would simply re-hit the trap and recurse.
//!
//! A gateway closes that gap. It is a small executable stub that holds a
//! relocated copy of the function's first instruction(s) followed by a jump back
//! into the body, exactly like an inline-hook trampoline:
//!
//! ```text
//! gateway:
//!     <relocated first instruction(s)>   ; e.g. push rbp / mov edi, edi
//!     jmp  target + L                    ; resume in the original body
//! ```
//!
//! Calling the gateway is therefore equivalent to calling the original
//! function, and crucially the instruction pointer is **never** equal to
//! `target` while running through it - so neither the INT3 byte nor the armed
//! hardware breakpoint at `target` is hit, and there is no recursion.
//!
//! Because the gateway is built from the bytes at `target`, those bytes must
//! still be the *original* instructions when it is constructed. INT3 hooks build
//! the gateway before they write the `0xCC`; VEH hooks never modify the bytes at
//! all.

use crate::alloc::{Trampoline, TrampolineAlloc};
use crate::disasm::Disassembler;

/// Capacity reserved for the gateway stub. The first instruction is at most
/// 15 bytes, relocation may widen a short branch to a 5-byte `rel32`, and the
/// appended jump back is at most 14 bytes - well under this budget (the actual
/// allocation is page-granular, so it is never the limiting factor).
const GATEWAY_CAPACITY: usize = 64;

/// Builds a gateway near `target` that runs the function's original prologue and
/// resumes in its body, returning an owned [`Trampoline`] whose `ptr` is the
/// callable original. The memory is freed when the returned value is dropped.
///
/// Returns `None` if the prologue cannot be measured, no memory is free within
/// jump range, the instructions cannot be relocated, or the page cannot be made
/// executable.
///
/// # Safety
///
/// `target` must point at the entry of a real function whose bytes are the
/// unmodified original instructions (the caller must build the gateway before
/// applying any byte patch).
pub(crate) unsafe fn build_original_gateway(target: *const u8) -> Option<Trampoline> {
    if target.is_null() {
        return None;
    }

    // Measure the first instruction. The gateway relocates whole instructions
    // and jumps back to `target + len`, so execution never lands on the patched
    // entry byte (INT3) or the armed address (VEH).
    let len = unsafe { Disassembler::get_instruction_len(target, 1) }.ok()?;

    let tramp = unsafe { TrampolineAlloc::alloc_nearby_trampoline(target, GATEWAY_CAPACITY) }?;

    // Relocate the prologue into the stub and append a jump back to the body.
    unsafe { Disassembler::relocate(target, tramp.ptr, len) }.ok()?;

    if !tramp.make_rx() {
        return None;
    }

    Some(tramp)
}
