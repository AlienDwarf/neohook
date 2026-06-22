// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Resolving relative references found by a signature scan.
//!
//! A [`crate::scan`] match usually lands on an instruction that *references* the
//! address you actually want rather than being it - a `call rel32` into the
//! function, or a `lea rax, [rip + disp32]` / `mov rax, [rip + disp32]` that
//! loads a global. On x86_64 these encodings are position-dependent, so the
//! bytes you matched do not contain the absolute target; you have to add the
//! displacement to the address *after* the instruction.
//!
//! These helpers do exactly that, either by decoding the instruction with
//! `iced-x86` ([`resolve_call_target`], [`resolve_rip_relative`]) or - when you
//! already know the exact encoding - by reading the displacement field directly
//! ([`resolve_relative`]).
//!
//! ```rust,ignore
//! use neohook::{Pattern, scan_module_by_name, resolve_call_target};
//!
//! // Signature lands on `call InitWorld` inside the caller.
//! let pat = Pattern::parse("E8 ?? ?? ?? ??").unwrap();
//! let call_site = scan_module_by_name("game.dll", &pat).unwrap();
//!
//! // Follow the relative call to the real function entry, then hook that.
//! let init_world = unsafe { resolve_call_target(call_site) }.unwrap();
//! ```

use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind};

/// Bitness of the current target architecture.
fn bitness() -> u32 {
    #[cfg(target_arch = "x86")]
    {
        32
    }
    #[cfg(target_arch = "x86_64")]
    {
        64
    }
}

/// Decodes a single instruction at `addr`, bounded by the committed region that
/// contains it so the decoder never reads unmapped memory. Returns `None` if the
/// address is not in readable memory or the bytes do not decode.
unsafe fn decode_one(addr: *const u8) -> Option<Instruction> {
    if addr.is_null() {
        return None;
    }

    // x86/x64 instructions are at most 15 bytes; never read past the region.
    let readable = unsafe { crate::disasm::readable_bytes_from(addr) };
    if readable == 0 {
        return None;
    }
    let read_len = readable.min(15);

    let slice = unsafe { std::slice::from_raw_parts(addr, read_len) };
    let mut decoder = Decoder::with_ip(bitness(), slice, addr as u64, DecoderOptions::NONE);
    if !decoder.can_decode() {
        return None;
    }
    let instr = decoder.decode();
    if instr.is_invalid() {
        return None;
    }
    Some(instr)
}

/// Resolves the absolute target of a near branch (`call`/`jmp`/`jcc rel`) at
/// `addr`.
///
/// Decodes the instruction at `addr`; if its first operand is a relative branch
/// target (`E8`/`E9`/`0F 8x`/`EB ...`), returns the absolute address it points
/// to. Returns `None` if `addr` is not readable, does not decode, or is not a
/// near-branch instruction.
///
/// # Safety
/// `addr` must point into this process's address space (it is only read, never
/// executed).
pub unsafe fn resolve_call_target(addr: *const u8) -> Option<*const u8> {
    let instr = unsafe { decode_one(addr)? };
    match instr.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(instr.near_branch_target() as *const u8)
        }
        _ => None,
    }
}

/// Resolves the absolute address referenced by a RIP-relative memory operand at
/// `addr` (e.g. `lea rax, [rip + disp32]` or `mov rax, [rip + disp32]`).
///
/// Decodes the instruction at `addr`; if it has a RIP-relative memory operand,
/// returns the absolute address `(end of instruction) + disp32`. Returns `None`
/// if `addr` is not readable, does not decode, or has no RIP-relative operand
/// (e.g. on x86, where there is no RIP-relative addressing).
///
/// # Safety
/// `addr` must point into this process's address space (it is only read, never
/// executed).
pub unsafe fn resolve_rip_relative(addr: *const u8) -> Option<*const u8> {
    let instr = unsafe { decode_one(addr)? };
    if instr.is_ip_rel_memory_operand() {
        Some(instr.memory_displacement64() as *const u8)
    } else {
        None
    }
}

/// Resolves a relative reference from its raw encoding, without decoding.
///
/// Use this when you already know the instruction layout: `disp_offset` is the
/// byte offset of the signed 32-bit displacement within the instruction, and
/// `instr_len` is the total instruction length. The result is
/// `addr + instr_len + disp32`, matching how x86/x64 computes a RIP-relative or
/// near-branch target (the displacement is relative to the *end* of the
/// instruction).
///
/// For example, a `call rel32` is `E8 <rel32>`, so `disp_offset = 1` and
/// `instr_len = 5`; a `mov rax, [rip+disp32]` is `48 8B 05 <disp32>`, so
/// `disp_offset = 3` and `instr_len = 7`.
///
/// # Safety
/// `addr` must be readable for at least `disp_offset + 4` bytes.
pub unsafe fn resolve_relative(addr: *const u8, disp_offset: usize, instr_len: usize) -> *const u8 {
    let disp_ptr = unsafe { addr.add(disp_offset) } as *const i32;
    let disp = unsafe { disp_ptr.read_unaligned() } as isize;
    let end = addr as isize + instr_len as isize;
    (end + disp) as *const u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_relative_matches_manual_arithmetic() {
        // call rel32 to +0x40: E8 40 00 00 00. End of instruction + 0x40.
        let code: [u8; 5] = [0xE8, 0x40, 0x00, 0x00, 0x00];
        let got = unsafe { resolve_relative(code.as_ptr(), 1, 5) };
        let expected = (code.as_ptr() as isize + 5 + 0x40) as *const u8;
        assert_eq!(got, expected);
    }

    #[test]
    fn resolve_relative_handles_negative_displacement() {
        // jmp rel32 backwards by 0x10: E9 F0 FF FF FF.
        let code: [u8; 5] = [0xE9, 0xF0, 0xFF, 0xFF, 0xFF];
        let got = unsafe { resolve_relative(code.as_ptr(), 1, 5) };
        let expected = (code.as_ptr() as isize + 5 - 0x10) as *const u8;
        assert_eq!(got, expected);
    }

    #[test]
    fn resolve_call_target_decodes_relative_call() {
        // E8 00 00 00 00 == call (next instruction). Target = addr + 5.
        let code: [u8; 5] = [0xE8, 0x00, 0x00, 0x00, 0x00];
        let got = unsafe { resolve_call_target(code.as_ptr()) }.expect("should decode a call");
        assert_eq!(got, (code.as_ptr() as usize + 5) as *const u8);
    }

    #[test]
    fn resolve_call_target_rejects_non_branch() {
        // 90 == nop, not a branch.
        let code: [u8; 4] = [0x90, 0x90, 0x90, 0x90];
        assert!(unsafe { resolve_call_target(code.as_ptr()) }.is_none());
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn resolve_rip_relative_decodes_memory_operand() {
        // mov rax, [rip+0] == 48 8B 05 00 00 00 00. Target = addr + 7.
        let code: [u8; 7] = [0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00];
        let got =
            unsafe { resolve_rip_relative(code.as_ptr()) }.expect("should decode a rip-relative");
        assert_eq!(got, (code.as_ptr() as usize + 7) as *const u8);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn resolve_rip_relative_with_displacement() {
        // lea rax, [rip+0x20] == 48 8D 05 20 00 00 00. Target = addr + 7 + 0x20.
        let code: [u8; 7] = [0x48, 0x8D, 0x05, 0x20, 0x00, 0x00, 0x00];
        let got = unsafe { resolve_rip_relative(code.as_ptr()) }.expect("should decode a lea");
        assert_eq!(got, (code.as_ptr() as usize + 7 + 0x20) as *const u8);
    }

    #[test]
    fn resolve_rip_relative_rejects_non_memory_operand() {
        // 90 == nop, no memory operand.
        let code: [u8; 4] = [0x90, 0x90, 0x90, 0x90];
        assert!(unsafe { resolve_rip_relative(code.as_ptr()) }.is_none());
    }

    #[test]
    fn null_pointer_returns_none() {
        assert!(unsafe { resolve_call_target(std::ptr::null()) }.is_none());
        assert!(unsafe { resolve_rip_relative(std::ptr::null()) }.is_none());
    }
}
