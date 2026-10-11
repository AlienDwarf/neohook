// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, FlowControl, Instruction,
    InstructionBlock, MemoryOperand, Mnemonic, OpKind, Register,
};

#[derive(Debug, Clone)]
pub(crate) struct RelocationMapping {
    pub written_len: usize,
    pub old_instruction_offsets: Vec<u32>,
    pub new_instruction_offsets: Vec<u32>,
}

/// Returns how many bytes are readable starting at `address`, bounded by the
/// committed memory region that contains it.
///
/// Returns 0 if the region cannot be queried or is not readable, so callers can
/// avoid dereferencing unmapped memory. A `PAGE_GUARD` page also counts as not
/// readable: reading it would consume the guard and raise
/// `STATUS_GUARD_PAGE_VIOLATION`.
///
/// # Safety
/// `address` only needs to be a value to query; it is never dereferenced here.
pub(crate) unsafe fn readable_bytes_from(address: *const u8) -> usize {
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
        PAGE_WRITECOPY, VirtualQuery,
    };

    const READABLE: u32 = PAGE_READONLY
        | PAGE_READWRITE
        | PAGE_WRITECOPY
        | PAGE_EXECUTE_READ
        | PAGE_EXECUTE_READWRITE
        | PAGE_EXECUTE_WRITECOPY;

    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let written = unsafe {
        VirtualQuery(
            address as *const _,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if written == 0 {
        return 0;
    }

    if mbi.State != MEM_COMMIT
        || (mbi.Protect & READABLE) == 0
        || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0
    {
        return 0;
    }

    let region_end = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
    region_end.saturating_sub(address as usize)
}

/// Provides functionality to disassemble and relocate instructions
pub(crate) struct Disassembler;

impl Disassembler {
    /// Helper function to determine the bitness of the current architecture (32 or 64)
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
    /// Returns `true` if execution never falls through past `instr`, i.e. the
    /// bytes after it are not part of the same straight-line code path: `ret`,
    /// `jmp`, `ud2` and `int 29h` (`__fastfail`).
    ///
    /// `int3` is deliberately *not* a terminator: functions such as
    /// `ntdll!DbgBreakPoint` (`int3; ret`) resume after it.
    fn ends_function(instr: &Instruction) -> bool {
        match instr.flow_control() {
            FlowControl::Return
            | FlowControl::UnconditionalBranch
            | FlowControl::IndirectBranch
            | FlowControl::Exception => true,
            FlowControl::Interrupt => instr.code() == Code::Int_imm8 && instr.immediate8() == 0x29,
            _ => false,
        }
    }

    /// Returns `true` for a direct conditional jump (`jcc`, `loop`, `jrcxz`),
    /// whose target is in this function. An unconditional `jmp` is not counted:
    /// it is just as often a tail jump into the next function.
    fn is_conditional_jump(instr: &Instruction) -> bool {
        instr.flow_control() == FlowControl::ConditionalBranch
            && matches!(
                instr.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            )
    }

    /// Returns `true` for alignment padding emitted between functions:
    /// `int3` and (multi-byte) `nop`.
    fn is_padding(instr: &Instruction) -> bool {
        matches!(instr.mnemonic(), Mnemonic::Int3 | Mnemonic::Nop)
    }

    /// Calculates the total length of instructions at `address` until at least `min_size` bytes are covered.
    ///
    /// If an instruction that ends the function (`ret`, `jmp`, `ud2`, ...) is
    /// reached before `min_size` bytes are covered, the range may only extend
    /// over `int3` / `nop` padding after it. Otherwise the bytes that follow
    /// belong to other code (typically the next function), overwriting them
    /// would corrupt it, and an error is returned. An earlier branch that jumps
    /// past such an instruction (an early-exit `jcc` over a `ret`) shows that
    /// the bytes after it are still this function's, so it does not end the
    /// function there; the relocation retargets that branch.
    ///
    /// # Safety
    /// The caller must ensure that `address` is a valid pointer
    pub unsafe fn get_instruction_len(
        address: *const u8,
        min_size: usize,
    ) -> Result<usize, String> {
        let mut total_bytes = 0;

        // We need enough bytes to reach `min_size` plus at most one full
        // additional instruction (x86/x64 max instruction length = 15 bytes).
        let mut read_len = min_size.saturating_add(15).max(15);

        // Never read past the end of the committed memory region that contains
        // `address`. Without this, a function that sits at the very end of a
        // mapped page makes `from_raw_parts` span into unmapped memory, and
        // decoding it triggers an access violation.
        let readable = unsafe { readable_bytes_from(address) };
        if readable == 0 {
            return Err("Target address is not in readable committed memory".to_string());
        }
        if readable < min_size {
            return Err(
                "Not enough readable bytes at target to cover the required patch size".to_string(),
            );
        }
        read_len = read_len.min(readable);

        let code_slice = unsafe { std::slice::from_raw_parts(address, read_len) };
        let mut decoder = Decoder::with_ip(
            Self::bitness(),
            code_slice,
            address as u64,
            DecoderOptions::NONE,
        );

        // Set once an instruction that ends the function has been decoded;
        // from then on only padding may be covered.
        let mut function_ended = false;
        // Furthest address a conditional jump decoded so far jumps to.
        let mut branch_reach = 0u64;

        // Decode instructions until we have at least min_size bytes or we run out of instructions to decode
        while decoder.can_decode() && total_bytes < min_size {
            let mut instruction = Instruction::default();
            decoder.decode_out(&mut instruction);

            if instruction.is_invalid() {
                return Err(
                    "Invalid instruction encountered while calculating instruction length"
                        .to_string(),
                );
            }

            if function_ended && !Self::is_padding(&instruction) {
                return Err(
                    "Function ends before the required patch size and is not followed by enough padding"
                        .to_string(),
                );
            }

            total_bytes += instruction.len();

            if total_bytes >= min_size {
                return Ok(total_bytes);
            }

            if Self::is_conditional_jump(&instruction) {
                branch_reach = branch_reach.max(instruction.near_branch_target());
            }
            if Self::ends_function(&instruction) && branch_reach < instruction.next_ip() {
                function_ended = true;
            }
        }

        Err(
            "Error calculating instruction length: not enough instructions to cover min_size"
                .to_string(),
        )
    }

    /// Emulates a relative `call` whose target lies inside the stolen range
    /// `[start, end]` (typically the get-PC idiom `call $+5; pop reg`).
    ///
    /// Such a call reads its own return address, so relocating it unchanged
    /// would push an address inside the trampoline and break the
    /// position-independent code that uses it. Instead it is replaced by a
    /// sequence that pushes the **original** return address and jumps to the
    /// target (the relocated copy if the target was stolen, the original code if
    /// it is `end`):
    ///
    /// - x86: `push imm32; jmp target`
    /// - x64: `push imm32` (sign-extended low half); `mov dword [rsp+4], hi`;
    ///   `jmp target`
    ///
    /// Neither sequence modifies flags or registers other than the stack
    /// pointer, matching the `call`. The first instruction keeps the call's IP so
    /// thread IP redirection maps a thread at the call to the start of the
    /// sequence. A target strictly inside the range that is not an instruction
    /// boundary cannot be reproduced and is rejected.
    ///
    /// Returns `None` for any other instruction.
    fn emulate_get_pc_call(
        instr: &Instruction,
        decoded: &[Instruction],
        start: u64,
        end: u64,
        jmp_code: Code,
    ) -> Result<Option<Vec<Instruction>>, String> {
        if !matches!(instr.code(), Code::Call_rel32_32 | Code::Call_rel32_64) {
            return Ok(None);
        }
        let call_target = instr.near_branch_target();
        if call_target < start || call_target > end {
            return Ok(None);
        }
        if call_target != end && !decoded.iter().any(|i| i.ip() == call_target) {
            return Err(
                "Relocation failed: call into the middle of a relocated instruction".to_string(),
            );
        }

        let ret_addr = instr.next_ip();
        let err = |_| "Relocation failed: cannot emulate call to stolen code".to_string();
        let mut seq = Vec::with_capacity(3);
        if instr.code() == Code::Call_rel32_32 {
            seq.push(Instruction::with1(Code::Pushd_imm32, ret_addr as u32).map_err(err)?);
        } else {
            seq.push(Instruction::with1(Code::Pushq_imm32, ret_addr as u32 as i32).map_err(err)?);
            seq.push(
                Instruction::with2(
                    Code::Mov_rm32_imm32,
                    MemoryOperand::with_base_displ(Register::RSP, 4),
                    (ret_addr >> 32) as u32,
                )
                .map_err(err)?,
            );
        }
        seq[0].set_ip(instr.ip());
        seq.push(Instruction::with_branch(jmp_code, call_target).map_err(err)?);
        Ok(Some(seq))
    }

    /// Relocates a block of instructions from `target` to `trampoline`,
    /// adjusting any relative addresses as needed.
    ///
    /// - `target`: The original address of the instructions to relocate.
    /// - `trampoline`: The destination address where the relocated instructions
    ///   will be written.
    /// - `stolen_len`: The number of bytes to relocate from `target`.
    ///
    /// Returns a mapping with the number of bytes written to `trampoline`. This may be
    /// greater than `stolen_len` because an additional jump back to the original
    /// code may be appended.
    ///
    /// # Safety
    ///
    /// - `target` must be valid for reading `stolen_len` consecutive bytes.
    /// - `trampoline` must be valid for writing all relocated bytes produced by
    ///   this function.
    /// - `target` and `trampoline` must not overlap.
    /// - The bytes at `target` must represent valid machine instructions for the
    ///   decoder/encoder
    pub unsafe fn relocate(
        target: *const u8,
        trampoline: *mut u8,
        stolen_len: usize,
    ) -> Result<RelocationMapping, String> {
        let bitness = Self::bitness();
        let code_slice = unsafe { std::slice::from_raw_parts(target, stolen_len) };
        let mut decoder =
            Decoder::with_ip(bitness, code_slice, target as u64, DecoderOptions::NONE);

        let mut decoded = Vec::new();
        let mut old_instruction_offsets = Vec::new();

        while decoder.can_decode() {
            let instr = decoder.decode();
            if instr.is_invalid() {
                return Err("Invalid instruction encountered while relocating".to_string());
            }

            let old_off = instr.ip().checked_sub(target as u64).ok_or_else(|| {
                "Internal relocation error: negative instruction offset".to_string()
            })?;

            let old_off = u32::try_from(old_off).map_err(|_| {
                "Internal relocation error: instruction offset overflow".to_string()
            })?;

            old_instruction_offsets.push(old_off);
            decoded.push(instr);
        }

        let return_addr = target as u64 + stolen_len as u64;
        let jmp_code = if bitness == 64 {
            Code::Jmp_rel32_64
        } else {
            Code::Jmp_rel32_32
        };

        // The block handed to the encoder. An original instruction may expand to
        // several block instructions; `block_index[i]` is the block index of the
        // first one emitted for original instruction `i`, which carries its
        // original IP so branches to it (and the offset map) resolve to it.
        let mut instructions = Vec::with_capacity(decoded.len() + 4);
        let mut block_index = Vec::with_capacity(decoded.len());
        for instr in &decoded {
            block_index.push(instructions.len());
            if let Some(seq) =
                Self::emulate_get_pc_call(instr, &decoded, target as u64, return_addr, jmp_code)?
            {
                instructions.extend(seq);
            } else {
                instructions.push(*instr);
            }
        }

        let jmp_back = Instruction::with_branch(jmp_code, return_addr)
            .map_err(|_| "Error while creating JMP back".to_string())?;
        instructions.push(jmp_back);

        let block = InstructionBlock::new(&instructions, trampoline as u64);
        let result = BlockEncoder::encode(
            bitness,
            block,
            BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
        )
        .map_err(|e| format!("Relocation failed: {}", e))?;

        if result.new_instruction_offsets.len() < instructions.len() {
            return Err(
                "Relocation failed: encoder returned incomplete instruction offsets".to_string(),
            );
        }

        let new_instruction_offsets: Vec<u32> = block_index
            .iter()
            .map(|&i| result.new_instruction_offsets[i])
            .collect();

        // `iced` reports `u32::MAX` for an original instruction it could not place
        // at a tracked offset - e.g. a short-only branch (`jrcxz`/`jcxz`/`loop`)
        // whose target is out of `rel8` range and which has no longer form. Such a
        // relocation is not faithfully representable: the trampoline body would be
        // wrong and the old->new offset map would be poisoned. Refuse it so the
        // hook fails cleanly (RelocationFailed) instead of installing a corrupt
        // trampoline. (Found by the relocator fuzzer.)
        if new_instruction_offsets.contains(&u32::MAX) {
            return Err(
                "Relocation failed: an instruction could not be re-encoded (short-only branch out of range)"
                    .to_string(),
            );
        }

        unsafe {
            std::ptr::copy_nonoverlapping(
                result.code_buffer.as_ptr(),
                trampoline,
                result.code_buffer.len(),
            );
        }

        Ok(RelocationMapping {
            written_len: result.code_buffer.len(),
            old_instruction_offsets,
            new_instruction_offsets,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::disasm::Disassembler;

    #[test]
    fn get_instruction_len_continues_past_a_ret_a_branch_jumps_over() {
        // stc; jc +1; ret; mov eax, 42; ret
        let code = [0xF9u8, 0x72, 0x01, 0xC3, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3];
        let len = unsafe { Disassembler::get_instruction_len(code.as_ptr(), 5) };
        assert_eq!(len, Ok(9));
        // Without the branch the ret ends the function.
        let code = [0xF9u8, 0x90, 0x90, 0xC3, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3];
        assert!(unsafe { Disassembler::get_instruction_len(code.as_ptr(), 5) }.is_err());
    }

    #[test]
    fn get_instruction_len_stops_at_a_ret_after_a_conditional_tail_call() {
        // test ecx, ecx; jne +0x1000 (another function); xor eax, eax; ret;
        // then the next function: mov eax, 42; ret.
        let mut code = [0xCCu8; 48];
        code[..17].copy_from_slice(&[
            0x85, 0xC9, 0x0F, 0x85, 0x00, 0x10, 0x00, 0x00, 0x31, 0xC0, 0xC3, 0xB8, 0x2A, 0x00,
            0x00, 0x00, 0xC3,
        ]);
        // A 14-byte patch would run into the next function.
        assert!(unsafe { Disassembler::get_instruction_len(code.as_ptr(), 14) }.is_err());
    }

    #[test]
    fn get_instruction_len_on_nops() {
        let code = [0x90u8; 32]; // NOPs
        let len = unsafe { Disassembler::get_instruction_len(code.as_ptr(), 5) }
            .expect("expected instruction length");
        assert_eq!(len, 5);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn get_instruction_len_respects_instruction_boundaries_x64() {
        let mut code = [0x90u8; 32];
        code[0..4].copy_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28

        let len = unsafe { Disassembler::get_instruction_len(code.as_ptr(), 3) }
            .expect("expected instruction length");
        assert_eq!(len, 4);
    }

    #[test]
    fn relocate_appends_jump_back() {
        let code = [0x90u8, 0x90, 0x90, 0x90, 0x90];
        let mut tramp = [0u8; 64];

        let written =
            unsafe { Disassembler::relocate(code.as_ptr(), tramp.as_mut_ptr(), code.len()) }
                .expect("relocation should succeed");

        assert!(
            written.written_len > code.len(),
            "expected appended jump-back"
        );
    }

    #[test]
    fn relocate_preserves_relative_call_target() {
        use iced_x86::{Decoder, DecoderOptions};

        // call $+0x15: a target outside the stolen range stays a call to it.
        let mut code = [0x90u8; 32];
        code[..5].copy_from_slice(&[0xE8, 0x10, 0x00, 0x00, 0x00]);
        let mut tramp = [0u8; 64];

        unsafe {
            Disassembler::relocate(code.as_ptr(), tramp.as_mut_ptr(), 5)
                .expect("relocation should succeed");
        }

        #[cfg(target_arch = "x86_64")]
        let bitness = 64;
        #[cfg(target_arch = "x86")]
        let bitness = 32;

        let mut decoder =
            Decoder::with_ip(bitness, &tramp, tramp.as_ptr() as u64, DecoderOptions::NONE);

        let instr = decoder.decode();
        assert_eq!(instr.mnemonic(), iced_x86::Mnemonic::Call);
        assert_eq!(instr.near_branch_target(), code.as_ptr() as u64 + 0x15);
    }

    #[test]
    fn disassembler_returns_expected_instruction_lengths() {
        let code: [u8; 10] = [0x90, 0x90, 0xB8, 0xAA, 0xBB, 0xCC, 0xDD, 0x90, 0x90, 0x90];
        let ptr = code.as_ptr();

        unsafe {
            assert_eq!(Disassembler::get_instruction_len(ptr, 1).unwrap(), 1);
            assert_eq!(Disassembler::get_instruction_len(ptr, 2).unwrap(), 2);
            assert_eq!(Disassembler::get_instruction_len(ptr, 3).unwrap(), 7);
        }
    }

    #[test]
    fn relocate_returns_instruction_offset_mapping() {
        let code = [0x90u8, 0x90, 0x90, 0x90, 0x90];
        let mut tramp = [0u8; 64];

        let mapping =
            unsafe { Disassembler::relocate(code.as_ptr(), tramp.as_mut_ptr(), code.len()) }
                .expect("relocation should succeed");

        assert_eq!(mapping.old_instruction_offsets, vec![0, 1, 2, 3, 4]);
        assert_eq!(mapping.new_instruction_offsets, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn relocate_preserves_rip_relative_memory_operand() {
        use iced_x86::{Decoder, DecoderOptions};

        // mov rax, [rip+0]  =>  48 8B 05 00 00 00 00
        // The effective address is (end of this instruction) + disp32.
        let code = [0x48u8, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00];
        let mut tramp = [0u8; 64];

        let original_target = code.as_ptr() as u64 + code.len() as u64;

        unsafe {
            Disassembler::relocate(code.as_ptr(), tramp.as_mut_ptr(), code.len())
                .expect("relocation should succeed");
        }

        let mut decoder = Decoder::with_ip(64, &tramp, tramp.as_ptr() as u64, DecoderOptions::NONE);
        let instr = decoder.decode();

        assert!(
            instr.is_ip_rel_memory_operand(),
            "relocated instruction should still be RIP-relative"
        );
        assert_eq!(
            instr.memory_displacement64(),
            original_target,
            "RIP-relative operand must still resolve to the same absolute address after relocation"
        );
    }

    /// Allocates a page of `nop`s ending in `ret` and protects it with
    /// `protect`.
    unsafe fn code_page(protect: u32) -> *mut u8 {
        use windows_sys::Win32::System::Memory::{
            MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualProtect,
        };
        unsafe {
            let page = VirtualAlloc(
                std::ptr::null(),
                4096,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ) as *mut u8;
            assert!(!page.is_null(), "setup allocation failed");
            std::ptr::write_bytes(page, 0x90, 4096);
            *page.add(4095) = 0xC3;
            let mut old = 0u32;
            assert_ne!(VirtualProtect(page as _, 4096, protect, &mut old), 0);
            page
        }
    }

    unsafe fn protect_of(addr: *const u8) -> u32 {
        use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQuery};
        unsafe {
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let q = VirtualQuery(
                addr as _,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            assert_ne!(q, 0, "VirtualQuery failed");
            mbi.Protect
        }
    }

    /// Reading a guard page consumes its guard (and raises
    /// STATUS_GUARD_PAGE_VIOLATION), so guard and no-access pages must not be
    /// reported as readable, and hooking into one must fail without touching it.
    #[test]
    fn guard_and_noaccess_pages_are_not_readable() {
        use windows_sys::Win32::System::Memory::{
            MEM_RELEASE, PAGE_EXECUTE_READ, PAGE_GUARD, PAGE_NOACCESS, VirtualFree,
        };
        extern "C" fn detour() {}
        for protect in [PAGE_EXECUTE_READ | PAGE_GUARD, PAGE_NOACCESS] {
            unsafe {
                let page = code_page(protect);
                assert_eq!(
                    super::readable_bytes_from(page),
                    0,
                    "protection {protect:#x} must not count as readable"
                );
                assert!(Disassembler::get_instruction_len(page, 5).is_err());

                let mut tx = crate::DetourTransaction::begin();
                let res = tx.attach(page, detour as *const u8);
                tx.abort();
                assert!(res.is_err(), "attach must fail cleanly, got {res:?}");

                assert_eq!(
                    protect_of(page),
                    protect,
                    "the page protection (guard bit) must be untouched"
                );
                assert_ne!(VirtualFree(page as _, 0, MEM_RELEASE), 0);
            }
        }
    }

    #[test]
    fn get_instruction_len_handles_min_size_larger_than_32() {
        let code = [0x90u8; 64]; // 64 NOPs
        let len = unsafe { Disassembler::get_instruction_len(code.as_ptr(), 40) }
            .expect("expected instruction length");
        assert_eq!(len, 40);
    }

    // ------------------------------------------------------------------------
    // Fuzzing harness for the relocator.
    //
    // Relocation is the single most dangerous operation in the library: it
    // decodes build-controlled bytes from a function prologue and
    // re-encodes them somewhere else. A subtle bug here corrupts a live process.
    // These harnesses hammer `relocate` / `get_instruction_len` with a corpus of
    // real instruction sequences plus byte-level mutations and assert hard
    // invariants. The heavy random pass is `#[ignore]` (run on demand / on a
    // schedule) so CI stays deterministic; a fast curated pass runs by default.
    //
    // Run the deep fuzzer with, e.g.:
    //   cargo test --release fuzz_relocate_deep -- --ignored --nocapture
    // ------------------------------------------------------------------------

    /// A run of real instruction bytes that decode on both x86 and x86_64
    /// (the harness decodes with the host bitness via `Disassembler::bitness`).
    fn corpus() -> Vec<Vec<u8>> {
        vec![
            vec![0x90],                                     // nop
            vec![0x66, 0x90],                               // 66 nop
            vec![0x0F, 0x1F, 0x00],                         // nop dword [rax]
            vec![0xF3, 0x0F, 0x1E, 0xFA],                   // endbr64
            vec![0x8B, 0xFF],                               // mov edi, edi (hotpatch)
            vec![0x55],                                     // push rbp/ebp
            vec![0x53, 0x56, 0x57],                         // push rbx; push rsi; push rdi
            vec![0x48, 0x89, 0xE5],                         // mov rbp, rsp
            vec![0x48, 0x83, 0xEC, 0x28],                   // sub rsp, 0x28
            vec![0x48, 0x89, 0x4C, 0x24, 0x08],             // mov [rsp+8], rcx
            vec![0x4C, 0x8B, 0xDC],                         // mov r11, rsp
            vec![0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00], // lea rax, [rip+0x10]
            vec![0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00], // mov rax, [rip+0]
            vec![0xE8, 0x00, 0x00, 0x00, 0x00],             // call rel32
            vec![0xE9, 0x11, 0x22, 0x33, 0x44],             // jmp rel32
            vec![0xEB, 0x10],                               // jmp rel8
            vec![0x74, 0x05],                               // je rel8
            vec![0x75, 0xFB],                               // jne rel8 (backward)
            vec![0x0F, 0x84, 0x00, 0x00, 0x00, 0x00],       // je rel32
            vec![0xB8, 0xAA, 0xBB, 0xCC, 0xDD],             // mov eax, imm32
            vec![0x31, 0xC0],                               // xor eax, eax
            vec![0x48, 0x85, 0xC9],                         // test rcx, rcx
            vec![0xC3],                                     // ret
            // A realistic multi-instruction prologue.
            vec![
                0x48, 0x89, 0x5C, 0x24, 0x08, // mov [rsp+8], rbx
                0x57, // push rdi
                0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
            ],
        ]
    }

    /// Deterministic xorshift64* PRNG - reproducible fuzzing without a dep.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// Outcome of a single guarded `relocate` call.
    enum RelocOutcome {
        Panicked,
        Ok { written_len: usize },
        Err,
    }

    /// Calls `relocate` into a canary-guarded buffer, catching panics and
    /// detecting any write past the declared capacity.
    fn relocate_guarded(input: &[u8]) -> RelocOutcome {
        const CAP: usize = 512;
        const GUARD: usize = 256;
        let mut buf = vec![0u8; CAP + GUARD];
        for b in &mut buf[CAP..] {
            *b = 0xAA;
        }
        let tramp = buf.as_mut_ptr();
        let src = input.to_vec(); // exact-size source: relocate reads `len` bytes
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            Disassembler::relocate(src.as_ptr(), tramp, src.len())
        }));
        match res {
            Err(_) => RelocOutcome::Panicked,
            Ok(Err(_)) => RelocOutcome::Err,
            Ok(Ok(mapping)) => {
                // No write may touch the guard region.
                assert!(
                    buf[CAP..].iter().all(|&b| b == 0xAA),
                    "relocate wrote past the {CAP}-byte trampoline budget (guard corrupted) \
                     for input {input:02X?}"
                );
                assert!(
                    mapping.written_len <= CAP,
                    "written_len {} exceeds budget for input {input:02X?}",
                    mapping.written_len
                );
                assert_eq!(
                    mapping.old_instruction_offsets.len(),
                    mapping.new_instruction_offsets.len(),
                    "offset vectors must align for input {input:02X?}"
                );
                for &off in &mapping.new_instruction_offsets {
                    assert!(
                        (off as usize) < mapping.written_len,
                        "new offset {off} out of bounds for input {input:02X?}"
                    );
                }
                RelocOutcome::Ok {
                    written_len: mapping.written_len,
                }
            }
        }
    }

    /// `get_instruction_len` over-reads up to 15 bytes past `min_size` by design
    /// (real code is followed by more code), so feed it a padded buffer and only
    /// assert it never panics and returns a sane length.
    fn instr_len_guarded(input: &[u8]) {
        let mut padded = input.to_vec();
        padded.extend_from_slice(&[0x90; 32]); // trailing real instructions
        let max_min = input.len().max(1);
        for min in 1..=max_min {
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                Disassembler::get_instruction_len(padded.as_ptr(), min)
            }));
            match res {
                Err(_) => panic!("get_instruction_len panicked: input={input:02X?} min={min}"),
                Ok(Ok(len)) => assert!(len >= min, "len {len} < min {min} for input {input:02X?}"),
                Ok(Err(_)) => {}
            }
        }
    }

    /// Mutates `bytes` in place with a random byte-level edit.
    fn mutate(rng: &mut Rng, bytes: &mut Vec<u8>) {
        if bytes.is_empty() {
            bytes.push((rng.next() & 0xFF) as u8);
            return;
        }
        match rng.below(5) {
            0 => {
                let i = rng.below(bytes.len());
                bytes[i] ^= 1 << (rng.below(8));
            }
            1 => {
                let i = rng.below(bytes.len());
                bytes[i] = (rng.next() & 0xFF) as u8;
            }
            2 if bytes.len() > 1 => {
                bytes.remove(rng.below(bytes.len()));
            }
            3 if bytes.len() < 32 => {
                let i = rng.below(bytes.len() + 1);
                bytes.insert(i, (rng.next() & 0xFF) as u8);
            }
            _ => {
                let i = rng.below(bytes.len());
                let j = rng.below(bytes.len());
                bytes.swap(i, j);
            }
        }
    }

    /// Fast, deterministic invariant pass over the curated corpus - always runs.
    #[test]
    fn relocate_corpus_invariants_hold() {
        for input in corpus() {
            instr_len_guarded(&input);
            match relocate_guarded(&input) {
                RelocOutcome::Panicked => {
                    panic!("relocate panicked on a valid corpus entry: {input:02X?}")
                }
                RelocOutcome::Ok { written_len, .. } => {
                    assert!(written_len > 0, "empty relocation for {input:02X?}");
                }
                RelocOutcome::Err => panic!("valid corpus entry failed to relocate: {input:02X?}"),
            }
        }
    }

    /// Resolves the absolute address an instruction points at, **independent of
    /// the encoding form** the relocator chose. iced may re-encode a direct
    /// `call rel32` / `jmp rel32` whose target is far from the trampoline as an
    /// indirect `call/jmp qword [rip+disp]` with the 64-bit target in a literal
    /// pool inside the block - both are correct, so the check must follow either.
    ///
    /// `buf`/`base` are the bytes and base address the instruction was decoded
    /// from (so a literal-pool slot can be read back).
    fn effective_target(instr: &iced_x86::Instruction, buf: &[u8], base: u64) -> u64 {
        use iced_x86::FlowControl;
        let is_branch = matches!(
            instr.flow_control(),
            FlowControl::Call
                | FlowControl::UnconditionalBranch
                | FlowControl::ConditionalBranch
                | FlowControl::IndirectBranch
                | FlowControl::IndirectCall
        );
        if is_branch {
            if instr.is_ip_rel_memory_operand() {
                // call/jmp qword [rip+disp]: target is stored in the literal slot.
                let slot = instr.memory_displacement64();
                let off = (slot - base) as usize;
                u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
            } else {
                instr.near_branch_target()
            }
        } else {
            // RIP-relative data load (lea/mov [rip+disp]): displacement is the target.
            instr.memory_displacement64()
        }
    }

    /// Differential check: relocating a relative branch / RIP-relative load must
    /// preserve the absolute address it points at, whatever encoding form the
    /// relocator emits.
    #[test]
    fn relocate_preserves_absolute_targets() {
        use iced_x86::{Decoder, DecoderOptions};
        let bitness = Disassembler::bitness();

        // Unconditional branches and calls relocate to a single instruction
        // (direct rel, or indirect `[rip+literal]` when out of range), so their
        // absolute target is resolvable from one decode. Conditional branches can
        // expand to an invert+indirect *pair* whose target lives in the second
        // instruction; those are covered by the no-crash / valid-re-decode
        // invariants in the fuzzer rather than this single-instruction check.
        let mut cases: Vec<Vec<u8>> = vec![
            vec![0xE8, 0x10, 0x00, 0x00, 0x00], // call rel32 ($+0x15)
            vec![0xE9, 0x40, 0x00, 0x00, 0x00], // jmp rel32
            vec![0xEB, 0x10],                   // jmp rel8
        ];
        if bitness == 64 {
            cases.push(vec![0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00]); // mov rax,[rip+0]
            cases.push(vec![0x48, 0x8D, 0x0D, 0x34, 0x12, 0x00, 0x00]); // lea rcx,[rip+0x1234]
        }

        for code in cases {
            // Relocate from a *stack* buffer so it is within ±2 GB of the stack
            // trampoline, mirroring NeoHook's near-allocation. A heap source could
            // be >2 GB from the stack, making a RIP-relative data load genuinely
            // un-relocatable (a correct Err, but not what this check is about).
            let mut src = [0x90u8; 32];
            let len = code.len();
            src[..len].copy_from_slice(&code);

            let mut d = Decoder::with_ip(
                bitness,
                &src[..len],
                src.as_ptr() as u64,
                DecoderOptions::NONE,
            );
            let orig = d.decode();
            let want = effective_target(&orig, &src[..len], src.as_ptr() as u64);

            let mut tramp = [0u8; 64];
            let map = unsafe { Disassembler::relocate(src.as_ptr(), tramp.as_mut_ptr(), len) }
                .expect("corpus case should relocate");

            let mut d2 = Decoder::with_ip(
                bitness,
                &tramp[..map.written_len],
                tramp.as_ptr() as u64,
                DecoderOptions::NONE,
            );
            let reloc = d2.decode();
            let got = effective_target(&reloc, &tramp[..map.written_len], tramp.as_ptr() as u64);

            assert_eq!(
                got, want,
                "relocation changed the absolute target for {code:02X?}"
            );
        }
    }

    /// Relocates `call $+5; pop eax/rax; ret` (`stolen_len` bytes of it) from
    /// an executable page into a trampoline on the next page, runs the
    /// trampoline and returns `(source, value it returned, mapping, tramp)`.
    fn run_relocated_get_pc(
        stolen_len: usize,
    ) -> (usize, usize, super::RelocationMapping, Vec<u8>) {
        use windows_sys::Win32::System::Memory::{
            MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc, VirtualFree,
        };
        const CODE: [u8; 7] = [0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0xC3];
        unsafe {
            let base = VirtualAlloc(
                std::ptr::null(),
                0x2000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            ) as *mut u8;
            assert!(!base.is_null(), "setup allocation failed");
            std::ptr::write_bytes(base, 0xCC, 0x2000);
            std::ptr::copy_nonoverlapping(CODE.as_ptr(), base, CODE.len());
            let tramp = base.add(0x1000);

            let map = Disassembler::relocate(base, tramp, stolen_len).expect("relocation failed");
            let run: extern "C" fn() -> usize = std::mem::transmute(tramp);
            let got = run();
            let bytes = std::slice::from_raw_parts(tramp, map.written_len).to_vec();
            assert_ne!(VirtualFree(base as _, 0, MEM_RELEASE), 0);
            (base as usize, got, map, bytes)
        }
    }

    /// The get-PC idiom must read the original return address, not one inside
    /// the trampoline, whether the `pop` was stolen too or not.
    #[test]
    fn relocated_get_pc_sees_original_return_address() {
        for stolen_len in [5, 7] {
            let (src, got, map, tramp) = run_relocated_get_pc(stolen_len);
            assert_eq!(got, src + 5, "stolen_len={stolen_len}");
            assert_eq!(map.new_instruction_offsets[0], 0);
            if stolen_len == 7 {
                assert_eq!(map.old_instruction_offsets, vec![0, 5, 6]);
                assert_eq!(tramp[map.new_instruction_offsets[1] as usize], 0x58);
                assert_eq!(tramp[map.new_instruction_offsets[2] as usize], 0xC3);
            }
        }
    }

    /// A call into the middle of a stolen instruction cannot be reproduced in
    /// the trampoline and must be refused.
    #[test]
    fn relocate_rejects_call_into_middle_of_stolen_instruction() {
        // call $+6 (into the imm32 of the following mov eax, imm32)
        let code = [0xE8u8, 0x01, 0x00, 0x00, 0x00, 0xB8, 0x11, 0x22, 0x33, 0x44];
        let mut tramp = [0u8; 64];
        let res = unsafe { Disassembler::relocate(code.as_ptr(), tramp.as_mut_ptr(), code.len()) };
        assert!(res.is_err(), "got {res:?}");
    }

    /// Regression (found by the relocator fuzzer): `jrcxz`/`jcxz`/`loop*` have no
    /// long form, so when the target is out of `rel8` range from the trampoline
    /// iced reports the new instruction offset as `u32::MAX`. `relocate` must then
    /// fail rather than hand back a poisoned offset map / corrupt trampoline.
    #[test]
    fn relocate_rejects_unencodable_short_branch() {
        // jrcxz with a backward displacement, placed far (4 KiB) from the
        // trampoline so the target cannot be reached by an 8-bit branch.
        let mut arena = vec![0x90u8; 8192];
        arena[0] = 0xE3; // jrcxz rel8
        arena[1] = 0x8B; // disp = -117
        let src = arena.as_ptr();
        let tramp = unsafe { arena.as_mut_ptr().add(4096) };

        let res = unsafe { Disassembler::relocate(src, tramp, 2) };
        match res {
            Err(_) => {} // refused - correct
            Ok(map) => assert!(
                !map.new_instruction_offsets.contains(&u32::MAX),
                "relocate returned Ok with an un-encoded (u32::MAX) instruction offset"
            ),
        }
    }

    /// Deep random fuzzer: corpus-seeded mutations, many iterations. `#[ignore]`d
    /// so it runs on demand, not in the default suite. Reproducible via the seed.
    #[test]
    #[ignore = "long-running fuzzer; run manually with --ignored"]
    fn fuzz_relocate_deep() {
        // Override iteration count via NEOHOOK_FUZZ_ITERS; default is substantial.
        let iters: u64 = std::env::var("NEOHOOK_FUZZ_ITERS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2_000_000);
        let seed: u64 = std::env::var("NEOHOOK_FUZZ_SEED")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        eprintln!("fuzz_relocate_deep: iters={iters} seed={seed:#x}");

        let corpus = corpus();
        let mut rng = Rng(seed);
        let mut ok = 0u64;
        let mut errs = 0u64;

        for i in 0..iters {
            // Start from a corpus entry, sometimes splice two, then mutate a few times.
            let mut bytes = corpus[rng.below(corpus.len())].clone();
            if rng.below(4) == 0 {
                bytes.extend_from_slice(&corpus[rng.below(corpus.len())]);
                bytes.truncate(32);
            }
            let edits = 1 + rng.below(4);
            for _ in 0..edits {
                mutate(&mut rng, &mut bytes);
            }
            if bytes.is_empty() {
                continue;
            }

            instr_len_guarded(&bytes);
            match relocate_guarded(&bytes) {
                RelocOutcome::Panicked => {
                    panic!(
                        "FUZZ FAIL: relocate panicked at iter {i} seed={seed:#x} input={bytes:02X?}"
                    )
                }
                RelocOutcome::Ok { .. } => ok += 1,
                RelocOutcome::Err => errs += 1,
            }
        }
        eprintln!("fuzz_relocate_deep done: ok={ok} rejected={errs}");
    }
}
