// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, Instruction, InstructionBlock,
};

#[derive(Debug, Clone)]
pub(crate) struct RelocationMapping {
    pub written_len: usize,
    pub old_instruction_offsets: Vec<u32>,
    pub new_instruction_offsets: Vec<u32>,
}

/// Provides functionality to disassemble and relocate instructions
pub struct Disassembler;

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
    /// Calculates the total length of instructions at `address` until at least `min_size` bytes are covered.
    ///
    /// # Safety
    /// The caller must ensure that `address` is a valid pointer
    pub unsafe fn get_instruction_len(
        address: *const u8,
        min_size: usize,
    ) -> Result<usize, String> {
        let mut total_bytes = 0;

        // We read a buffer of 32 bytes for analysis (x64 instructions are max 15 bytes)
        let code_slice = unsafe { std::slice::from_raw_parts(address, 32) };
        let mut decoder = Decoder::with_ip(
            Self::bitness(),
            code_slice,
            address as u64,
            DecoderOptions::NONE,
        );

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

            total_bytes += instruction.len();

            // We need at least 5 bytes for a JMP rel32, but we can be more flexible and allow any instruction boundary after min_size
            if total_bytes >= min_size {
                return Ok(total_bytes);
            }
        }

        Err(
            "Error calculating instruction length: not enough instructions to cover min_size"
                .to_string(),
        )
    }

    /// Checks if the instruction at `address` is a relative instruction (e.g., JMP, CALL with relative addressing).
    /// This is important because such instructions need to be relocated when moved to a trampoline.
    ///
    /// # Safety
    /// The caller must ensure that `address` is a valid pointer
    pub unsafe fn is_relative(address: *const u8) -> bool {
        let bitness = Self::bitness();
        // We only analyze the first instruction at the address, so we read a buffer of 15 bytes (max instruction length) for analysis
        let code_slice = unsafe { std::slice::from_raw_parts(address, 15) };
        let mut decoder =
            Decoder::with_ip(bitness, code_slice, address as u64, DecoderOptions::NONE);
        let instr = decoder.decode();

        // We check if the instruction has IP-relative memory operands or is a near branch (like JMP or CALL with relative addressing).
        instr.is_ip_rel_memory_operand() || instr.near_branch_target() != 0
    }

    /// Relocates a block of instructions from `target` to `trampoline`,
    /// adjusting any relative addresses as needed.
    ///
    /// - `target`: The original address of the instructions to relocate.
    /// - `trampoline`: The destination address where the relocated instructions
    ///   will be written.
    /// - `stolen_len`: The number of bytes to relocate from `target`.
    ///
    /// Returns the total number of bytes written to `trampoline`. This may be
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
    ) -> Result<usize, String> {
        let bitness = Self::bitness();
        let code_slice = unsafe { std::slice::from_raw_parts(target, stolen_len) };

        // Decode instrcutions until we have at least stolen_len
        let decoder = Decoder::with_ip(bitness, code_slice, target as u64, DecoderOptions::NONE);
        let mut instructions: Vec<Instruction> = decoder.into_iter().collect();

        // Add a jump back to the original at the end (target + stolen_len)
        let return_addr = target as u64 + stolen_len as u64;

        // We need to use a different jump code for x64 if the return address is out of range for a rel32 jump
        let jmp_code = if bitness == 64 {
            Code::Jmp_rel32_64
        } else {
            // x86 standard relative jump (5 bytes)
            Code::Jmp_rel32_32
        };

        let jmp_back = Instruction::with_branch(jmp_code, return_addr)
            .map_err(|_| "Error while creating JMP back")?;

        // iced-x86 automatically calculates the correct relative offset for the jump based on the instruction's IP,
        //so we don't need to manually adjust it here
        instructions.push(jmp_back);

        // Enccode the instructions into the trampoline
        let block = InstructionBlock::new(&instructions, trampoline as u64);
        let result = BlockEncoder::encode(bitness, block, BlockEncoderOptions::NONE)
            .map_err(|e| format!("Relocation failed: {}", e))?;

        // Copy the encoded instructions to the trampoline
        unsafe {
            std::ptr::copy_nonoverlapping(
                result.code_buffer.as_ptr(),
                trampoline,
                result.code_buffer.len(),
            );
        }

        Ok(result.code_buffer.len())
    }
    pub(crate) unsafe fn relocate_with_mapping(
        target: *const u8,
        trampoline: *mut u8,
        stolen_len: usize,
    ) -> Result<RelocationMapping, String> {
        let bitness = Self::bitness();
        let code_slice = unsafe { std::slice::from_raw_parts(target, stolen_len) };
        let mut decoder =
            Decoder::with_ip(bitness, code_slice, target as u64, DecoderOptions::NONE);

        let mut instructions = Vec::new();
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
            instructions.push(instr);
        }

        let original_instruction_count = instructions.len();

        let return_addr = target as u64 + stolen_len as u64;
        let jmp_code = if bitness == 64 {
            Code::Jmp_rel32_64
        } else {
            Code::Jmp_rel32_32
        };

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

        if result.new_instruction_offsets.len() < original_instruction_count {
            return Err(
                "Relocation failed: encoder returned incomplete instruction offsets".to_string(),
            );
        }

        let new_instruction_offsets =
            result.new_instruction_offsets[..original_instruction_count].to_vec();

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
fn is_relative_detects_rel32_call() {
    let code = [0xE8, 0x00, 0x00, 0x00, 0x00]; // call next instruction
    assert!(unsafe { Disassembler::is_relative(code.as_ptr()) });
}

#[test]
fn is_relative_is_false_for_nop() {
    let code = [0x90u8; 15];
    assert!(!unsafe { Disassembler::is_relative(code.as_ptr()) });
}

#[test]
#[cfg(target_arch = "x86_64")]
fn is_relative_detects_rip_relative_memory_operand() {
    let code = [0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00]; // mov rax, [rip+0]
    assert!(unsafe { Disassembler::is_relative(code.as_ptr()) });
}

#[test]
fn relocate_appends_jump_back() {
    let code = [0x90u8, 0x90, 0x90, 0x90, 0x90];
    let mut tramp = [0u8; 64];

    let written = unsafe { Disassembler::relocate(code.as_ptr(), tramp.as_mut_ptr(), code.len()) }
        .expect("relocation should succeed");

    assert!(written > code.len(), "expected appended jump-back");
}

#[test]
fn relocate_preserves_relative_call_target() {
    use iced_x86::{Decoder, DecoderOptions};

    let code = [0xE8, 0x00, 0x00, 0x00, 0x00]; // call next instruction
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
    assert_eq!(instr.near_branch_target(), code.as_ptr() as u64 + 5);
}
