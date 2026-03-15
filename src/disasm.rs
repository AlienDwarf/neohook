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
    /// Calculates the total length of instructions at `address` until at least `min_size` bytes are covered.
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
        let read_len = min_size.saturating_add(15).max(15);

        let code_slice = unsafe { std::slice::from_raw_parts(address, read_len) };
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

            if total_bytes >= min_size {
                return Ok(total_bytes);
            }
        }

        Err(
            "Error calculating instruction length: not enough instructions to cover min_size"
                .to_string(),
        )
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

#[cfg(test)]
mod tests {
    use crate::disasm::Disassembler;

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
    fn get_instruction_len_handles_min_size_larger_than_32() {
        let code = [0x90u8; 64]; // 64 NOPs
        let len = unsafe { Disassembler::get_instruction_len(code.as_ptr(), 40) }
            .expect("expected instruction length");
        assert_eq!(len, 40);
    }
}
