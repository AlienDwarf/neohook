// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, Instruction, InstructionBlock,
};

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
}
