// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Best-effort signature inference: how many arguments a function takes, of
//! roughly which types, and what it returns - from its machine code alone.
//!
//! Writing a detour needs the target's signature. For an undocumented or
//! internal function there is none to copy, and guessing wrong corrupts the
//! stack or the arguments. [`infer_signature`] reads the function's code and
//! reports what the code itself reveals:
//!
//! * **Argument count.** On x64 every argument register (`rcx`, `rdx`, `r8`,
//!   `r9`, `xmm0`-`xmm3`) the function reads before writing it, and every stack
//!   slot above the home space it reads. On x86 the stack slots above the
//!   return address it reads, and the byte count of a `ret N`, which is exact
//!   for callee-cleaned conventions.
//! * **Argument types.** An argument used as an address is a pointer; one read
//!   by `*ss` / `*sd` instructions is a `float` / `double`; otherwise the width
//!   of the register or memory read gives the integer size.
//! * **Return type.** Whether `rax`/`eax` or `xmm0` (or the x87 stack on x86)
//!   is written on the way to a `ret`.
//! * **Calling convention** on x86: `cdecl`, `stdcall`, `fastcall` or
//!   `thiscall`, from `ret N` and the use of `ecx` / `edx`.
//!
//! The analysis follows every path through the function - conditional
//! branches, register copies, spills to the stack and reloads (which is all a
//! debug build does with its arguments). A wrapper that hands its arguments on
//! untouched never reads them itself, so direct and import calls and tail jumps
//! are followed a few levels deep: an argument register the callee reads and
//! the caller has not written is the caller's argument too.
//!
//! ## Limits
//!
//! This is an estimate, not a decompiler. A parameter the function never
//! touches is invisible (except as a gap before a later one), an argument that
//! is only forwarded to a tail call is not seen, a `struct` passed by value
//! looks like an integer, and a variadic function looks like one that takes
//! every register argument. Each argument carries a confidence, and
//! [`SignatureGuess::complete`] is `false` when the analysis had to give up on
//! a path (an indirect jump, a tail call or the instruction budget).
//!
//! ```rust,ignore
//! let sig = neohook::infer_signature_by_name("kernel32.dll", "Sleep")?;
//! println!("{} args, returns {:?}", sig.args.len(), sig.returns);
//! ```

use std::collections::{HashMap, HashSet};
use std::fmt;

use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, MemorySize,
    Mnemonic, OpAccess, OpKind, Register,
};

/// Upper bound on instructions decoded across all paths.
const MAX_STEPS: usize = 20_000;

/// Upper bound on instructions decoded for one callee.
const MAX_CALLEE_STEPS: usize = 4_000;

/// How deep calls are followed to see which arguments a function forwards.
const MAX_DEPTH: u8 = 2;

/// Upper bound on distinct callees analysed per function.
const MAX_CALLEES: usize = 32;

/// Upper bound on the code a function may span, used to tell an internal jump
/// from a tail call where no unwind data says where the function ends.
const MAX_FUNCTION_BYTES: u64 = 0x1_0000;

/// Stack bytes a pointer-sized slot takes.
const WORD: i64 = std::mem::size_of::<usize>() as i64;

/// Entry-relative stack offset of the first stack argument: past the return
/// address, and on x64 past the 32-byte home space as well.
#[cfg(target_arch = "x86_64")]
const FIRST_STACK_ARG: i64 = 0x28;
#[cfg(target_arch = "x86")]
const FIRST_STACK_ARG: i64 = 4;

/// Register arguments of the calling convention in order: Win64 `rcx`, `rdx`,
/// `r8`, `r9` (each paired with `xmm0`-`xmm3`), or x86 `fastcall` `ecx`, `edx`.
#[cfg(target_arch = "x86_64")]
const GP_ARG_REGS: [usize; 4] = [1, 2, 8, 9];
#[cfg(target_arch = "x86")]
const GP_ARG_REGS: [usize; 2] = [1, 2];

/// Number of positional register slots (`xmm` registers share them on x64).
const REG_SLOTS: usize = GP_ARG_REGS.len();

/// The calling convention the code matches.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallingConvention {
    /// The x64 Windows convention (`rcx`, `rdx`, `r8`, `r9`, then the stack).
    Win64,
    /// x86, arguments on the stack, removed by the caller.
    Cdecl,
    /// x86, arguments on the stack, removed by the callee (`ret N`).
    Stdcall,
    /// x86, first two arguments in `ecx` / `edx`, the rest on the stack.
    Fastcall,
    /// x86, `this` in `ecx`, the rest on the stack, removed by the callee.
    Thiscall,
}

/// The rough type of an argument or return value.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ValueKind {
    /// 8-bit integer (`bool`, `char`, `u8`).
    Int8,
    /// 16-bit integer.
    Int16,
    /// 32-bit integer.
    Int32,
    /// 64-bit integer (on x64 possibly a pointer that is never dereferenced).
    Int64,
    /// A pointer: the value is used as an address.
    Pointer,
    /// 32-bit floating point.
    Float,
    /// 64-bit floating point.
    Double,
    /// The argument exists (a later one is used) but nothing reveals its type.
    Unknown,
}

/// Where an argument is passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgLocation {
    /// In a register, named as the convention names it (`"rcx"`, `"xmm1"`).
    Register(&'static str),
    /// On the stack, at this byte offset from the stack pointer at entry.
    Stack(u32),
}

/// One inferred argument.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ArgGuess {
    /// Where the argument is passed.
    pub location: ArgLocation,
    /// Its rough type.
    pub kind: ValueKind,
    /// How sure the analysis is about this argument, from 0.0 to 1.0.
    pub confidence: f32,
}

/// The inferred signature of a function.
#[derive(Clone, Debug, PartialEq)]
pub struct SignatureGuess {
    /// The calling convention the code matches.
    pub convention: CallingConvention,
    /// The arguments, in declaration order.
    pub args: Vec<ArgGuess>,
    /// The return value, or `None` for `void`.
    pub returns: Option<ValueKind>,
    /// Bytes the function removes from the stack on return (`ret N`), x86 only.
    pub stack_cleanup: u32,
    /// `false` if a path could not be followed to its end (an indirect jump, a
    /// tail call, or the instruction budget), so arguments used only there
    /// may be missing.
    pub complete: bool,
}

/// Errors produced by [`infer_signature`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// A null function pointer was supplied.
    NullPointer,
    /// The module could not be loaded or does not have the export
    /// ([`infer_signature_by_name`]).
    NotFound,
    /// The function's code is not readable.
    UnreadableCode,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NullPointer => write!(f, "null function pointer"),
            Self::NotFound => write!(f, "module or export not found"),
            Self::UnreadableCode => write!(f, "function code is not readable"),
        }
    }
}

impl std::error::Error for SignatureError {}

/// Infers the signature of the function at `func` from its machine code.
///
/// Leading jump thunks (an incremental-linking stub, an import thunk) are
/// followed to the real body first.
///
/// # Errors
///
/// [`SignatureError::NullPointer`] for a null `func`, and
/// [`SignatureError::UnreadableCode`] if its first instruction cannot be read.
///
/// # Safety
///
/// `func` must point at the start of a function in mapped memory that stays
/// mapped for the duration of the call.
pub unsafe fn infer_signature(func: *const u8) -> Result<SignatureGuess, SignatureError> {
    if func.is_null() {
        return Err(SignatureError::NullPointer);
    }
    let entry = unsafe { crate::detour_code_from_pointer(func) };
    if entry.is_null() || unsafe { crate::disasm::readable_bytes_from(entry) } == 0 {
        return Err(SignatureError::UnreadableCode);
    }
    let mut analysis = Analysis::new(entry as u64);
    unsafe { analysis.run() };
    Ok(analysis.finish())
}

/// Infers the signature of the export `func` of `module`, loading the module
/// if it is not already present (as [`crate::find_function`] does).
///
/// # Errors
///
/// [`SignatureError::NotFound`] if the module cannot be loaded or does not
/// export `func`, otherwise as [`infer_signature`].
pub fn infer_signature_by_name(module: &str, func: &str) -> Result<SignatureGuess, SignatureError> {
    let address = crate::find_function(module, func).ok_or(SignatureError::NotFound)?;
    // SAFETY: an export of a loaded module is mapped code.
    unsafe { infer_signature(address) }
}

/// What is known about one argument across all paths.
#[derive(Clone, Copy, Default)]
struct Evidence {
    used: bool,
    /// Widest integer read, in bytes.
    width: usize,
    pointer: bool,
    float: bool,
    double: bool,
}

impl Evidence {
    fn merge(&mut self, other: &Evidence) {
        if !other.used {
            return;
        }
        self.used = true;
        self.width = self.width.max(other.width);
        self.pointer |= other.pointer;
        self.float |= other.float;
        self.double |= other.double;
    }

    fn read(&mut self, width: usize) {
        self.used = true;
        self.width = self.width.max(width);
    }

    fn kind(&self) -> ValueKind {
        if self.pointer {
            ValueKind::Pointer
        } else if self.double {
            ValueKind::Double
        } else if self.float {
            ValueKind::Float
        } else {
            match self.width {
                1 => ValueKind::Int8,
                2 => ValueKind::Int16,
                4 => ValueKind::Int32,
                8 => ValueKind::Int64,
                _ => ValueKind::Unknown,
            }
        }
    }

    fn confidence(&self) -> f32 {
        if self.pointer || self.float || self.double {
            0.85
        } else if self.width > 0 {
            0.6
        } else {
            0.3
        }
    }
}

/// Where a value came from: a register argument slot or a stack argument.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Origin {
    /// Register slot `n` (`rcx`/`xmm0` = 0 on x64, `ecx` = 0 on x86).
    Reg(u8),
    /// Stack argument at this entry-relative offset.
    Stack(i64),
}

/// The state of one path through the function.
#[derive(Clone, PartialEq, Eq, Hash)]
struct PathState {
    /// General registers (bits 0-15) and XMM registers (bits 16-31) written
    /// since entry.
    written: u32,
    /// Which argument each register currently holds, if any.
    holds: [Option<Origin>; 32],
    /// For each general register holding a stack address, that address. The
    /// stack pointer starts as the entry anchor; a frame pointer or any other
    /// register copied from it carries it along.
    stack: [Option<Slot>; 16],
    /// Stack slots holding a copy of an argument.
    spills: Vec<(Slot, Origin)>,
    /// Width in bytes of the last write to `rax` / `eax`, 0 if none.
    ret_width: u8,
    /// Kind of the last write to `xmm0`.
    ret_xmm: Option<ValueKind>,
    /// A value left on the x87 stack (an x86 floating-point return).
    x87: bool,
}

impl PathState {
    fn entry() -> Self {
        Self {
            written: 0,
            holds: [None; 32],
            stack: {
                let mut stack = [None; 16];
                stack[RSP] = Some(ENTRY_SLOT);
                stack
            },
            spills: Vec::new(),
            ret_width: 0,
            ret_xmm: None,
            x87: false,
        }
    }
}

/// A stack address: an anchor and a byte offset from it. Anchor 0 is the stack
/// pointer at entry; aligning the stack (`and rsp, -16`) starts a new anchor,
/// named by the address of that instruction, since the offset from the entry
/// is no longer known.
type Slot = (u64, i64);

const ENTRY_SLOT: Slot = (0, 0);

/// Index of a general or XMM register in [`PathState::written`].
fn reg_index(reg: Register) -> Option<usize> {
    if reg.is_xmm() {
        Some(16 + reg.number())
    } else if reg.is_gpr() {
        Some(reg.number())
    } else {
        None
    }
}

const RAX: usize = 0;
const RSP: usize = 4;
const RBP: usize = 5;
const XMM0: usize = 16;

/// The argument slot a register is at entry, if it is an argument register.
fn arg_slot(index: usize) -> Option<u8> {
    if let Some(slot) = GP_ARG_REGS.iter().position(|&r| r == index) {
        return Some(slot as u8);
    }
    #[cfg(target_arch = "x86_64")]
    if (XMM0..XMM0 + 4).contains(&index) {
        return Some((index - XMM0) as u8);
    }
    None
}

fn is_xmm_index(index: usize) -> bool {
    index >= XMM0
}

/// Registers a call clobbers.
#[cfg(target_arch = "x86_64")]
const VOLATILE: u32 = (1 << 0) | (1 << 1) | (1 << 2) | (0xF << 8) | (0x3F << 16);
#[cfg(target_arch = "x86")]
const VOLATILE: u32 = (1 << 0) | (1 << 1) | (1 << 2) | (0xFF << 16);

/// What a callee reads of its arguments and returns, as seen by its caller.
#[derive(Clone)]
struct CalleeUse {
    regs: [Evidence; REG_SLOTS],
    /// Only x64 passes arguments in XMM registers.
    #[cfg_attr(target_arch = "x86", allow(dead_code))]
    xmm: [Evidence; REG_SLOTS],
    stack: Vec<(i64, Evidence)>,
    stack_cleanup: u32,
    returns: Option<ValueKind>,
    returned: bool,
    complete: bool,
}

struct Analysis {
    entry: u64,
    /// Call depth below the analysed function.
    depth: u8,
    /// Instruction budget.
    budget: usize,
    /// Callees analysed so far, by entry address.
    callees: HashMap<u64, Option<CalleeUse>>,
    /// `[begin, end)` of the function from its unwind data, if any.
    bounds: Option<(u64, u64)>,
    regs: [Evidence; REG_SLOTS],
    xmm: [Evidence; REG_SLOTS],
    /// Stack arguments by entry-relative offset.
    stack: Vec<(i64, Evidence)>,
    returns_int: Option<u8>,
    returns_xmm: Option<ValueKind>,
    returns_x87: bool,
    rets: usize,
    void_rets: usize,
    stack_cleanup: u32,
    complete: bool,
    factory: InstructionInfoFactory,
}

impl Analysis {
    fn new(entry: u64) -> Self {
        Self {
            entry,
            depth: 0,
            budget: MAX_STEPS,
            callees: HashMap::new(),
            bounds: function_bounds(entry),
            regs: [Evidence::default(); REG_SLOTS],
            xmm: [Evidence::default(); REG_SLOTS],
            stack: Vec::new(),
            returns_int: None,
            returns_xmm: None,
            returns_x87: false,
            rets: 0,
            void_rets: 0,
            stack_cleanup: 0,
            complete: true,
            factory: InstructionInfoFactory::new(),
        }
    }

    fn evidence(&mut self, origin: Origin) -> &mut Evidence {
        match origin {
            Origin::Reg(slot) => &mut self.regs[slot as usize],
            Origin::Stack(offset) => {
                let pos = match self.stack.iter().position(|(o, _)| *o == offset) {
                    Some(pos) => pos,
                    None => {
                        self.stack.push((offset, Evidence::default()));
                        self.stack.len() - 1
                    }
                };
                &mut self.stack[pos].1
            }
        }
    }

    fn xmm_evidence(&mut self, slot: u8) -> &mut Evidence {
        &mut self.xmm[slot as usize]
    }

    /// Whether a jump to `target` stays inside the function.
    fn is_internal(&self, target: u64) -> bool {
        match self.bounds {
            Some((begin, end)) => (begin..end).contains(&target),
            None => target >= self.entry && target < self.entry + MAX_FUNCTION_BYTES,
        }
    }

    unsafe fn run(&mut self) {
        let mut seen: HashSet<(u64, PathState)> = HashSet::new();
        let mut work: Vec<(u64, PathState)> = vec![(self.entry, PathState::entry())];
        let mut steps = 0usize;

        while let Some((mut ip, mut state)) = work.pop() {
            loop {
                if !seen.insert((ip, state.clone())) {
                    break;
                }
                steps += 1;
                if steps > self.budget {
                    self.complete = false;
                    return;
                }
                let Some(instr) = (unsafe { decode_at(ip) }) else {
                    self.complete = false;
                    break;
                };
                self.step(&instr, &mut state);

                match instr.flow_control() {
                    FlowControl::Return => {
                        self.on_return(&instr, &state);
                        break;
                    }
                    FlowControl::ConditionalBranch => {
                        let target = instr.near_branch_target();
                        if self.is_internal(target) {
                            work.push((target, state.clone()));
                        } else {
                            self.complete = false;
                        }
                        ip = instr.next_ip();
                    }
                    FlowControl::UnconditionalBranch => {
                        let target = instr.near_branch_target();
                        if matches!(
                            instr.op0_kind(),
                            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                        ) && self.is_internal(target)
                        {
                            ip = target;
                        } else {
                            self.tail_call(&instr, &state);
                            break;
                        }
                    }
                    FlowControl::IndirectBranch => {
                        // An import tail jump, or a jump table.
                        self.tail_call(&instr, &state);
                        break;
                    }
                    // `int3`, `ud2`, `int 29h` (`__fastfail`): the path ends.
                    FlowControl::Exception | FlowControl::Interrupt => break,
                    _ => ip = instr.next_ip(),
                }
            }
        }
    }

    /// The arguments and return value of the callee at `target`, analysed once.
    fn callee_use(&mut self, target: u64) -> Option<CalleeUse> {
        if self.depth >= MAX_DEPTH {
            return None;
        }
        if let Some(cached) = self.callees.get(&target) {
            return cached.clone();
        }
        if self.callees.len() >= MAX_CALLEES {
            return None;
        }
        let entry = unsafe { crate::detour_code_from_pointer(target as *const u8) } as u64;
        let result = (entry != 0
            && unsafe { crate::disasm::readable_bytes_from(entry as *const u8) } != 0)
            .then(|| {
                let mut callee = Analysis::new(entry);
                callee.depth = self.depth + 1;
                callee.budget = MAX_CALLEE_STEPS;
                unsafe { callee.run() };
                CalleeUse {
                    regs: callee.regs,
                    xmm: callee.xmm,
                    stack: callee.stack.clone(),
                    stack_cleanup: callee.stack_cleanup,
                    returns: callee.return_kind(),
                    returned: callee.rets > 0,
                    complete: callee.complete,
                }
            });
        self.callees.insert(target, result.clone());
        result
    }

    /// Credits the arguments `callee` reads to this function where they are
    /// still this function's own arguments in `state`: argument registers not
    /// written on this path, or registers holding a copy of an argument. On a
    /// tail jump with the stack as it was at entry, the stack arguments are
    /// passed on as well.
    fn forward(&mut self, callee: &CalleeUse, state: &PathState, tail: bool) {
        for (slot, &reg) in GP_ARG_REGS.iter().enumerate() {
            if !callee.regs[slot].used {
                continue;
            }
            let origin = if state.written & (1 << reg) == 0 {
                Some(Origin::Reg(slot as u8))
            } else {
                state.holds[reg]
            };
            if let Some(origin) = origin {
                self.evidence(origin).merge(&callee.regs[slot]);
            }
        }
        #[cfg(target_arch = "x86_64")]
        for slot in 0..REG_SLOTS {
            if callee.xmm[slot].used && state.written & (1 << (XMM0 + slot)) == 0 {
                let evidence = callee.xmm[slot];
                self.xmm_evidence(slot as u8).merge(&evidence);
            }
        }
        if tail && state.stack[RSP] == Some(ENTRY_SLOT) {
            for (offset, evidence) in &callee.stack {
                if *offset >= FIRST_STACK_ARG {
                    self.evidence(Origin::Stack(*offset)).merge(evidence);
                }
            }
            self.stack_cleanup = self.stack_cleanup.max(callee.stack_cleanup);
        }
    }

    /// A jump out of the function: it continues in the target, which takes
    /// the arguments still in place and returns for this function.
    fn tail_call(&mut self, instr: &Instruction, state: &PathState) {
        let Some(callee) = branch_target(instr).and_then(|t| self.callee_use(t)) else {
            self.complete = false;
            return;
        };
        self.forward(&callee, state, true);
        self.complete &= callee.complete;
        if !callee.returned {
            return;
        }
        self.rets += 1;
        match callee.returns {
            Some(kind @ (ValueKind::Float | ValueKind::Double)) => self.returns_xmm = Some(kind),
            Some(ValueKind::Unknown) => {}
            Some(kind) => {
                let width = match kind {
                    ValueKind::Int8 => 1,
                    ValueKind::Int16 => 2,
                    ValueKind::Int32 => 4,
                    _ => 8,
                };
                self.returns_int = Some(self.returns_int.unwrap_or(0).max(width));
            }
            None => self.void_rets += 1,
        }
    }

    /// Applies one instruction to `state` and records what it reveals.
    fn step(&mut self, instr: &Instruction, state: &mut PathState) {
        let mnemonic = instr.mnemonic();
        let info = self.factory.info(instr).clone();

        // Idioms that set a register without depending on it read nothing:
        // `xor r, r` and friends, `or r, -1`, `and r, 0`.
        let zeroing = instr.op_count() == 2
            && instr.op0_kind() == OpKind::Register
            && ((instr.op1_kind() == OpKind::Register
                && instr.op0_register() == instr.op1_register()
                && matches!(
                    mnemonic,
                    Mnemonic::Xor
                        | Mnemonic::Sub
                        | Mnemonic::Sbb
                        | Mnemonic::Pxor
                        | Mnemonic::Xorps
                        | Mnemonic::Xorpd
                ))
                || (is_immediate(instr.op1_kind())
                    && ((mnemonic == Mnemonic::Or && instr.immediate(1) as i64 == -1)
                        || (mnemonic == Mnemonic::And && instr.immediate(1) == 0))));

        // `push reg` only stores the register (compilers also use it to
        // reserve a stack slot); it is tracked as a spill below.
        let pushes_register = mnemonic == Mnemonic::Push && instr.op0_kind() == OpKind::Register;

        // Reads of argument registers not written yet on this path, and of
        // registers holding a copy of an argument.
        if !zeroing && !pushes_register {
            for used in info.used_registers() {
                if !matches!(
                    used.access(),
                    OpAccess::Read
                        | OpAccess::CondRead
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                ) {
                    continue;
                }
                let reg = used.register();
                let Some(index) = reg_index(reg) else {
                    continue;
                };
                let origin = if state.written & (1 << index) == 0 {
                    arg_slot(index).map(Origin::Reg)
                } else {
                    state.holds[index]
                };
                let Some(origin) = origin else {
                    continue;
                };
                if is_xmm_index(index) {
                    if let Origin::Reg(slot) = origin {
                        let kind = xmm_kind(mnemonic);
                        let evidence = self.xmm_evidence(slot);
                        evidence.used = true;
                        match kind {
                            Some(ValueKind::Float) => evidence.float = true,
                            Some(ValueKind::Double) => evidence.double = true,
                            _ => {}
                        }
                    }
                } else {
                    self.evidence(origin).read(reg.size());
                }
            }
        }

        // Memory operands: an argument used as an address is a pointer, and a
        // read of a stack slot above the return address is a stack argument.
        for mem in info.used_memory() {
            if let Some(index) = reg_index(mem.base()) {
                let origin = if state.written & (1 << index) == 0 {
                    arg_slot(index).map(Origin::Reg)
                } else {
                    state.holds[index]
                };
                if let Some(origin) = origin
                    && mem.access() != OpAccess::NoMemAccess
                {
                    self.evidence(origin).pointer = true;
                }
            }
            if !matches!(
                mem.access(),
                OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
            ) {
                continue;
            }
            let Some(slot) = stack_slot(state, mem.base(), mem.index(), mem.displacement()) else {
                continue;
            };
            let (anchor, offset) = slot;
            if anchor == ENTRY_SLOT.0
                && offset >= FIRST_STACK_ARG
                && !state.spills.iter().any(|(s, _)| *s == slot)
            {
                let size = mem.memory_size().size();
                let evidence = self.evidence(Origin::Stack(offset));
                evidence.read(size.min(8));
                match mem.memory_size() {
                    MemorySize::Float32 => evidence.float = true,
                    MemorySize::Float64 => evidence.double = true,
                    _ => {}
                }
            }
        }

        self.track(instr, &info, state, zeroing);
    }

    /// Updates register contents, the stack and frame pointers, spills and the
    /// return-value registers for `instr`.
    fn track(
        &mut self,
        instr: &Instruction,
        info: &iced_x86::InstructionInfo,
        state: &mut PathState,
        zeroing: bool,
    ) {
        let mnemonic = instr.mnemonic();

        // Values moved by this instruction, computed before any write.
        let copied = copy_source(instr, state);
        let lea_base = if mnemonic == Mnemonic::Lea {
            reg_index(instr.memory_base()).and_then(|b| {
                if state.written & (1 << b) == 0 {
                    arg_slot(b).map(Origin::Reg)
                } else {
                    state.holds[b]
                }
            })
        } else {
            None
        };

        // Stack addresses: computed from the registers before this
        // instruction, applied after its writes below.
        let before = state.stack;
        let shifted = |slot: Option<Slot>, by: i64| slot.map(|(a, o)| (a, o + by));
        match mnemonic {
            Mnemonic::Push => state.stack[RSP] = shifted(before[RSP], -WORD),
            Mnemonic::Pop => state.stack[RSP] = shifted(before[RSP], WORD),
            Mnemonic::Leave => state.stack[RSP] = shifted(before[RBP], WORD),
            _ => {}
        }
        let dst_stack = if instr.op_count() >= 1
            && instr.op0_kind() == OpKind::Register
            && !matches!(mnemonic, Mnemonic::Push | Mnemonic::Pop)
            && let Some(dst) = reg_index(instr.op0_register()).filter(|&d| d < 16)
        {
            let anchored = match (mnemonic, instr.op1_kind()) {
                (Mnemonic::Mov, OpKind::Register) => reg_index(instr.op1_register())
                    .filter(|&r| r < 16)
                    .and_then(|r| before[r]),
                (Mnemonic::Lea, _) if instr.memory_index() == Register::None => {
                    reg_index(instr.memory_base())
                        .filter(|&b| b < 16)
                        .and_then(|b| shifted(before[b], instr.memory_displacement64() as i64))
                }
                (Mnemonic::Add, k) if is_immediate(k) => {
                    shifted(before[dst], instr.immediate(1) as i64)
                }
                (Mnemonic::Sub, k) if is_immediate(k) => {
                    shifted(before[dst], -(instr.immediate(1) as i64))
                }
                // Aligning a stack address: a new anchor.
                (Mnemonic::And, k) if is_immediate(k) && before[dst].is_some() => {
                    Some((instr.ip(), 0))
                }
                _ => None,
            };
            Some((dst, anchored))
        } else {
            None
        };

        // `push reg` spills it; `pop reg` reloads what was pushed there.
        let popped = if mnemonic == Mnemonic::Pop && instr.op0_kind() == OpKind::Register {
            before[RSP].and_then(|slot| {
                state
                    .spills
                    .iter()
                    .find(|(s, _)| *s == slot)
                    .map(|(_, o)| *o)
            })
        } else {
            None
        };
        if mnemonic == Mnemonic::Push
            && instr.op0_kind() == OpKind::Register
            && let Some(slot) = state.stack[RSP]
        {
            state.spills.retain(|(s, _)| *s != slot);
            let pushed = reg_index(instr.op0_register()).and_then(|r| {
                if state.written & (1 << r) == 0 {
                    arg_slot(r).map(Origin::Reg)
                } else {
                    state.holds[r]
                }
            });
            if let Some(origin) = pushed
                && state.spills.len() < 32
            {
                state.spills.push((slot, origin));
            }
        }

        // Spills of an argument copy to the stack.
        if mnemonic == Mnemonic::Mov
            && instr.op0_kind() == OpKind::Memory
            && instr.op1_kind() == OpKind::Register
            && let Some(slot) = stack_slot(
                state,
                instr.memory_base(),
                instr.memory_index(),
                instr.memory_displacement64(),
            )
        {
            state.spills.retain(|(s, _)| *s != slot);
            if let Some(origin) = copied
                && state.spills.len() < 32
            {
                state.spills.push((slot, origin));
            }
        }

        // Register writes.
        let mut wrote_rax = 0u8;
        let mut wrote_xmm0 = false;
        for used in info.used_registers() {
            if !matches!(used.access(), OpAccess::Write | OpAccess::ReadWrite) {
                continue;
            }
            let reg = used.register();
            let Some(index) = reg_index(reg) else {
                continue;
            };
            if index == RSP {
                continue;
            }
            state.written |= 1 << index;
            state.holds[index] = None;
            if index < 16 {
                state.stack[index] = None;
            }
            if index == RAX {
                // A 32-bit write is reported as the full register; the
                // destination operand has the width the code chose.
                wrote_rax = if instr.op_count() >= 1
                    && instr.op0_kind() == OpKind::Register
                    && reg_index(instr.op0_register()) == Some(RAX)
                {
                    instr.op0_register().size() as u8
                } else {
                    reg.size() as u8
                };
            }
            if index == XMM0 {
                wrote_xmm0 = true;
            }
        }
        if instr.op_count() >= 1
            && instr.op0_kind() == OpKind::Register
            && !zeroing
            && let Some(dst) = reg_index(instr.op0_register())
            && let Some(origin) = copied.or(lea_base)
        {
            state.holds[dst] = Some(origin);
        }
        if let Some((dst, anchored)) = dst_stack {
            state.stack[dst] = anchored;
        }
        if let Some(origin) = popped
            && let Some(dst) = reg_index(instr.op0_register())
        {
            state.holds[dst] = Some(origin);
        }
        if wrote_rax != 0 {
            state.ret_width = wrote_rax;
        }
        if wrote_xmm0 {
            state.ret_xmm = xmm_kind(mnemonic).or(Some(ValueKind::Unknown));
        }

        // The x87 stack: a load leaves a value, a popping store removes it.
        let name = mnemonic_name(mnemonic);
        if name.starts_with("Fld") || name.starts_with("Fild") {
            state.x87 = true;
        } else if name.starts_with("Fstp") || name.starts_with("Fistp") || name.ends_with("pp") {
            state.x87 = false;
        }

        // A call clobbers the volatile registers and leaves its result in
        // rax / xmm0; on x86 a callee-cleaned call also moves the stack.
        if instr.flow_control() == FlowControl::Call
            || instr.flow_control() == FlowControl::IndirectCall
        {
            let callee = branch_target(instr).and_then(|t| self.callee_use(t));
            if let Some(callee) = &callee {
                self.forward(callee, state, false);
            }
            state.written |= VOLATILE;
            for (index, holds) in state.holds.iter_mut().enumerate() {
                if VOLATILE & (1 << index) != 0 {
                    *holds = None;
                }
            }
            for (index, stack) in state.stack.iter_mut().enumerate() {
                if VOLATILE & (1 << index) != 0 {
                    *stack = None;
                }
            }
            state.ret_width = WORD as u8;
            state.ret_xmm = Some(ValueKind::Unknown);
            // On x86 a callee-cleaned callee also pops its stack arguments; how
            // many is known only if it was analysed to a `ret`.
            #[cfg(target_arch = "x86")]
            {
                state.stack[RSP] = match &callee {
                    Some(callee) if callee.returned => state.stack[RSP]
                        .map(|(anchor, offset)| (anchor, offset + callee.stack_cleanup as i64)),
                    _ => None,
                };
            }
        }
    }

    fn on_return(&mut self, instr: &Instruction, state: &PathState) {
        self.rets += 1;
        if instr.op_count() == 1 && is_immediate(instr.op0_kind()) {
            self.stack_cleanup = self.stack_cleanup.max(instr.immediate(0) as u32);
        }
        if state.ret_xmm.is_some() && state.ret_width == 0 {
            self.returns_xmm = state
                .ret_xmm
                .filter(|k| *k != ValueKind::Unknown)
                .or(self.returns_xmm);
            if self.returns_xmm.is_none() {
                self.returns_xmm = Some(ValueKind::Unknown);
            }
        } else if state.ret_width != 0 {
            self.returns_int = Some(self.returns_int.unwrap_or(0).max(state.ret_width));
        } else if state.x87 {
            self.returns_x87 = true;
        } else {
            self.void_rets += 1;
        }
    }

    fn return_kind(&self) -> Option<ValueKind> {
        if self.returns_xmm.is_some() {
            self.returns_xmm
        } else if let Some(width) = self.returns_int {
            Some(match width {
                1 => ValueKind::Int8,
                2 => ValueKind::Int16,
                4 => ValueKind::Int32,
                _ => ValueKind::Int64,
            })
        } else if self.returns_x87 {
            Some(ValueKind::Double)
        } else {
            None
        }
    }

    fn finish(self) -> SignatureGuess {
        let mut args = Vec::new();

        #[cfg(target_arch = "x86_64")]
        let convention = {
            // Positional slots: the highest one used fixes the count.
            let stack_slots = self
                .stack
                .iter()
                .filter(|(_, e)| e.used)
                .map(|(o, _)| ((o - FIRST_STACK_ARG) / 8) as usize + 1)
                .max()
                .unwrap_or(0);
            let reg_slots = (0..REG_SLOTS)
                .rev()
                .find(|&i| self.regs[i].used || self.xmm[i].used)
                .map_or(0, |i| i + 1);
            let count = if stack_slots > 0 {
                REG_SLOTS + stack_slots
            } else {
                reg_slots
            };
            const GP_NAMES: [&str; 4] = ["rcx", "rdx", "r8", "r9"];
            const XMM_NAMES: [&str; 4] = ["xmm0", "xmm1", "xmm2", "xmm3"];
            for i in 0..count {
                if i < REG_SLOTS {
                    let (name, evidence) = if self.xmm[i].used && !self.regs[i].used {
                        (XMM_NAMES[i], self.xmm[i])
                    } else {
                        (GP_NAMES[i], self.regs[i])
                    };
                    args.push(ArgGuess {
                        location: ArgLocation::Register(name),
                        kind: evidence.kind(),
                        confidence: if evidence.used {
                            evidence.confidence()
                        } else {
                            0.3
                        },
                    });
                } else {
                    let offset = FIRST_STACK_ARG + 8 * (i - REG_SLOTS) as i64;
                    let evidence = self
                        .stack
                        .iter()
                        .find(|(o, _)| *o == offset)
                        .map(|(_, e)| *e)
                        .unwrap_or_default();
                    args.push(ArgGuess {
                        location: ArgLocation::Stack(offset as u32),
                        kind: evidence.kind(),
                        confidence: if evidence.used {
                            evidence.confidence()
                        } else {
                            0.3
                        },
                    });
                }
            }
            CallingConvention::Win64
        };

        #[cfg(target_arch = "x86")]
        let convention = {
            let ecx = self.regs[0];
            let edx = self.regs[1];
            let convention = if edx.used {
                CallingConvention::Fastcall
            } else if ecx.used && self.stack_cleanup > 0 && ecx.pointer {
                CallingConvention::Thiscall
            } else if ecx.used {
                CallingConvention::Fastcall
            } else if self.stack_cleanup > 0 {
                CallingConvention::Stdcall
            } else {
                CallingConvention::Cdecl
            };
            match convention {
                CallingConvention::Fastcall => {
                    args.push(reg_arg("ecx", ecx));
                    args.push(reg_arg("edx", edx));
                }
                CallingConvention::Thiscall => args.push(reg_arg("ecx", ecx)),
                _ => {}
            }
            // A callee-cleaned `ret N` gives the stack bytes exactly; otherwise
            // the highest slot read does.
            let read_end = self
                .stack
                .iter()
                .filter(|(_, e)| e.used)
                .map(|(o, e)| o + (e.width.max(4) as i64))
                .max()
                .unwrap_or(FIRST_STACK_ARG);
            let end = if self.stack_cleanup > 0 {
                FIRST_STACK_ARG + self.stack_cleanup as i64
            } else {
                read_end
            };
            let exact = self.stack_cleanup > 0;
            let mut offset = FIRST_STACK_ARG;
            while offset < end {
                let evidence = self
                    .stack
                    .iter()
                    .find(|(o, _)| *o == offset)
                    .map(|(_, e)| *e)
                    .unwrap_or_default();
                let size = if evidence.width == 8 || evidence.double {
                    8
                } else {
                    4
                };
                let mut confidence = if evidence.used {
                    evidence.confidence()
                } else {
                    0.3
                };
                if exact {
                    confidence = confidence.max(0.5);
                }
                args.push(ArgGuess {
                    location: ArgLocation::Stack(offset as u32),
                    kind: evidence.kind(),
                    confidence,
                });
                offset += size;
            }
            // Drop the unused trailing fastcall register when only ecx is used.
            if convention == CallingConvention::Fastcall && !edx.used && args.len() == 2 {
                args.truncate(1);
            }
            convention
        };

        let returns = self.return_kind();

        SignatureGuess {
            convention,
            args,
            returns,
            stack_cleanup: self.stack_cleanup,
            complete: self.complete && self.rets > 0,
        }
    }
}

#[cfg(target_arch = "x86")]
fn reg_arg(name: &'static str, evidence: Evidence) -> ArgGuess {
    ArgGuess {
        location: ArgLocation::Register(name),
        kind: evidence.kind(),
        confidence: if evidence.used {
            evidence.confidence()
        } else {
            0.3
        },
    }
}

fn is_immediate(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

/// The stack slot a `[reg + disp]` operand addresses, if `reg` holds a known
/// stack address on this path.
fn stack_slot(state: &PathState, base: Register, index: Register, disp: u64) -> Option<Slot> {
    if index != Register::None {
        return None;
    }
    let base = reg_index(base).filter(|&b| b < 16)?;
    state.stack[base].map(|(anchor, offset)| (anchor, offset + disp as i64))
}

/// The argument a `mov`-style copy moves into its destination, if any.
fn copy_source(instr: &Instruction, state: &PathState) -> Option<Origin> {
    if instr.op_count() != 2 {
        return None;
    }
    let is_move = matches!(
        instr.mnemonic(),
        Mnemonic::Mov
            | Mnemonic::Movzx
            | Mnemonic::Movsx
            | Mnemonic::Movsxd
            | Mnemonic::Movaps
            | Mnemonic::Movapd
            | Mnemonic::Movups
            | Mnemonic::Movupd
            | Mnemonic::Movss
            | Mnemonic::Movsd
            | Mnemonic::Movq
            | Mnemonic::Movd
    );
    if !is_move {
        return None;
    }
    match instr.op1_kind() {
        OpKind::Register => {
            let index = reg_index(instr.op1_register())?;
            if state.written & (1 << index) == 0 {
                arg_slot(index).map(Origin::Reg)
            } else {
                state.holds[index]
            }
        }
        OpKind::Memory => {
            let slot = stack_slot(
                state,
                instr.memory_base(),
                instr.memory_index(),
                instr.memory_displacement64(),
            )?;
            if let Some((_, origin)) = state.spills.iter().find(|(s, _)| *s == slot) {
                Some(*origin)
            } else if slot.0 == ENTRY_SLOT.0 && slot.1 >= FIRST_STACK_ARG {
                Some(Origin::Stack(slot.1))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// `Float` for scalar-single, `Double` for scalar-double SSE instructions.
fn xmm_kind(mnemonic: Mnemonic) -> Option<ValueKind> {
    let name = mnemonic_name(mnemonic);
    if matches!(mnemonic, Mnemonic::Movd | Mnemonic::Movq) {
        return None;
    }
    if name.ends_with("ss") || name.starts_with("Cvtss") || name == "Ucomiss" || name == "Comiss" {
        Some(ValueKind::Float)
    } else if name.ends_with("sd")
        || name.starts_with("Cvtsd")
        || name == "Ucomisd"
        || name == "Comisd"
    {
        Some(ValueKind::Double)
    } else {
        None
    }
}

fn mnemonic_name(mnemonic: Mnemonic) -> String {
    format!("{mnemonic:?}")
}

/// Where a call or jump goes: a direct target, or the pointer an import slot
/// (`call [rip + __imp_X]`, `jmp [__imp_X]`) holds.
fn branch_target(instr: &Instruction) -> Option<u64> {
    match instr.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(instr.near_branch_target())
        }
        OpKind::Memory => {
            let slot = if instr.is_ip_rel_memory_operand() {
                instr.ip_rel_memory_address()
            } else if instr.memory_base() == Register::None
                && instr.memory_index() == Register::None
            {
                instr.memory_displacement64()
            } else {
                return None;
            };
            let slot = slot as *const usize;
            if unsafe { crate::disasm::readable_bytes_from(slot.cast()) } < WORD as usize {
                return None;
            }
            let target = unsafe { slot.read_unaligned() } as u64;
            (target != 0).then_some(target)
        }
        _ => None,
    }
}

/// Decodes the instruction at `ip`, or `None` if it is unreadable or invalid.
unsafe fn decode_at(ip: u64) -> Option<Instruction> {
    let readable = unsafe { crate::disasm::readable_bytes_from(ip as *const u8) };
    if readable == 0 {
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(ip as *const u8, readable.min(15)) };
    #[cfg(target_arch = "x86_64")]
    let bitness = 64;
    #[cfg(target_arch = "x86")]
    let bitness = 32;
    let mut decoder = Decoder::with_ip(bitness, bytes, ip, DecoderOptions::NONE);
    let instr = decoder.decode();
    (!instr.is_invalid() && instr.code() != Code::INVALID).then_some(instr)
}

/// `[begin, end)` of the function containing `entry`, from its x64 unwind
/// data.
#[cfg(target_arch = "x86_64")]
fn function_bounds(entry: u64) -> Option<(u64, u64)> {
    use windows_sys::Win32::System::Diagnostics::Debug::RtlLookupFunctionEntry;
    let mut image_base = 0u64;
    let function = unsafe { RtlLookupFunctionEntry(entry, &mut image_base, std::ptr::null_mut()) };
    if function.is_null() {
        return None;
    }
    let function = unsafe { &*function };
    let begin = image_base + function.BeginAddress as u64;
    let end = image_base + function.EndAddress as u64;
    (begin == entry).then_some((begin, end))
}

#[cfg(target_arch = "x86")]
fn function_bounds(_entry: u64) -> Option<(u64, u64)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs the analysis on raw instruction bytes (readable memory suffices).
    fn infer_bytes(code: &[u8]) -> SignatureGuess {
        unsafe { infer_signature(code.as_ptr()) }.expect("infer")
    }

    fn kinds(sig: &SignatureGuess) -> Vec<ValueKind> {
        sig.args.iter().map(|a| a.kind).collect()
    }

    #[test]
    fn evidence_kind_prefers_pointer_then_float_then_width() {
        let mut e = Evidence::default();
        assert_eq!(e.kind(), ValueKind::Unknown);
        assert_eq!(e.confidence(), 0.3);
        e.read(4);
        assert_eq!(e.kind(), ValueKind::Int32);
        assert_eq!(e.confidence(), 0.6);
        e.read(1);
        assert_eq!(e.kind(), ValueKind::Int32, "the widest read wins");
        e.double = true;
        assert_eq!(e.kind(), ValueKind::Double);
        e.pointer = true;
        assert_eq!(e.kind(), ValueKind::Pointer);
        assert_eq!(e.confidence(), 0.85);
    }

    #[test]
    fn evidence_merge_ignores_unused_evidence() {
        let mut e = Evidence::default();
        e.merge(&Evidence {
            pointer: true,
            ..Evidence::default()
        });
        assert!(!e.used && !e.pointer, "an unused callee slot adds nothing");
        let mut used = Evidence::default();
        used.read(8);
        used.float = true;
        e.merge(&used);
        assert!(e.used && e.float);
        assert_eq!(e.width, 8);
    }

    #[test]
    fn xmm_kind_from_mnemonic() {
        assert_eq!(xmm_kind(Mnemonic::Addss), Some(ValueKind::Float));
        assert_eq!(xmm_kind(Mnemonic::Mulsd), Some(ValueKind::Double));
        assert_eq!(xmm_kind(Mnemonic::Cvtss2sd), Some(ValueKind::Float));
        assert_eq!(xmm_kind(Mnemonic::Ucomisd), Some(ValueKind::Double));
        assert_eq!(xmm_kind(Mnemonic::Movq), None);
        assert_eq!(xmm_kind(Mnemonic::Pxor), None);
    }

    #[test]
    fn unreadable_code_is_rejected() {
        use windows_sys::Win32::System::Memory::{
            MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, VirtualAlloc, VirtualFree,
        };
        let page = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                0x1000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_NOACCESS,
            )
        };
        assert!(!page.is_null());
        let result = unsafe { infer_signature(page as *const u8) };
        unsafe { VirtualFree(page, 0, MEM_RELEASE) };
        assert_eq!(result, Err(SignatureError::UnreadableCode));
    }

    #[test]
    fn a_function_without_ret_is_incomplete() {
        // jmp $ - loops forever, never returns.
        let sig = infer_bytes(&[0xEB, 0xFE]);
        assert!(!sig.complete);
        assert!(sig.args.is_empty());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn zeroing_idioms_are_writes() {
        // xor ecx, ecx; sub edx, edx; or r8d, -1; and r9d, 0;
        // add ecx, edx; add ecx, r8d; add ecx, r9d; mov eax, ecx; ret
        let sig = infer_bytes(&[
            0x31, 0xC9, 0x29, 0xD2, 0x41, 0x83, 0xC8, 0xFF, 0x41, 0x83, 0xE1, 0x00, 0x01, 0xD1,
            0x44, 0x01, 0xC1, 0x44, 0x01, 0xC9, 0x89, 0xC8, 0xC3,
        ]);
        assert!(sig.args.is_empty(), "{sig:?}");
        assert_eq!(sig.returns, Some(ValueKind::Int32));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn copies_carry_the_argument_along() {
        // mov rax, rdx; mov r10, rax; mov eax, [r10]; ret
        let sig = infer_bytes(&[0x48, 0x89, 0xD0, 0x49, 0x89, 0xC2, 0x41, 0x8B, 0x02, 0xC3]);
        assert_eq!(kinds(&sig), vec![ValueKind::Unknown, ValueKind::Pointer]);
        assert_eq!(sig.args[0].location, ArgLocation::Register("rcx"));
        assert_eq!(sig.args[1].location, ArgLocation::Register("rdx"));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn aligned_stack_keeps_spills_trackable() {
        // push rbp; mov rbp, rsp; and rsp, -16; sub rsp, 0x20;
        // mov [rsp], rcx; mov rax, [rsp]; mov eax, [rax]; leave; ret
        let sig = infer_bytes(&[
            0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89,
            0x0C, 0x24, 0x48, 0x8B, 0x04, 0x24, 0x8B, 0x00, 0xC9, 0xC3,
        ]);
        assert_eq!(kinds(&sig), vec![ValueKind::Pointer], "{sig:?}");
    }

    #[cfg(target_arch = "x86")]
    #[test]
    fn zeroing_idioms_are_writes() {
        // xor ecx, ecx; or edx, -1; add ecx, edx; mov eax, ecx; ret
        let sig = infer_bytes(&[0x31, 0xC9, 0x83, 0xCA, 0xFF, 0x01, 0xD1, 0x89, 0xC8, 0xC3]);
        assert!(sig.args.is_empty(), "{sig:?}");
        assert_eq!(sig.convention, CallingConvention::Cdecl);
    }

    #[cfg(target_arch = "x86")]
    #[test]
    fn copies_carry_the_argument_along() {
        // mov eax, [esp+4]; mov edx, eax; mov eax, [edx]; ret 4
        let sig = infer_bytes(&[
            0x8B, 0x44, 0x24, 0x04, 0x89, 0xC2, 0x8B, 0x02, 0xC2, 0x04, 0x00,
        ]);
        assert_eq!(kinds(&sig), vec![ValueKind::Pointer]);
        assert_eq!(sig.args[0].location, ArgLocation::Stack(4));
        assert_eq!(sig.convention, CallingConvention::Stdcall);
    }

    #[cfg(target_arch = "x86")]
    #[test]
    fn aligned_stack_keeps_spills_trackable() {
        // push ebp; mov ebp, esp; and esp, -8; sub esp, 8; mov eax, [ebp+8];
        // mov [esp], eax; mov ecx, [esp]; mov eax, [ecx]; leave; ret
        let sig = infer_bytes(&[
            0x55, 0x89, 0xE5, 0x83, 0xE4, 0xF8, 0x83, 0xEC, 0x08, 0x8B, 0x45, 0x08, 0x89, 0x04,
            0x24, 0x8B, 0x0C, 0x24, 0x8B, 0x01, 0xC9, 0xC3,
        ]);
        assert_eq!(kinds(&sig), vec![ValueKind::Pointer], "{sig:?}");
    }
}
