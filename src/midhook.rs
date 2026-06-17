// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Mid-function / arbitrary-address detours with full register context.
//!
//! Every other hook NeoHook offers is anchored to a *function*: inline hooks
//! patch a prologue, IAT/EAT/VTable hooks rewrite a table slot, VEH hooks break
//! on an entry address. They all assume the patch site is reached through a
//! normal `call`, where the calling convention defines which registers are live.
//!
//! A **mid-function detour** drops that assumption. You point it at *any*
//! instruction boundary inside a function - a spot found by a signature scan, a
//! loop body, the exact place where a register holds the value you care about -
//! and NeoHook redirects execution there. Because such a site is reached with
//! *arbitrary* registers live, a normal detour function would clobber them and
//! corrupt the interrupted routine. So instead of calling your code with the
//! native ABI, NeoHook builds a small **context bridge**:
//!
//! ```text
//! target (mid-function):  JMP stub            ; stolen_len bytes, NOP-padded
//!
//! stub:
//!     push all GPRs + flags        ; snapshot the live CPU state
//!     handler(&mut HookContext)    ; your code reads / modifies the snapshot
//!     pop all GPRs + flags         ; apply any edits back to the registers
//!     <relocated stolen bytes>     ; run the original instructions
//!     JMP target + stolen_len      ; resume the function
//! ```
//!
//! Your handler receives a pointer to a [`HookContext`] mirroring the saved
//! register block. Reads observe the live values; writes are restored into the
//! real registers before the original instructions resume - so a handler can
//! rewrite arguments, results, loop counters, or flags in flight, **without**
//! the function ever returning to a caller.
//!
//! The patch itself reuses the full inline-hook engine
//! ([`crate::transaction`]): threads are suspended, any instruction pointer or
//! return address inside the overwritten range is redirected, the stolen bytes
//! are relocated with `iced-x86`, and the whole thing rolls back atomically on
//! failure.
//!
//! # Safety and limits
//!
//! - The detour always *continues* the original function; there is no facility
//!   to skip it or redirect control flow from the handler (modifying the saved
//!   instruction pointer is intentionally not supported).
//! - Only general-purpose registers and the flags register are captured. XMM /
//!   floating-point state is **not** snapshotted; a handler must not disturb it.
//! - `target` must sit on a real instruction boundary. Patching mid-instruction
//!   corrupts the function.

use crate::DetourError;
use crate::alloc::{Trampoline, TrampolineAlloc};
use crate::transaction::{Hook, TransactionCore};

/// Capacity reserved for the generated context-bridge stub. The real stub is
/// well under 100 bytes on both architectures; this leaves generous headroom.
const STUB_CAPACITY: usize = 256;

/// Snapshot of the general-purpose registers and flags at the hook site,
/// captured for an x86_64 [`MidHook`] handler.
///
/// The field order matches the order in which the stub pushes registers, so the
/// pointer passed to the handler aliases this layout exactly. A handler may read
/// any field to observe the live value, or write any field to change the
/// register before the original instructions resume. `rsp` is captured for
/// inspection but writing it has no effect (the stack pointer is managed by the
/// stub).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HookContext {
    /// The flags register (`RFLAGS`).
    pub rflags: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

/// Snapshot of the general-purpose registers and flags at the hook site,
/// captured for an x86 [`MidHook`] handler.
///
/// The layout matches the `pushad` + `pushfd` block the stub writes. Writing
/// `esp` has no effect (`popad` discards its saved stack pointer slot).
#[cfg(target_arch = "x86")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HookContext {
    /// The flags register (`EFLAGS`).
    pub eflags: u32,
    pub edi: u32,
    pub esi: u32,
    pub ebp: u32,
    pub esp: u32,
    pub ebx: u32,
    pub edx: u32,
    pub ecx: u32,
    pub eax: u32,
}

/// A handler invoked at a mid-function hook site with a pointer to the captured
/// [`HookContext`].
///
/// The handler runs with every register snapshotted and restored around it, so
/// it may freely clobber registers and modify the context block in place. It
/// must not block indefinitely or unwind across the FFI boundary.
pub type MidHookHandler = unsafe extern "system" fn(context: *mut HookContext);

/// An installed mid-function detour.
///
/// Created with [`MidHook::install`]. The detour stays active until the hook is
/// dropped or [`MidHook::unhook`] is called, at which point the original bytes
/// are restored and the context-bridge stub is released.
#[derive(Debug)]
pub struct MidHook {
    /// The committed inline hook patching the target. `None` after [`Self::unhook`].
    hook: Option<Hook>,
    /// The context-bridge stub. Held so its `Drop` frees the allocation once the
    /// target no longer jumps to it.
    #[allow(dead_code)]
    stub: Trampoline,
    target: *mut u8,
}

impl MidHook {
    /// Installs a mid-function detour redirecting `target` to `handler`.
    ///
    /// `target` may be any instruction boundary - it does not have to be a
    /// function entry. Threads are suspended for the duration of the patch and
    /// any thread executing inside the overwritten range is redirected, exactly
    /// as for [`crate::DetourTransaction::attach`].
    ///
    /// # Errors
    /// - [`DetourError::InvalidParameter`] if `target` or `handler` is null.
    /// - [`DetourError::AllocationFailed`] if no stub/trampoline memory could be
    ///   reserved near the target.
    /// - [`DetourError::RelocationFailed`] if the bytes at `target` could not be
    ///   relocated (e.g. `target` is not on an instruction boundary).
    ///
    /// # Safety
    /// `target` must point at the start of a real instruction in executable
    /// memory, and `handler` must be a valid [`MidHookHandler`]. Patching
    /// mid-instruction or at a non-code address is undefined behavior.
    pub unsafe fn install(
        target: *const u8,
        handler: MidHookHandler,
    ) -> Result<MidHook, DetourError> {
        let target = target as *mut u8;
        if target.is_null() {
            return Err(DetourError::InvalidParameter);
        }
        let handler_addr = handler as *const u8;

        // Reserve the context-bridge stub near the target so the inline patch
        // can reach it with a compact relative jump.
        let stub = unsafe {
            TrampolineAlloc::alloc_nearby_trampoline(target, STUB_CAPACITY)
                .ok_or(DetourError::AllocationFailed)?
        };

        let mut tx = TransactionCore::begin();
        tx.update_all_threads();

        // Patch the exact target with a jump to the stub. The returned gateway
        // runs the relocated original bytes and resumes at target + stolen_len,
        // which is exactly where the stub must continue execution.
        let gateway = match tx.attach_exact(target, stub.ptr as *const u8) {
            Ok(g) => g,
            Err(e) => {
                // `tx` drops here, aborting and resuming threads; `stub` frees.
                return Err(e);
            }
        };

        // The stub is private memory not yet referenced by anything, so it is
        // safe to fill in while threads are suspended and before the commit.
        let stub_bytes = build_stub(stub.ptr, handler_addr, gateway);
        if stub_bytes.len() > stub.size {
            return Err(DetourError::AllocationFailed);
        }
        unsafe {
            std::ptr::copy_nonoverlapping(stub_bytes.as_ptr(), stub.ptr, stub_bytes.len());
            windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache(
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                stub.ptr as _,
                stub_bytes.len(),
            );
        }
        stub.make_rx();

        let hooks = tx.commit()?;
        let hook = hooks
            .into_iter()
            .next()
            .ok_or(DetourError::InvalidParameter)?;

        Ok(MidHook {
            hook: Some(hook),
            stub,
            target,
        })
    }

    /// Returns the address that was patched.
    pub fn target(&self) -> *const u8 {
        self.target
    }

    /// Removes the detour, restoring the original bytes at the target. The
    /// context-bridge stub is released when the returned value is dropped.
    pub fn unhook(mut self) -> Result<(), DetourError> {
        if let Some(hook) = self.hook.take() {
            hook.unhook()?;
        }
        Ok(())
    }
}

// The inline `Hook` inside owns raw pointers but is only ever touched from the
// thread holding the hook; mirror the rest of the crate by not auto-deriving
// Send/Sync (callers move the guard into their own synchronization).

/// Emits the context-bridge stub: snapshot all GPRs + flags, call `handler`
/// with a pointer to that block, restore the (possibly modified) registers, then
/// jump to `gateway` (which runs the relocated stolen bytes and resumes the
/// function). `stub_addr` is the address the bytes will live at.
#[cfg(target_arch = "x86_64")]
fn build_stub(stub_addr: *mut u8, handler: *const u8, gateway: *mut u8) -> Vec<u8> {
    let _ = stub_addr; // x64 stub is position-independent.
    let mut c = Vec::with_capacity(96);

    // --- save: push r15..r8, rdi, rsi, rbp, rbx, rdx, rcx, rax, then flags ---
    // Pushing flags last places it at the lowest address, matching HookContext.
    c.extend_from_slice(&[
        0x41, 0x57, // push r15
        0x41, 0x56, // push r14
        0x41, 0x55, // push r13
        0x41, 0x54, // push r12
        0x41, 0x53, // push r11
        0x41, 0x52, // push r10
        0x41, 0x51, // push r9
        0x41, 0x50, // push r8
        0x57, // push rdi
        0x56, // push rsi
        0x55, // push rbp
        0x53, // push rbx
        0x52, // push rdx
        0x51, // push rcx
        0x50, // push rax
        0x9C, // pushfq
    ]);

    // --- call handler(&context) ---
    c.extend_from_slice(&[0x48, 0x89, 0xE1]); // mov rcx, rsp   (arg1 = &context)
    c.extend_from_slice(&[0x48, 0x89, 0xE5]); // mov rbp, rsp   (rbp is callee-saved: survives the call)
    c.extend_from_slice(&[0x48, 0x83, 0xE4, 0xF0]); // and rsp, -16  (16-byte align for the call)
    c.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]); // sub rsp, 32   (Win64 shadow space)
    c.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
    c.extend_from_slice(&(handler as u64).to_le_bytes());
    c.extend_from_slice(&[0xFF, 0xD0]); // call rax
    c.extend_from_slice(&[0x48, 0x89, 0xEC]); // mov rsp, rbp  (back to the context block)

    // --- restore: flags, then rax..rdi, r8..r15 (reverse of the push order) ---
    c.extend_from_slice(&[
        0x9D, // popfq
        0x58, // pop rax
        0x59, // pop rcx
        0x5A, // pop rdx
        0x5B, // pop rbx
        0x5D, // pop rbp
        0x5E, // pop rsi
        0x5F, // pop rdi
        0x41, 0x58, // pop r8
        0x41, 0x59, // pop r9
        0x41, 0x5A, // pop r10
        0x41, 0x5B, // pop r11
        0x41, 0x5C, // pop r12
        0x41, 0x5D, // pop r13
        0x41, 0x5E, // pop r14
        0x41, 0x5F, // pop r15
    ]);

    // --- jmp [rip+0]; <abs64 gateway> --- clobbers no register.
    c.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
    c.extend_from_slice(&(gateway as u64).to_le_bytes());

    c
}

#[cfg(target_arch = "x86")]
fn build_stub(stub_addr: *mut u8, handler: *const u8, gateway: *mut u8) -> Vec<u8> {
    let mut c = Vec::with_capacity(32);

    c.push(0x60); // pushad
    c.push(0x9C); // pushfd
    c.extend_from_slice(&[0x89, 0xE0]); // mov eax, esp   (eax = &context)
    c.push(0x50); // push eax        (arg)
    c.push(0xB8); // mov eax, imm32
    c.extend_from_slice(&(handler as u32).to_le_bytes());
    c.extend_from_slice(&[0xFF, 0xD0]); // call eax  (stdcall: callee pops the arg)
    c.push(0x9D); // popfd
    c.push(0x61); // popad

    // jmp rel32 gateway (clobbers no register; x86 trampolines are always in range)
    c.push(0xE9);
    let rel_at = stub_addr as i64 + c.len() as i64; // address of the rel32 field
    let next_ip = rel_at + 4;
    let rel = (gateway as i64 - next_ip) as i32;
    c.extend_from_slice(&rel.to_le_bytes());

    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_fits_within_capacity() {
        let bytes = build_stub(0x1000 as *mut u8, 0xDEAD_BEEF as *const u8, 0x2000 as *mut u8);
        assert!(
            bytes.len() <= STUB_CAPACITY,
            "stub ({} bytes) must fit in the reserved buffer",
            bytes.len()
        );
        assert!(!bytes.is_empty());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x64_stub_embeds_handler_and_gateway() {
        let handler = 0x1122_3344_5566_7788u64;
        let gateway = 0x99AA_BBCC_DDEE_FF00u64;
        let bytes = build_stub(0x4000 as *mut u8, handler as *const u8, gateway as *mut u8);

        // The handler appears as an imm64 after `mov rax, imm64` (48 B8).
        let movabs = bytes
            .windows(2)
            .position(|w| w == [0x48, 0xB8])
            .expect("mov rax, imm64 present");
        let imm = u64::from_le_bytes(bytes[movabs + 2..movabs + 10].try_into().unwrap());
        assert_eq!(imm, handler);

        // The gateway is the trailing 8 bytes after the FF 25 absolute jump.
        let tail = u64::from_le_bytes(bytes[bytes.len() - 8..].try_into().unwrap());
        assert_eq!(tail, gateway);
        assert_eq!(&bytes[bytes.len() - 14..bytes.len() - 8], &[0xFF, 0x25, 0, 0, 0, 0]);
    }

    #[cfg(target_arch = "x86")]
    #[test]
    fn x86_stub_encodes_relative_jump_to_gateway() {
        let stub_addr = 0x0040_0000i64;
        let gateway = 0x0050_0000i64;
        let bytes = build_stub(stub_addr as *mut u8, 0xCAFE as *const u8, gateway as *mut u8);

        assert_eq!(bytes[0], 0x60, "pushad first");
        assert_eq!(*bytes.last_chunk::<5>().unwrap().first().unwrap(), 0xE9);

        let rel = i32::from_le_bytes(bytes[bytes.len() - 4..].try_into().unwrap()) as i64;
        let next_ip = stub_addr + bytes.len() as i64;
        assert_eq!(next_ip + rel, gateway, "rel32 must resolve to the gateway");
    }
}
