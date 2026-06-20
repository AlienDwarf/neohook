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
//!     save XMM regs + MXCSR        ; snapshot the SSE / floating-point state
//!     push all GPRs + flags        ; snapshot the live integer CPU state
//!     handler(&mut HookContext)    ; your code reads / modifies the snapshot
//!     pop all GPRs + flags         ; apply any integer edits back
//!     restore XMM regs + MXCSR     ; apply any SSE / FP edits back
//!     JMP (redirect ? handler-set address : gateway)
//!                                  ; gateway runs the relocated stolen bytes
//!                                  ; and resumes at target + stolen_len
//! ```
//!
//! Your handler receives a pointer to a [`HookContext`] mirroring the saved
//! register block - general-purpose registers, the flags register, every XMM
//! register, and the `MXCSR` control/status word. Reads observe the live
//! values; writes are restored into the real registers before the original
//! instructions resume - so a handler can rewrite integer or floating-point /
//! SIMD arguments, results, loop counters, or flags in flight, **without** the
//! function ever returning to a caller.
//!
//! # Control-flow redirect
//!
//! By default the detour *continues* the original function: after the handler
//! returns, the stub runs the relocated stolen bytes and resumes at
//! `target + stolen_len`. A handler can instead **redirect control flow** by
//! setting [`HookContext::redirect_rip`] (`redirect_eip` on x86) to a code
//! address. When that field is non-zero, the stub restores the (possibly
//! modified) register/XMM state and jumps straight there, **skipping the stolen
//! instructions entirely**. The handler-chosen target therefore executes with
//! exactly the register and stack state the context describes.
//!
//! Typical uses: replace a routine wholesale (hook its entry, redirect to a
//! drop-in with the same ABI, which returns to the original caller), or skip a
//! patched region and continue at [`MidHook::resume_address`]
//! (`= target + stolen_len`, where the default path would have resumed). The
//! redirect uses an indirect `jmp`, not a `ret`, so it does not disturb the
//! CPU return-address predictor or a CET shadow stack.
//!
//! The patch itself reuses the full inline-hook engine
//! ([`crate::transaction`]): threads are suspended, any instruction pointer or
//! return address inside the overwritten range is redirected, the stolen bytes
//! are relocated with `iced-x86`, and the whole thing rolls back atomically on
//! failure.
//!
//! # Safety and limits
//!
//! - Control flow can be redirected via [`HookContext::redirect_rip`] (see
//!   above), but the redirect target is reached with the *current* stack - the
//!   stub neither unwinds nor adjusts `rsp`. You are responsible for choosing a
//!   target that is valid for that stack state (e.g. a same-ABI replacement of
//!   the function whose entry you hooked, or [`MidHook::resume_address`]).
//! - General-purpose registers, the flags register, all XMM registers and the
//!   `MXCSR` word are captured and restored. The legacy **x87** stack registers
//!   (`st0`-`st7`) and MMX state are **not** snapshotted; if your handler runs
//!   x87 floating-point code at a site where the interrupted routine has live
//!   x87 state, that state may be disturbed. Modern code passes floating-point
//!   and SIMD values in XMM registers, which are fully covered.
//! - SSE support is assumed (guaranteed on x86_64, and universal on any x86 CPU
//!   running a supported Windows version).
//! - `target` must sit on a real instruction boundary. Patching mid-instruction
//!   corrupts the function.

use crate::DetourError;
use crate::alloc::{Trampoline, TrampolineAlloc};
use crate::transaction::{Hook, TransactionCore};

/// Capacity reserved for the generated context-bridge stub. With the XMM /
/// MXCSR save-restore block and the redirect dispatch the real stub is ~420
/// bytes on x86_64 and ~180 on x86; this leaves generous headroom.
const STUB_CAPACITY: usize = 512;

/// A 128-bit XMM register, captured for a [`MidHook`] handler.
///
/// The two halves are stored little-endian, matching how `movups` writes the
/// register to memory: `low` is bytes 0..8 (a packed `f64`, the scalar `f32`,
/// or the low quadword of a vector) and `high` is bytes 8..16. A handler reads
/// or writes these directly - e.g. `f64::from_bits(ctx.xmm[0].low)` to read a
/// scalar `double` argument, or `ctx.xmm[0].low = v.to_bits()` to replace it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Xmm {
    /// Bytes 0..8 of the register (the low quadword).
    pub low: u64,
    /// Bytes 8..16 of the register (the high quadword).
    pub high: u64,
}

/// Snapshot of the general-purpose registers, flags and SSE / floating-point
/// state at the hook site, captured for an x86_64 [`MidHook`] handler.
///
/// The field order matches the order in which the stub saves the state, so the
/// pointer passed to the handler aliases this layout exactly. A handler may read
/// any field to observe the live value, or write any field to change the
/// register before the original instructions resume. `rsp` is captured for
/// inspection but writing it has no effect (the stack pointer is managed by the
/// stub).
///
/// `xmm` holds `XMM0`..`XMM15` in order, and `mxcsr` holds the SSE
/// control/status word. The x87 stack registers are not captured (see the
/// module-level limits).
///
/// `redirect_rip` is **0 on entry**. Leave it 0 to continue the original
/// function normally; set it to a code address to redirect control flow there
/// instead (see the [module docs](self#control-flow-redirect)).
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
    /// The SSE control/status register (`MXCSR`).
    pub mxcsr: u32,
    /// Padding so `xmm` is 8-byte aligned; mirrors a reserved slot in the stub.
    pub _reserved: u32,
    /// `XMM0` through `XMM15`, in register-number order.
    pub xmm: [Xmm; 16],
    /// Control-flow redirect target. `0` (the default) continues the original
    /// function; any other value is jumped to after the registers are restored,
    /// skipping the stolen instructions. See the [module docs](self#control-flow-redirect).
    pub redirect_rip: u64,
}

/// Snapshot of the general-purpose registers, flags and SSE / floating-point
/// state at the hook site, captured for an x86 [`MidHook`] handler.
///
/// The layout matches the `pushad` + `pushfd` block the stub writes, preceded
/// by the saved `MXCSR` and `XMM0`..`XMM7`. Writing `esp` has no effect
/// (`popad` discards its saved stack pointer slot). The x87 stack registers are
/// not captured (see the module-level limits).
///
/// `redirect_eip` is **0 on entry**. Leave it 0 to continue the original
/// function normally; set it to a code address to redirect control flow there
/// instead (see the [module docs](self#control-flow-redirect)).
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
    /// The SSE control/status register (`MXCSR`).
    pub mxcsr: u32,
    /// `XMM0` through `XMM7`, in register-number order.
    pub xmm: [Xmm; 8],
    /// Control-flow redirect target. `0` (the default) continues the original
    /// function; any other value is jumped to after the registers are restored,
    /// skipping the stolen instructions. See the [module docs](self#control-flow-redirect).
    pub redirect_eip: u32,
}

/// A handler invoked at a mid-function hook site with a pointer to the captured
/// [`HookContext`].
///
/// The handler runs with every general-purpose register, the flags, all XMM
/// registers and `MXCSR` snapshotted and restored around it, so it may freely
/// clobber registers and modify the context block in place. It must not block
/// indefinitely or unwind across the FFI boundary.
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
    /// `target + stolen_len`: where the default (non-redirecting) path resumes.
    resume: *mut u8,
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

        // The number of bytes stolen at the target; the default path resumes at
        // `target + stolen_len`. A mid-function patch always produces an inline
        // hook, but fall back to 0 defensively for any other variant.
        let stolen_len = match &hook {
            Hook::Inline(h) => h.stolen_len,
            _ => 0,
        };
        let resume = unsafe { target.add(stolen_len) };

        Ok(MidHook {
            hook: Some(hook),
            stub,
            target,
            resume,
        })
    }

    /// Returns the address that was patched.
    pub fn target(&self) -> *const u8 {
        self.target
    }

    /// Returns the address where the original function resumes when a handler
    /// does **not** redirect - i.e. `target + stolen_len`, just past the bytes
    /// the patch overwrote.
    ///
    /// A handler can set [`HookContext::redirect_rip`] (`redirect_eip` on x86)
    /// to this value to skip the patched region but otherwise let the function
    /// continue normally. Capture it at install time (e.g. into a `static`) so
    /// the handler can read it. Note this skips the *relocated stolen bytes*, so
    /// only resume here when those instructions are safe to omit.
    pub fn resume_address(&self) -> *const u8 {
        self.resume
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

/// Emits the context-bridge stub: snapshot the SSE state (XMM + MXCSR) and all
/// GPRs + flags, call `handler` with a pointer to that block, restore the
/// (possibly modified) state, then jump either to `gateway` (which runs the
/// relocated stolen bytes and resumes the function) or, if the handler set
/// `redirect_rip`, straight to that address. `stub_addr` is the address the
/// bytes will live at.
///
/// The combined block, from the lowest address (where the handler pointer aims)
/// upward, is `rflags, rax..r15, mxcsr, _pad, xmm0..xmm15, redirect_rip` -
/// exactly the [`HookContext`] layout. The save order is therefore "highest
/// field first": the (zeroed) `redirect_rip` slot, then XMM (with `xmm15` pushed
/// first so `xmm0` ends up lowest), then MXCSR, then the GPRs, then flags last.
/// `movups` is used so the stack need not be 16-byte aligned for the spill.
///
/// After the handler returns, the stub overwrites the `redirect_rip` slot with
/// the chosen target (`redirect_rip` if non-zero, else `gateway`); that slot is
/// the very top of the frame, so once the registers are restored `rsp` lands on
/// it and a single indirect `jmp` transfers control.
#[cfg(target_arch = "x86_64")]
fn build_stub(stub_addr: *mut u8, handler: *const u8, gateway: *mut u8) -> Vec<u8> {
    let _ = stub_addr; // x64 stub is position-independent.
    let mut c = Vec::with_capacity(STUB_CAPACITY);

    // sub rsp,16 ; movups [rsp], xmmN   (REX.R for xmm8..15).
    let save_xmm = |c: &mut Vec<u8>, n: u8| {
        c.extend_from_slice(&[0x48, 0x83, 0xEC, 0x10]); // sub rsp, 16
        if n >= 8 {
            c.push(0x44); // REX.R
        }
        c.extend_from_slice(&[0x0F, 0x11, 0x04 | ((n & 7) << 3), 0x24]); // movups [rsp], xmmN
    };
    // movups xmmN, [rsp] ; add rsp,16
    let restore_xmm = |c: &mut Vec<u8>, n: u8| {
        if n >= 8 {
            c.push(0x44); // REX.R
        }
        c.extend_from_slice(&[0x0F, 0x10, 0x04 | ((n & 7) << 3), 0x24]); // movups xmmN, [rsp]
        c.extend_from_slice(&[0x48, 0x83, 0xC4, 0x10]); // add rsp, 16
    };

    // Reserve and zero the redirect slot at the very top of the frame. The
    // handler sees it as `HookContext::redirect_rip` (0 == "do not redirect");
    // after the handler returns this slot holds the address the stub jumps to.
    c.extend_from_slice(&[0x48, 0x83, 0xEC, 0x08]); // sub rsp, 8
    c.extend_from_slice(&[0x48, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00]); // mov qword [rsp], 0

    // --- save: xmm15..xmm0 (xmm0 ends lowest), MXCSR, GPRs, flags last ---
    for n in (0..16u8).rev() {
        save_xmm(&mut c, n);
    }
    c.extend_from_slice(&[0x48, 0x83, 0xEC, 0x08]); // sub rsp, 8   (mxcsr + 4 pad bytes)
    c.extend_from_slice(&[0x0F, 0xAE, 0x1C, 0x24]); // stmxcsr [rsp]
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

    // --- pick the jump target: redirect_rip if the handler set it, else gateway ---
    // redirect_rip lives at the top of the frame, offset 392 from the context
    // base (= rbp). rax/rcx are clobbered here but restored by the pops below.
    const REDIRECT_OFF: i32 = 392;
    c.extend_from_slice(&[0x48, 0x8B, 0x85]); // mov rax, [rbp + disp32]
    c.extend_from_slice(&REDIRECT_OFF.to_le_bytes());
    c.extend_from_slice(&[0x48, 0xB9]); // movabs rcx, imm64 (gateway)
    c.extend_from_slice(&(gateway as u64).to_le_bytes());
    c.extend_from_slice(&[0x48, 0x85, 0xC0]); // test rax, rax
    c.extend_from_slice(&[0x48, 0x0F, 0x44, 0xC1]); // cmovz rax, rcx  (rax = redirect ? redirect : gateway)
    c.extend_from_slice(&[0x48, 0x89, 0x85]); // mov [rbp + disp32], rax
    c.extend_from_slice(&REDIRECT_OFF.to_le_bytes());

    // --- restore: flags, rax..rdi, r8..r15, MXCSR, xmm0..xmm15 (reverse) ---
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
    c.extend_from_slice(&[0x0F, 0xAE, 0x14, 0x24]); // ldmxcsr [rsp]
    c.extend_from_slice(&[0x48, 0x83, 0xC4, 0x08]); // add rsp, 8
    for n in 0..16u8 {
        restore_xmm(&mut c, n);
    }
    // After the XMM reloads rsp points at the redirect slot (= the chosen
    // target). Drop it back to the entry rsp and jump through it. Using an
    // indirect `jmp` (not `ret`) keeps the CET shadow stack intact; the operand
    // sits 8 bytes below rsp only for this single instruction.
    c.extend_from_slice(&[0x48, 0x83, 0xC4, 0x08]); // add rsp, 8     (rsp = entry rsp)
    c.extend_from_slice(&[0xFF, 0x64, 0x24, 0xF8]); // jmp qword [rsp - 8]

    c
}

#[cfg(target_arch = "x86")]
fn build_stub(stub_addr: *mut u8, handler: *const u8, gateway: *mut u8) -> Vec<u8> {
    let mut c = Vec::with_capacity(STUB_CAPACITY);

    // sub esp,16 ; movups [esp], xmmN
    let save_xmm = |c: &mut Vec<u8>, n: u8| {
        c.extend_from_slice(&[0x83, 0xEC, 0x10]); // sub esp, 16
        c.extend_from_slice(&[0x0F, 0x11, 0x04 | (n << 3), 0x24]); // movups [esp], xmmN
    };
    // movups xmmN, [esp] ; add esp,16
    let restore_xmm = |c: &mut Vec<u8>, n: u8| {
        c.extend_from_slice(&[0x0F, 0x10, 0x04 | (n << 3), 0x24]); // movups xmmN, [esp]
        c.extend_from_slice(&[0x83, 0xC4, 0x10]); // add esp, 16
    };

    // Reserve and zero the redirect slot at the top of the frame (the handler
    // sees it as `HookContext::redirect_eip`; 0 == "do not redirect"). Eight
    // bytes are reserved - `redirect_eip` (4) plus 4 of tail padding - so the
    // frame size matches `size_of::<HookContext>()` (the struct is 8-aligned
    // because of `Xmm`), leaving no slack a full-struct read could run past.
    c.extend_from_slice(&[0x83, 0xEC, 0x08]); // sub esp, 8
    c.extend_from_slice(&[0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00]); // mov dword [esp], 0 (redirect_eip)

    // --- save: xmm7..xmm0 (xmm0 ends lowest), MXCSR, then pushad + pushfd ---
    for n in (0..8u8).rev() {
        save_xmm(&mut c, n);
    }
    c.extend_from_slice(&[0x83, 0xEC, 0x04]); // sub esp, 4   (mxcsr)
    c.extend_from_slice(&[0x0F, 0xAE, 0x1C, 0x24]); // stmxcsr [esp]
    c.push(0x60); // pushad
    c.push(0x9C); // pushfd

    // --- call handler(&context) ---
    c.extend_from_slice(&[0x89, 0xE0]); // mov eax, esp   (eax = &context)
    c.push(0x50); // push eax        (arg)
    c.push(0xB8); // mov eax, imm32
    c.extend_from_slice(&(handler as u32).to_le_bytes());
    c.extend_from_slice(&[0xFF, 0xD0]); // call eax  (stdcall: callee pops the arg)

    // --- pick the jump target: redirect_eip if the handler set it, else gateway ---
    // esp == context base here; redirect_eip is at offset 168. eax/ecx are
    // clobbered but restored by popad below.
    const REDIRECT_OFF: i32 = 168;
    c.extend_from_slice(&[0x8B, 0x84, 0x24]); // mov eax, [esp + disp32]
    c.extend_from_slice(&REDIRECT_OFF.to_le_bytes());
    c.push(0xB9); // mov ecx, imm32 (gateway)
    c.extend_from_slice(&(gateway as u32).to_le_bytes());
    c.extend_from_slice(&[0x85, 0xC0]); // test eax, eax
    c.extend_from_slice(&[0x0F, 0x44, 0xC1]); // cmovz eax, ecx
    c.extend_from_slice(&[0x89, 0x84, 0x24]); // mov [esp + disp32], eax
    c.extend_from_slice(&REDIRECT_OFF.to_le_bytes());

    // --- restore: flags, GPRs, MXCSR, xmm0..xmm7 ---
    c.push(0x9D); // popfd
    c.push(0x61); // popad
    c.extend_from_slice(&[0x0F, 0xAE, 0x14, 0x24]); // ldmxcsr [esp]
    c.extend_from_slice(&[0x83, 0xC4, 0x04]); // add esp, 4
    for n in 0..8u8 {
        restore_xmm(&mut c, n);
    }
    // After the XMM reloads esp points at the redirect slot (= chosen target).
    // Drop back to the entry esp (past the 8-byte slot) and jump through it
    // (indirect jmp, not ret). redirect_eip sits at the low dword of the slot.
    c.extend_from_slice(&[0x83, 0xC4, 0x08]); // add esp, 8      (esp = entry esp)
    c.extend_from_slice(&[0xFF, 0x64, 0x24, 0xF8]); // jmp dword [esp - 8]

    let _ = stub_addr; // position-independent now; kept for signature symmetry.

    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_fits_within_capacity() {
        let bytes = build_stub(
            0x1000 as *mut u8,
            0xDEAD_BEEF as *const u8,
            0x2000 as *mut u8,
        );
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

        // The handler appears as an imm64 after `mov rax, imm64` (48 B8); the
        // gateway after `movabs rcx, imm64` (48 B9). Neither pair occurs in the
        // spill prologue.
        let movabs_rax = bytes
            .windows(2)
            .position(|w| w == [0x48, 0xB8])
            .expect("mov rax, imm64 present");
        let imm = u64::from_le_bytes(bytes[movabs_rax + 2..movabs_rax + 10].try_into().unwrap());
        assert_eq!(imm, handler);

        let movabs_rcx = bytes
            .windows(2)
            .position(|w| w == [0x48, 0xB9])
            .expect("movabs rcx, imm64 (gateway) present");
        let gw = u64::from_le_bytes(bytes[movabs_rcx + 2..movabs_rcx + 10].try_into().unwrap());
        assert_eq!(gw, gateway);

        // The stub ends with `add rsp, 8` then an indirect `jmp [rsp - 8]`
        // (FF 64 24 F8) - a jmp, never a `ret`, to keep the CET shadow stack
        // intact.
        assert_eq!(
            &bytes[bytes.len() - 4..],
            &[0xFF, 0x64, 0x24, 0xF8],
            "stub tail must be jmp qword [rsp-8]"
        );
        assert!(!bytes.contains(&0xC3), "stub must not contain a ret (0xC3)");

        // The SSE state is saved (stmxcsr 0F AE 1C 24) and restored
        // (ldmxcsr 0F AE 14 24) exactly once around the call.
        assert_eq!(
            bytes
                .windows(4)
                .filter(|w| *w == [0x0F, 0xAE, 0x1C, 0x24])
                .count(),
            1,
            "exactly one stmxcsr"
        );
        assert_eq!(
            bytes
                .windows(4)
                .filter(|w| *w == [0x0F, 0xAE, 0x14, 0x24])
                .count(),
            1,
            "exactly one ldmxcsr"
        );
        // 16 XMM spills (movups store, 0F 11) and 16 reloads (movups load, 0F 10).
        assert_eq!(
            bytes.windows(2).filter(|w| *w == [0x0F, 0x11]).count(),
            16,
            "one movups store per XMM register"
        );
        assert_eq!(
            bytes.windows(2).filter(|w| *w == [0x0F, 0x10]).count(),
            16,
            "one movups load per XMM register"
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x64_context_layout_matches_stub() {
        use std::mem::{offset_of, size_of};
        assert_eq!(size_of::<Xmm>(), 16);
        assert_eq!(offset_of!(HookContext, rflags), 0);
        assert_eq!(offset_of!(HookContext, r15), 120);
        assert_eq!(offset_of!(HookContext, mxcsr), 128);
        assert_eq!(offset_of!(HookContext, xmm), 136);
        // redirect_rip must be the topmost field at offset 392 - the stub's
        // hard-coded REDIRECT_OFF and the slot it jumps through depend on it.
        assert_eq!(offset_of!(HookContext, redirect_rip), 392);
        assert_eq!(size_of::<HookContext>(), 392 + 8);
    }

    #[cfg(target_arch = "x86")]
    #[test]
    fn x86_context_layout_matches_stub() {
        use std::mem::{offset_of, size_of};
        assert_eq!(size_of::<Xmm>(), 16);
        assert_eq!(offset_of!(HookContext, eflags), 0);
        assert_eq!(offset_of!(HookContext, eax), 32);
        assert_eq!(offset_of!(HookContext, mxcsr), 36);
        assert_eq!(offset_of!(HookContext, xmm), 40);
        // redirect_eip must be the topmost field at offset 168 (the stub's
        // REDIRECT_OFF and ret-free jump slot depend on it). The struct is
        // 8-aligned (Xmm), so it is padded to 176 bytes - the stub reserves the
        // matching 8-byte slot.
        assert_eq!(offset_of!(HookContext, redirect_eip), 168);
        assert_eq!(size_of::<HookContext>(), 176);
    }

    #[cfg(target_arch = "x86")]
    #[test]
    fn x86_stub_redirects_through_slot_without_ret() {
        let gateway = 0x0050_0000u32;
        let bytes = build_stub(
            0x0040_0000 as *mut u8,
            0xCAFE as *const u8,
            gateway as *mut u8,
        );

        // First op reserves the 8-byte redirect slot (sub esp, 8).
        assert_eq!(&bytes[0..3], &[0x83, 0xEC, 0x08], "first op is sub esp, 8");
        assert!(bytes.contains(&0x60), "pushad present");

        // The gateway is embedded as imm32 after `mov ecx, imm32` (B9).
        let movimm = bytes
            .windows(1)
            .position(|w| w == [0xB9])
            .expect("mov ecx, imm32 present");
        let gw = u32::from_le_bytes(bytes[movimm + 1..movimm + 5].try_into().unwrap());
        assert_eq!(gw, gateway);

        // Tail is `add esp, 8` then indirect `jmp [esp - 8]` (FF 64 24 F8), no ret.
        assert_eq!(
            &bytes[bytes.len() - 4..],
            &[0xFF, 0x64, 0x24, 0xF8],
            "stub tail must be jmp dword [esp-8]"
        );
        assert!(!bytes.contains(&0xC3), "stub must not contain a ret (0xC3)");
    }
}
