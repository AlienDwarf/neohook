// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(windows)]

//! Signature inference on functions whose signature is known: hand-written
//! assembly for each pattern the analysis recognises, a compiled Rust
//! function, and a system export.

use neohook::{
    CallingConvention, SignatureError, ValueKind, infer_signature, infer_signature_by_name,
};
use std::arch::naked_asm;

fn kinds(f: *const u8) -> (Vec<ValueKind>, Option<ValueKind>, CallingConvention) {
    let sig = unsafe { infer_signature(f) }.expect("infer");
    (
        sig.args.iter().map(|a| a.kind).collect(),
        sig.returns,
        sig.convention,
    )
}

#[test]
fn null_pointer_is_rejected() {
    assert_eq!(
        unsafe { infer_signature(std::ptr::null()) },
        Err(SignatureError::NullPointer)
    );
}

#[test]
fn unknown_export_is_not_found() {
    assert_eq!(
        infer_signature_by_name("kernel32.dll", "NoSuchExportAnywhere"),
        Err(SignatureError::NotFound)
    );
}

#[cfg(target_arch = "x86_64")]
mod x64 {
    use super::*;
    use ValueKind::*;
    use neohook::ArgLocation;

    #[unsafe(naked)]
    extern "C" fn add_ints() {
        naked_asm!("mov eax, ecx", "add eax, edx", "ret");
    }

    #[unsafe(naked)]
    extern "C" fn deref() {
        naked_asm!("mov rax, [rcx]", "ret");
    }

    #[unsafe(naked)]
    extern "C" fn add_doubles() {
        naked_asm!("addsd xmm0, xmm1", "ret");
    }

    #[unsafe(naked)]
    extern "C" fn mixed() {
        // (int, float) -> float
        naked_asm!("cvtsi2ss xmm0, ecx", "addss xmm0, xmm1", "ret");
    }

    #[unsafe(naked)]
    extern "C" fn fifth_arg() {
        naked_asm!("mov eax, [rsp + 0x28]", "add eax, ecx", "ret");
    }

    #[unsafe(naked)]
    extern "C" fn returns_zero() {
        naked_asm!("xor eax, eax", "ret");
    }

    #[unsafe(naked)]
    extern "C" fn returns_nothing() {
        naked_asm!("ret");
    }

    #[unsafe(naked)]
    extern "C" fn branches() {
        naked_asm!(
            "test ecx, ecx",
            "je 2f",
            "mov eax, edx",
            "ret",
            "2:",
            "mov eax, r8d",
            "ret"
        );
    }

    #[unsafe(naked)]
    extern "C" fn reads_after_call() {
        // Only rcx is an argument: rdx is read after the call clobbered it.
        naked_asm!(
            "push rbx",
            "sub rsp, 0x20",
            "mov ebx, ecx",
            "call {f}",
            "add eax, ebx",
            "add eax, edx",
            "add rsp, 0x20",
            "pop rbx",
            "ret",
            f = sym returns_zero,
        );
    }

    #[unsafe(naked)]
    extern "C" fn spilled_pointer() {
        // What a debug build does: spill to the home space, reload, deref.
        naked_asm!(
            "mov [rsp + 8], rcx",
            "sub rsp, 0x28",
            "mov rax, [rsp + 0x30]",
            "mov eax, [rax]",
            "add rsp, 0x28",
            "ret"
        );
    }

    #[unsafe(naked)]
    extern "C" fn tail_wrapper() {
        naked_asm!("jmp {f}", f = sym add_ints);
    }

    #[unsafe(naked)]
    extern "C" fn call_wrapper() {
        // Hands both arguments on in place and never reads them itself.
        naked_asm!("sub rsp, 0x28", "call {f}", "add rsp, 0x28", "ret", f = sym add_ints);
    }

    #[unsafe(naked)]
    extern "C" fn partial_wrapper() {
        // Sets the second argument itself: only the first is its own.
        naked_asm!("xor edx, edx", "jmp {f}", f = sym add_ints);
    }

    #[test]
    fn arguments_forwarded_to_callees_count() {
        assert_eq!(kinds(tail_wrapper as *const u8).0, vec![Int32, Int32]);
        assert_eq!(kinds(call_wrapper as *const u8).0, vec![Int32, Int32]);
        assert_eq!(kinds(partial_wrapper as *const u8).0, vec![Int32]);
    }

    #[test]
    fn integer_arguments() {
        assert_eq!(
            kinds(add_ints as *const u8),
            (vec![Int32, Int32], Some(Int32), CallingConvention::Win64)
        );
    }

    #[unsafe(naked)]
    extern "C" fn third_arg_bool() {
        naked_asm!("test r8b, r8b", "setne al", "ret");
    }

    #[unsafe(naked)]
    extern "C" fn byte_write_then_xmm2() {
        // Writing r14b must not count as writing xmm2.
        naked_asm!("mov r14b, 1", "movsd xmm0, xmm2", "ret");
    }

    #[test]
    fn byte_registers_map_to_their_full_register() {
        let sig = unsafe { infer_signature(third_arg_bool as *const u8) }.unwrap();
        assert_eq!(sig.args.len(), 3);
        assert_eq!(sig.args[2].location, ArgLocation::Register("r8"));

        let sig = unsafe { infer_signature(byte_write_then_xmm2 as *const u8) }.unwrap();
        assert_eq!(sig.args.len(), 3);
        assert_eq!(sig.args[2].location, ArgLocation::Register("xmm2"));
    }

    #[test]
    fn dereferenced_argument_is_a_pointer() {
        assert_eq!(kinds(deref as *const u8).0, vec![Pointer]);
        assert_eq!(kinds(deref as *const u8).1, Some(Int64));
    }

    #[test]
    fn floating_point_arguments() {
        assert_eq!(
            kinds(add_doubles as *const u8),
            (vec![Double, Double], Some(Double), CallingConvention::Win64)
        );
        assert_eq!(
            kinds(mixed as *const u8),
            (vec![Int32, Float], Some(Float), CallingConvention::Win64)
        );
        let sig = unsafe { infer_signature(mixed as *const u8) }.unwrap();
        assert_eq!(sig.args[1].location, ArgLocation::Register("xmm1"));
    }

    #[test]
    fn stack_argument_fixes_the_count() {
        let sig = unsafe { infer_signature(fifth_arg as *const u8) }.unwrap();
        assert_eq!(sig.args.len(), 5);
        assert_eq!(sig.args[0].kind, Int32);
        assert_eq!(sig.args[4].kind, Int32);
        assert_eq!(sig.args[4].location, ArgLocation::Stack(0x28));
        assert_eq!(sig.args[1].kind, Unknown, "unused middle slots are unknown");
    }

    #[test]
    fn return_values() {
        assert_eq!(
            kinds(returns_zero as *const u8),
            (vec![], Some(Int32), CallingConvention::Win64)
        );
        assert_eq!(
            kinds(returns_nothing as *const u8),
            (vec![], None, CallingConvention::Win64)
        );
    }

    #[test]
    fn every_path_is_followed() {
        assert_eq!(kinds(branches as *const u8).0.len(), 3);
    }

    #[test]
    fn registers_read_after_a_call_are_not_arguments() {
        assert_eq!(kinds(reads_after_call as *const u8).0, vec![Int32]);
    }

    #[test]
    fn spilled_and_reloaded_argument_keeps_its_type() {
        assert_eq!(kinds(spilled_pointer as *const u8).0, vec![Pointer]);
    }
}

#[cfg(target_arch = "x86")]
mod x86 {
    use super::*;
    use ValueKind::*;

    #[unsafe(naked)]
    extern "C" fn stdcall_add() {
        naked_asm!("mov eax, [esp + 4]", "add eax, [esp + 8]", "ret 8");
    }

    #[unsafe(naked)]
    extern "C" fn cdecl_identity() {
        naked_asm!("mov eax, [esp + 4]", "ret");
    }

    #[unsafe(naked)]
    extern "C" fn high_byte_write_keeps_frame() {
        // Writing ch must not drop the ebp frame tracking.
        naked_asm!(
            "push ebp",
            "mov ebp, esp",
            "mov ch, 1",
            "mov eax, [ebp + 8]",
            "pop ebp",
            "ret"
        );
    }

    #[unsafe(naked)]
    extern "C" fn sets_control_word() {
        naked_asm!("fldcw [esp + 4]", "ret");
    }

    #[test]
    fn high_byte_register_write_keeps_the_frame_pointer() {
        let sig = unsafe { infer_signature(high_byte_write_keeps_frame as *const u8) }.unwrap();
        assert_eq!(sig.args.len(), 1);
    }

    #[test]
    fn loading_the_control_word_returns_no_value() {
        assert_ne!(kinds(sets_control_word as *const u8).1, Some(Double));
    }

    #[unsafe(naked)]
    extern "C" fn frame_pointer_deref() {
        naked_asm!(
            "push ebp",
            "mov ebp, esp",
            "mov eax, [ebp + 8]",
            "mov eax, [eax]",
            "pop ebp",
            "ret 4"
        );
    }

    #[unsafe(naked)]
    extern "C" fn fastcall_add() {
        naked_asm!("lea eax, [ecx + edx]", "ret");
    }

    #[unsafe(naked)]
    extern "C" fn thiscall_member() {
        naked_asm!("mov eax, [ecx + 4]", "add eax, [esp + 4]", "ret 4");
    }

    #[unsafe(naked)]
    extern "C" fn stdcall_double() {
        naked_asm!("fld qword ptr [esp + 4]", "ret 8");
    }

    #[unsafe(naked)]
    extern "C" fn stdcall_unused_arg() {
        // Two stack arguments by `ret 8`, only the first is read.
        naked_asm!("mov eax, [esp + 4]", "ret 8");
    }

    #[unsafe(naked)]
    extern "C" fn push_reserves_a_slot() {
        // `push ecx` as a cheap `sub esp, 4`: ecx is not an argument.
        naked_asm!("push ecx", "mov eax, [esp + 8]", "pop ecx", "ret 4");
    }

    #[unsafe(naked)]
    extern "C" fn or_minus_one() {
        naked_asm!("or ecx, -1", "mov eax, ecx", "ret");
    }

    #[unsafe(naked)]
    extern "C" fn stdcall_one() {
        naked_asm!("mov eax, [esp + 4]", "ret 4");
    }

    #[unsafe(naked)]
    extern "C" fn calls_a_stdcall_callee() {
        // The callee pops what was pushed for it, so [esp + 8] after the call
        // is this function's second argument.
        naked_asm!(
            "push dword ptr [esp + 4]",
            "call {f}",
            "add eax, [esp + 8]",
            "ret",
            f = sym stdcall_one,
        );
    }

    #[test]
    fn register_idioms_are_not_arguments() {
        assert_eq!(
            kinds(push_reserves_a_slot as *const u8),
            (vec![Int32], Some(Int32), CallingConvention::Stdcall)
        );
        assert_eq!(
            kinds(or_minus_one as *const u8),
            (vec![], Some(Int32), CallingConvention::Cdecl)
        );
    }

    #[test]
    fn stack_tracked_across_a_callee_cleaned_call() {
        assert_eq!(
            kinds(calls_a_stdcall_callee as *const u8),
            (vec![Int32, Int32], Some(Int32), CallingConvention::Cdecl)
        );
    }

    #[test]
    fn stdcall_arguments_from_ret_n() {
        let sig = unsafe { infer_signature(stdcall_add as *const u8) }.unwrap();
        assert_eq!(sig.convention, CallingConvention::Stdcall);
        assert_eq!(sig.stack_cleanup, 8);
        assert_eq!(
            sig.args.iter().map(|a| a.kind).collect::<Vec<_>>(),
            vec![Int32, Int32]
        );
        assert_eq!(sig.returns, Some(Int32));
    }

    #[test]
    fn cdecl_arguments_from_stack_reads() {
        assert_eq!(
            kinds(cdecl_identity as *const u8),
            (vec![Int32], Some(Int32), CallingConvention::Cdecl)
        );
    }

    #[test]
    fn frame_pointer_relative_argument() {
        assert_eq!(
            kinds(frame_pointer_deref as *const u8),
            (vec![Pointer], Some(Int32), CallingConvention::Stdcall)
        );
    }

    #[test]
    fn fastcall_and_thiscall() {
        assert_eq!(
            kinds(fastcall_add as *const u8),
            (vec![Int32, Int32], Some(Int32), CallingConvention::Fastcall)
        );
        assert_eq!(
            kinds(thiscall_member as *const u8),
            (
                vec![Pointer, Int32],
                Some(Int32),
                CallingConvention::Thiscall
            )
        );
    }

    #[test]
    fn double_on_the_stack_and_x87_return() {
        assert_eq!(
            kinds(stdcall_double as *const u8),
            (vec![Double], Some(Double), CallingConvention::Stdcall)
        );
    }

    #[test]
    fn ret_n_counts_unread_arguments() {
        let sig = unsafe { infer_signature(stdcall_unused_arg as *const u8) }.unwrap();
        assert_eq!(sig.args.len(), 2);
        assert_eq!(sig.args[1].kind, Unknown);
    }
}

#[inline(never)]
extern "system" fn compiled(a: u32, b: *const u64, c: f64) -> u64 {
    std::hint::black_box(a) as u64 + unsafe { *b } + c as u64
}

#[test]
fn compiled_rust_function() {
    let sig = unsafe { infer_signature(compiled as *const u8) }.expect("infer");
    assert_eq!(sig.args.len(), 3, "{sig:?}");
    assert_eq!(sig.args[1].kind, ValueKind::Pointer, "{sig:?}");
    #[cfg(target_arch = "x86_64")]
    assert_eq!(sig.args[2].kind, ValueKind::Double, "{sig:?}");
}

#[test]
fn system_exports() {
    let sig = infer_signature_by_name("kernel32.dll", "GetCurrentProcessId").expect("infer");
    assert!(sig.args.is_empty(), "{sig:?}");
    assert!(sig.returns.is_some(), "{sig:?}");

    // int MulDiv(int, int, int)
    let sig = infer_signature_by_name("kernel32.dll", "MulDiv").expect("infer");
    assert_eq!(sig.args.len(), 3, "{sig:?}");
    assert!(
        sig.args.iter().all(|a| a.kind == ValueKind::Int32),
        "{sig:?}"
    );

    // void Sleep(DWORD): a wrapper that tail-calls SleepEx.
    let sig = infer_signature_by_name("kernel32.dll", "Sleep").expect("infer");
    assert_eq!(sig.args.len(), 1, "{sig:?}");
}
