#![cfg(windows)]

//! Exhaustive coverage of the `Display` / `From` / `Error::source` surfaces of
//! every public error type. These arms are otherwise only reached on rare OS
//! failures, so they are pinned here directly by constructing each variant.

use neohook::{
    DelayHookError, DetourError, EatHookError, HookKind, IatHookError, Int3HookError, PatternError,
    VTableHookError, VehHookError,
};

fn io_err() -> std::io::Error {
    std::io::Error::from_raw_os_error(5) // ERROR_ACCESS_DENIED
}

#[test]
fn hook_kind_display_covers_every_variant() {
    assert_eq!(HookKind::Inline.to_string(), "inline");
    assert_eq!(HookKind::Iat.to_string(), "IAT");
    assert_eq!(HookKind::Eat.to_string(), "EAT");
    assert_eq!(HookKind::Vtable.to_string(), "VTable");
    assert_eq!(HookKind::VtableInstance.to_string(), "per-instance VTable");
    assert_eq!(HookKind::Detach.to_string(), "detach");
}

#[test]
fn detour_error_display_covers_every_variant() {
    let cases: Vec<DetourError> = vec![
        DetourError::NotStarted,
        DetourError::AllocationFailed,
        DetourError::RelocationFailed,
        DetourError::InvalidParameter,
        DetourError::Pattern(PatternError::Empty),
        DetourError::PatternNotFound,
        DetourError::Iat(IatHookError::TargetNotFound),
        DetourError::Eat(EatHookError::TargetIsForwarder),
        DetourError::Vtable(VTableHookError::InvalidParameter),
        DetourError::CommitFailed {
            index: 0,
            kind: HookKind::Inline,
            source: Box::new(DetourError::AllocationFailed),
        },
    ];
    for err in &cases {
        assert!(
            !err.to_string().is_empty(),
            "every arm must format: {err:?}"
        );
    }

    // Error::source is Some only for CommitFailed.
    use std::error::Error;
    assert!(DetourError::NotStarted.source().is_none());
    let nested = DetourError::CommitFailed {
        index: 1,
        kind: HookKind::Eat,
        source: Box::new(DetourError::InvalidParameter),
    };
    assert!(nested.source().is_some());
}

#[test]
fn detour_error_from_conversions() {
    let from_iat: DetourError = IatHookError::InvalidParameter.into();
    assert!(matches!(from_iat, DetourError::Iat(_)));

    let from_pat: DetourError = PatternError::Empty.into();
    assert!(matches!(from_pat, DetourError::Pattern(_)));

    let from_eat: DetourError = EatHookError::TargetNotFound.into();
    assert!(matches!(from_eat, DetourError::Eat(_)));

    let from_vtable: DetourError = VTableHookError::AllocationFailed.into();
    assert!(matches!(from_vtable, DetourError::Vtable(_)));
}

#[test]
fn iat_hook_error_display() {
    for err in [
        IatHookError::InvalidParameter,
        IatHookError::InvalidPeImage,
        IatHookError::ImportTableUnavailable,
        IatHookError::NameResolutionUnavailable,
        IatHookError::TargetNotFound,
        IatHookError::ProtectFailed(io_err()),
    ] {
        assert!(!err.to_string().is_empty());
    }
}

#[test]
fn eat_hook_error_display() {
    for err in [
        EatHookError::InvalidParameter,
        EatHookError::InvalidPeImage,
        EatHookError::ExportTableUnavailable,
        EatHookError::TargetNotFound,
        EatHookError::TargetIsForwarder,
        EatHookError::DetourUnreachable,
        EatHookError::AllocationFailed,
        EatHookError::ProtectFailed(io_err()),
    ] {
        assert!(!err.to_string().is_empty());
    }
}

#[test]
fn veh_hook_error_display() {
    for err in [
        VehHookError::InvalidParameter,
        VehHookError::NoFreeSlot,
        VehHookError::AlreadyHooked,
        VehHookError::HandlerRegistrationFailed,
    ] {
        assert!(!err.to_string().is_empty());
    }
}

#[test]
fn int3_hook_error_display() {
    for err in [
        Int3HookError::InvalidParameter,
        Int3HookError::NoFreeSlot,
        Int3HookError::AlreadyHooked,
        Int3HookError::HandlerRegistrationFailed,
        Int3HookError::PatchFailed,
    ] {
        assert!(!err.to_string().is_empty());
    }
}

#[test]
fn vtable_hook_error_display() {
    for err in [
        VTableHookError::InvalidParameter,
        VTableHookError::AllocationFailed,
        VTableHookError::ProtectFailed(io_err()),
    ] {
        assert!(!err.to_string().is_empty());
    }
}

#[test]
fn delay_hook_error_display() {
    for err in [
        DelayHookError::InvalidParameter,
        DelayHookError::LdrHookFailed,
    ] {
        assert!(!err.to_string().is_empty());
    }
}

#[test]
fn pattern_error_display_covers_every_variant() {
    for err in [
        PatternError::Empty,
        PatternError::InvalidToken("ZZ".to_string()),
        PatternError::InvalidMaskChar('q'),
        PatternError::MaskLengthMismatch { bytes: 3, mask: 2 },
    ] {
        assert!(!err.to_string().is_empty());
    }
}
