// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! NeoHook: Hook any function with a single line.
//!
//! NeoHook is a high-performance hooking library for installing inline and IAT hooks on Windows.
//! By leveraging a transaction-based API, it allows applications to intercept function calls and redirect execution
//! without modifying the original source code.

#[cfg(not(windows))]
compile_error!("neohook only supports Windows.");
use std::fmt;

mod alloc;
pub mod api;
mod code;
mod disasm;
mod eat;
mod iat;
mod introspect;
mod mem;
mod module;
mod pe;
mod reentrancy;
mod threads;
pub(crate) mod transaction;
mod veh;
mod vtable;

// Re-exports for public API
pub use crate::api::DetourTransaction;
pub use crate::code::detour_code_from_pointer;
pub use crate::eat::EatHookError;
pub use crate::iat::IatHookError;
pub use crate::introspect::{
    ExportInfo, ImportInfo, ModuleInfo, enumerate_exports, enumerate_imports, enumerate_modules,
    get_entry_point,
};
pub use crate::module::{
    find_function, find_function_by_ordinal, get_module_handle, get_module_size,
};
pub use crate::pe::PeError;
pub use crate::reentrancy::ReentrancyGuard;
pub use crate::transaction::{
    EatHook, Hook, IatHook, InlineHook, JumpType, TransactionCore, VtableHook, VtableInstanceHook,
};
pub use crate::veh::{VehHook, VehHookError};
pub use crate::vtable::VTableHookError;

/// Identifies which kind of hook a [`DetourError::CommitFailed`] refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookKind {
    Inline,
    Iat,
    Eat,
    Vtable,
    VtableInstance,
    Detach,
}

impl fmt::Display for HookKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Inline => "inline",
            Self::Iat => "IAT",
            Self::Eat => "EAT",
            Self::Vtable => "VTable",
            Self::VtableInstance => "per-instance VTable",
            Self::Detach => "detach",
        };
        f.write_str(name)
    }
}

/// Errors that can occur while installing or managing detours.
#[derive(Debug)]
pub enum DetourError {
    /// The transaction has not been started or has already been finished.
    NotStarted,
    /// Allocating memory for a trampoline failed.
    AllocationFailed,
    /// Relocating the stolen instructions into the trampoline failed.
    RelocationFailed,
    /// One or more parameters were invalid.
    InvalidParameter,
    /// An error occurred while installing an IAT hook.
    Iat(crate::iat::IatHookError),
    /// An error occurred while installing an EAT hook.
    Eat(crate::eat::EatHookError),
    /// An error occurred while installing a VTable hook.
    Vtable(crate::vtable::VTableHookError),
    /// A pending hook failed to install during [`DetourTransaction::commit`].
    ///
    /// Reports the position of the failing hook in the order it was queued and
    /// its kind, along with the underlying error. All hooks installed earlier in
    /// the same commit have already been rolled back.
    CommitFailed {
        /// Index of the failing hook among the queued hooks (0-based).
        index: usize,
        /// Which kind of hook failed.
        kind: HookKind,
        /// The underlying error that caused the failure.
        source: Box<DetourError>,
    },
}

impl fmt::Display for DetourError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotStarted => write!(f, "Transaction not started or already finished"),
            Self::AllocationFailed => write!(f, "Failed to allocate memory for trampoline"),
            Self::RelocationFailed => write!(f, "Failed to relocate instructions to trampoline"),
            Self::InvalidParameter => write!(f, "One or more parameters were invalid"),
            Self::Iat(err) => write!(f, "IAT hook error: {err}"),
            Self::Eat(err) => write!(f, "EAT hook error: {err}"),
            Self::Vtable(err) => write!(f, "VTable hook error: {err}"),
            Self::CommitFailed {
                index,
                kind,
                source,
            } => write!(
                f,
                "commit failed at {kind} hook #{index} (rolled back): {source}"
            ),
        }
    }
}

impl From<crate::iat::IatHookError> for DetourError {
    fn from(err: crate::iat::IatHookError) -> Self {
        Self::Iat(err)
    }
}

impl From<crate::eat::EatHookError> for DetourError {
    fn from(err: crate::eat::EatHookError) -> Self {
        Self::Eat(err)
    }
}

impl From<crate::vtable::VTableHookError> for DetourError {
    fn from(err: crate::vtable::VTableHookError) -> Self {
        Self::Vtable(err)
    }
}

// Implement the standard Error trait for DetourError to allow it to be used with the `?` operator
impl std::error::Error for DetourError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CommitFailed { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

/// Convenience macro for installing a single inline hook.
///
/// # Examples
/// if you just want to install a hook without handling the result, you can use:
/// ```rust,ignore
/// let hooks = detour_inline!(target_func, my_detour)?;
/// ```
/// A more common use case is to handle the result:
/// ```rust,ignore
/// let hook = detour_inline!(target_func, my_detour)
///     .expect("Hooking failed");
/// ```
#[macro_export]
macro_rules! detour_inline {
    ($target:expr, $detour:expr) => {{
        let mut session = $crate::DetourTransaction::begin();
        session.update_all_threads();
        match session.attach($target as *mut u8, $detour as *const u8) {
            Ok(_) => session.commit(),
            Err(e) => Err(e),
        }
    }};
}

/// Convenience macro for installing a hook and storing a typed trampoline
/// pointer to the original function.
///
/// # Examples
///
/// ```rust,ignore
/// use std::sync::OnceLock;
///
/// static ORIGINAL_FUNC: OnceLock<extern "C" fn(i32) -> i32> = OnceLock::new();
///
/// let hook = detour_helper!(
///     ORIGINAL_FUNC,
///     target_func,
///     my_detour,
///     extern "C" fn(i32) -> i32
/// )
/// .expect("Hooking failed");
/// ```
#[macro_export]
macro_rules! detour_helper {
    ($name:ident, $target:expr, $detour:expr, $sig:ty) => {{
        let mut session = $crate::DetourTransaction::begin();
        session.update_all_threads();

        match session.attach($target as *mut u8, $detour as *const u8) {
            Ok(tramp) => {
                let trampoline_fn: $sig = unsafe { std::mem::transmute(tramp) };

                if $name.set(trampoline_fn).is_err() {
                    Err($crate::DetourError::InvalidParameter)
                } else {
                    session.commit()
                }
            }
            Err(e) => Err(e),
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_failed_reports_index_kind_and_source() {
        let err = DetourError::CommitFailed {
            index: 2,
            kind: HookKind::Vtable,
            source: Box::new(DetourError::InvalidParameter),
        };

        let msg = err.to_string();
        assert!(
            msg.contains("VTable"),
            "message should name the hook kind: {msg}"
        );
        assert!(
            msg.contains("#2"),
            "message should include the hook index: {msg}"
        );

        // The underlying cause is reachable via Error::source.
        let source = std::error::Error::source(&err).expect("CommitFailed should expose a source");
        assert_eq!(
            source.to_string(),
            DetourError::InvalidParameter.to_string()
        );
    }

    #[test]
    fn hook_kind_display_names() {
        assert_eq!(HookKind::Inline.to_string(), "inline");
        assert_eq!(HookKind::Iat.to_string(), "IAT");
        assert_eq!(HookKind::Vtable.to_string(), "VTable");
        assert_eq!(HookKind::VtableInstance.to_string(), "per-instance VTable");
    }
}
