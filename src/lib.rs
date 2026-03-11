// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! NeoHook: Hook any function with a single line.
//!
//! NeoHook is a high-performance hooking library for installing inline and IAT hooks on Windows.
//! By leveraging a transaction-based API, it allows applications to intercept function calls and redirect execution
//! without modifying the original source code.

use std::fmt;

pub mod alloc;
pub mod api;
pub mod disasm;
pub mod iat;
pub mod mem;
pub mod module;
pub mod threads;
pub(crate) mod transaction;

// Re-exports for public API
pub use crate::api::DetourTransaction;
pub use crate::transaction::{Hook, IatHook, InlineHook, JumpType, TransactionCore};

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
}

impl fmt::Display for DetourError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotStarted => write!(f, "Transaction not started or already finished"),
            Self::AllocationFailed => write!(f, "Failed to allocate memory for trampoline"),
            Self::RelocationFailed => write!(f, "Failed to relocate instructions to trampoline"),
            Self::InvalidParameter => write!(f, "One or more parameters were invalid"),
        }
    }
}

// Implement the standard Error trait for DetourError to allow it to be used with the `?` operator
impl std::error::Error for DetourError {}

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
        // Wir führen attach aus und merken uns das Ergebnis
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
                // OnceLock: try to set the trampoline function pointer
                // If already set, do nothing (can happen in multithread scenarios)
                let _ = $name.set(trampoline_fn);

                session.commit()
            }
            Err(e) => Err(e),
        }
    }};
}
