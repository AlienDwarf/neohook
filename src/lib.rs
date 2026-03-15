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
mod disasm;
mod iat;
mod mem;
mod module;
mod threads;
pub(crate) mod transaction;

// Re-exports for public API
pub use crate::api::DetourTransaction;
pub use crate::iat::IatHookError;
pub use crate::module::{find_function, get_module_handle, get_module_size};
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
    /// An error occurred while installing an IAT hook.
    Iat(crate::iat::IatHookError),
}

impl fmt::Display for DetourError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotStarted => write!(f, "Transaction not started or already finished"),
            Self::AllocationFailed => write!(f, "Failed to allocate memory for trampoline"),
            Self::RelocationFailed => write!(f, "Failed to relocate instructions to trampoline"),
            Self::InvalidParameter => write!(f, "One or more parameters were invalid"),
            Self::Iat(err) => write!(f, "IAT hook error: {err}"),
        }
    }
}

impl From<crate::iat::IatHookError> for DetourError {
    fn from(err: crate::iat::IatHookError) -> Self {
        Self::Iat(err)
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
