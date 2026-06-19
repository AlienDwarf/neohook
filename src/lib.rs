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
mod delay;
mod disasm;
mod eat;
mod iat;
mod int3;
mod introspect;
mod mem;
mod midhook;
mod module;
mod pe;
mod reentrancy;
pub mod registry;
mod resolve;
mod scan;
mod threads;
pub(crate) mod transaction;
mod veh;
mod vtable;

// Re-exports for public API
pub use crate::api::DetourTransaction;
pub use crate::code::detour_code_from_pointer;
pub use crate::delay::{DelayHook, DelayHookError};
pub use crate::eat::EatHookError;
pub use crate::iat::IatHookError;
pub use crate::int3::{Int3Hook, Int3HookError, MAX_HOOKS as INT3_MAX_HOOKS};
pub use crate::introspect::{
    ExportInfo, ImportInfo, ModuleInfo, enumerate_exports, enumerate_imports, enumerate_modules,
    get_entry_point,
};
pub use crate::midhook::{HookContext, MidHook, MidHookHandler};
pub use crate::module::{
    find_function, find_function_by_ordinal, get_module_handle, get_module_size,
};
pub use crate::pe::PeError;
pub use crate::reentrancy::ReentrancyGuard;
pub use crate::resolve::{resolve_call_target, resolve_relative, resolve_rip_relative};
pub use crate::scan::{
    Pattern, PatternError, scan, scan_all, scan_module, scan_module_all, scan_module_by_name,
    scan_range, scan_range_all,
};
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
    /// A byte signature could not be parsed.
    Pattern(crate::scan::PatternError),
    /// A byte signature parsed correctly but did not match anywhere in the
    /// target module.
    PatternNotFound,
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
            Self::Pattern(err) => write!(f, "Signature parse error: {err}"),
            Self::PatternNotFound => write!(f, "Signature did not match in the target module"),
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

impl From<crate::scan::PatternError> for DetourError {
    fn from(err: crate::scan::PatternError) -> Self {
        Self::Pattern(err)
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

/// Installs an inline hook whose detour is a **Rust closure** - so it can
/// capture environment (counters, channels, configuration) that a plain `fn`
/// detour cannot. The closure receives the original function as its first
/// argument, so it can forward to it.
///
/// This is something the C/C++ hooking libraries cannot express: their detours
/// must be bare function pointers. NeoHook generates a per-site shim that stores
/// the boxed closure and dispatches to it with the target's ABI.
///
/// # Syntax
///
/// ```rust,ignore
/// detour_closure!(
///     target_fn,                          // the function to hook
///     "system" fn(a: i32, b: i32) -> i32, // ABI + argument names/types + return
///     move |orig, a, b| orig(a, b) * 10,  // closure: first param is the original
/// )
/// ```
///
/// The argument **names** in the signature (`a`, `b`) are reused for the
/// closure's parameters. The first closure parameter (`orig`) is the original
/// function, typed `extern "<abi>" fn(<args>) -> <ret>`.
///
/// Returns `Result<Vec<Hook>, DetourError>`, exactly like [`detour_inline!`];
/// keep the returned value alive to keep the hook installed (RAII unhook on
/// drop).
///
/// # Caveats
///
/// - The closure is heap-allocated and **leaked** for the lifetime of the
///   process (the per-site shim references it through a `static`). Unhooking
///   stops it from being called but does not free it.
/// - Like any detour, the closure may run concurrently on multiple threads. It
///   is `FnMut`, so if it mutates captured state you are responsible for making
///   that state thread-safe.
///
/// # Example
///
/// ```rust,ignore
/// use neohook::detour_closure;
/// use std::sync::atomic::{AtomicU32, Ordering};
///
/// #[inline(never)]
/// extern "system" fn add(a: i32, b: i32) -> i32 { a + b }
///
/// let calls = AtomicU32::new(0);
/// let _hooks = detour_closure!(
///     add,
///     "system" fn(a: i32, b: i32) -> i32,
///     move |orig, a, b| {
///         calls.fetch_add(1, Ordering::Relaxed); // captured state!
///         orig(a, b) * 10
///     },
/// ).expect("hook failed");
///
/// assert_eq!(add(2, 3), 50);
/// ```
#[macro_export]
macro_rules! detour_closure {
    (
        $target:expr,
        $abi:literal fn ( $($arg:ident : $argty:ty),* $(,)? ) $(-> $ret:ty)?,
        $closure:expr $(,)?
    ) => {{
        // Concrete, monomorphic types derived from the provided signature.
        type __OrigFn = extern $abi fn($($argty),*) $(-> $ret)?;
        type __ClosureBox =
            ::std::boxed::Box<dyn ::std::ops::FnMut(__OrigFn, $($argty),*) $(-> $ret)?>;

        static __ORIG: ::std::sync::OnceLock<__OrigFn> = ::std::sync::OnceLock::new();
        static __CLOSURE: ::std::sync::atomic::AtomicPtr<__ClosureBox> =
            ::std::sync::atomic::AtomicPtr::new(::std::ptr::null_mut());

        // The detour the target is patched to jump to. Enters with the target's
        // ABI, loads the boxed closure, and dispatches with the original first.
        extern $abi fn __shim($($arg : $argty),*) $(-> $ret)? {
            let __p = __CLOSURE.load(::std::sync::atomic::Ordering::Acquire);
            let __orig = *__ORIG
                .get()
                .expect("neohook: closure detour original not set");
            // SAFETY: `__p` points at a leaked Box set during install and is
            // never freed while the hook is live.
            unsafe { (&mut **__p)(__orig $(, $arg)*) }
        }

        // Box the closure twice: the inner Box is the `dyn FnMut`, the outer Box
        // owns it so we can hand a stable `*mut __ClosureBox` to the shim.
        let __boxed: ::std::boxed::Box<__ClosureBox> =
            ::std::boxed::Box::new(::std::boxed::Box::new($closure));
        __CLOSURE.store(
            ::std::boxed::Box::into_raw(__boxed),
            ::std::sync::atomic::Ordering::Release,
        );

        let mut __session = $crate::DetourTransaction::begin();
        __session.update_all_threads();
        match __session.attach($target as *mut u8, __shim as *const u8) {
            ::std::result::Result::Ok(__tramp) => {
                let __orig_fn: __OrigFn = unsafe { ::std::mem::transmute(__tramp) };
                let _ = __ORIG.set(__orig_fn);
                __session.commit()
            }
            ::std::result::Result::Err(__e) => ::std::result::Result::Err(__e),
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

    #[inline(never)]
    extern "system" fn closure_add(a: i32, b: i32) -> i32 {
        std::hint::black_box(a) + std::hint::black_box(b)
    }

    #[test]
    fn detour_closure_captures_environment_and_forwards_to_original() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        let calls = Arc::new(AtomicU32::new(0));
        let calls_in = Arc::clone(&calls);

        let target: extern "system" fn(i32, i32) -> i32 = closure_add;
        assert_eq!(target(2, 3), 5, "sanity before hook");

        let hooks = detour_closure!(
            closure_add,
            "system" fn(a: i32, b: i32) -> i32,
            move |orig, a, b| {
                // Captured state - impossible with a bare fn detour.
                calls_in.fetch_add(1, Ordering::Relaxed);
                orig(a, b) * 10
            },
        )
        .expect("closure hook should install");

        assert_eq!(target(2, 3), 50, "(2 + 3) * 10 via the closure detour");
        assert_eq!(target(4, 5), 90, "(4 + 5) * 10");
        assert_eq!(calls.load(Ordering::Relaxed), 2, "closure captured the counter");

        drop(hooks); // RAII restores the original.
        assert_eq!(target(2, 3), 5, "original restored after unhook");
    }
}
