// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reentrancy / recursion protection for detours.
//!
//! A detour can end up invoking itself — directly, or because it calls other
//! code that dispatches back through the same hook (common with logging,
//! allocator, or COM method hooks). A [`ReentrancyGuard`] lets a detour notice
//! that it is already running on the current thread and take a different path,
//! typically forwarding straight to the original.

use std::cell::Cell;
use std::thread::LocalKey;

/// RAII guard that marks a region as "entered" on the current thread.
///
/// Obtain one with the [`reentrancy_guard!`](crate::reentrancy_guard) macro,
/// which declares a unique per-call-site thread-local flag:
///
/// ```rust,ignore
/// fn my_detour(x: i32) -> i32 {
///     let _guard = match neohook::reentrancy_guard!() {
///         Some(g) => g,                    // outermost entry on this thread
///         None => return call_original(x), // already inside -> just forward
///     };
///     // ... detour logic that is safe from re-entering itself ...
///     call_original(x)
/// }
/// ```
///
/// The flag is cleared automatically when the guard is dropped.
pub struct ReentrancyGuard {
    key: &'static LocalKey<Cell<bool>>,
}

impl ReentrancyGuard {
    /// Attempts to enter the region guarded by `key` on the current thread.
    ///
    /// Returns `Some(guard)` on the outermost entry, or `None` if the same
    /// thread is already inside the region (a reentrant call).
    ///
    /// Prefer the [`reentrancy_guard!`](crate::reentrancy_guard) macro, which
    /// supplies a fresh per-call-site key for you.
    pub fn enter(key: &'static LocalKey<Cell<bool>>) -> Option<Self> {
        key.with(|flag| {
            if flag.get() {
                None
            } else {
                flag.set(true);
                Some(Self { key })
            }
        })
    }
}

impl Drop for ReentrancyGuard {
    fn drop(&mut self) {
        self.key.with(|flag| flag.set(false));
    }
}

/// Declares a per-call-site thread-local flag and tries to enter its
/// [`ReentrancyGuard`].
///
/// Evaluates to `Option<ReentrancyGuard>`: `Some` on the outermost call on the
/// current thread, `None` if the current thread is already inside this call
/// site's guard. Each textual use of the macro gets its own independent flag.
#[macro_export]
macro_rules! reentrancy_guard {
    () => {{
        thread_local! {
            static __NEOHOOK_REENTRANCY: ::core::cell::Cell<bool> =
                const { ::core::cell::Cell::new(false) };
        }
        $crate::ReentrancyGuard::enter(&__NEOHOOK_REENTRANCY)
    }};
}
