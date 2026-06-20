// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A process-wide registry of named hooks.
//!
//! By default a [`Hook`] is owned by whoever holds the `Vec<Hook>` returned from
//! [`crate::DetourTransaction::commit`], and it is unhooked when that value
//! drops. That is exactly what you want for scoped hooks, but in a long-lived
//! injected DLL it is often more convenient to park hooks in one place and refer
//! to them by name - toggling, removing, or tearing them all down without
//! threading a guard through your whole codebase.
//!
//! This module provides that shared store. [`register`] moves a hook in under a
//! name; [`enable`] / [`disable`] toggle it; [`unhook`] removes one; and
//! [`unhook_all`] tears everything down (useful from `DllMain` on
//! `DLL_PROCESS_DETACH`). All entries are dropped - and therefore unhooked - if
//! they are still present when the process exits.
//!
//! ```rust,ignore
//! use neohook::{registry, DetourTransaction};
//!
//! let mut tx = DetourTransaction::begin();
//! tx.update_all_threads();
//! tx.attach(target as *mut u8, detour as *const u8)?;
//! let mut hooks = tx.commit()?;
//!
//! registry::register("sleep", hooks.remove(0));
//! registry::disable("sleep")?;   // temporarily off
//! registry::enable("sleep")?;    // back on
//! registry::unhook_all();        // tear everything down
//! ```

use std::collections::HashMap;
use std::sync::Mutex;

use crate::DetourError;
use crate::transaction::Hook;

/// Wraps a [`Hook`] so it can live in a `static`.
///
/// A `Hook` holds raw target/trampoline pointers and is therefore not `Send` by
/// default. Those pointers are process-global code addresses with no thread
/// affinity, so moving the guard between threads is sound; the registry
/// serializes every access through its mutex.
struct SendHook(Hook);

// SAFETY: see `SendHook` docs - the wrapped pointers are process-global and all
// access is serialized by `REGISTRY`'s mutex.
unsafe impl Send for SendHook {}

/// The shared name -> hook table. `None` until the first `register`.
static REGISTRY: Mutex<Option<HashMap<String, SendHook>>> = Mutex::new(None);

/// Locks the registry, recovering from a poisoned mutex (the guarded map carries
/// no invariant a panic could corrupt).
fn lock() -> std::sync::MutexGuard<'static, Option<HashMap<String, SendHook>>> {
    REGISTRY.lock().unwrap_or_else(|p| p.into_inner())
}

/// Registers `hook` under `name`, returning the previous hook stored under that
/// name if one existed.
///
/// If a previous hook is returned it is **not** unhooked; ownership passes back
/// to the caller, who may drop it (unhooking) or keep it. To replace and unhook
/// in one step, call [`unhook`] first.
pub fn register(name: impl Into<String>, hook: Hook) -> Option<Hook> {
    let mut guard = lock();
    let map = guard.get_or_insert_with(HashMap::new);
    map.insert(name.into(), SendHook(hook)).map(|prev| prev.0)
}

/// Removes the hook registered under `name` and returns it without unhooking, so
/// the caller can decide what to do with it. Returns `None` if no such hook is
/// registered.
pub fn take(name: &str) -> Option<Hook> {
    let mut guard = lock();
    guard.as_mut().and_then(|m| m.remove(name)).map(|h| h.0)
}

/// Re-enables the hook registered under `name`.
///
/// Returns `Ok(true)` if a hook was found and enabled, `Ok(false)` if no hook is
/// registered under `name`, or an error if the toggle itself failed.
pub fn enable(name: &str) -> Result<bool, DetourError> {
    let mut guard = lock();
    match guard.as_mut().and_then(|m| m.get_mut(name)) {
        Some(h) => h.0.enable().map(|_| true),
        None => Ok(false),
    }
}

/// Disables the hook registered under `name` without removing it, so it can be
/// re-enabled later with [`enable`].
///
/// Returns `Ok(true)` if a hook was found and disabled, `Ok(false)` if no hook
/// is registered under `name`, or an error if the toggle itself failed.
pub fn disable(name: &str) -> Result<bool, DetourError> {
    let mut guard = lock();
    match guard.as_mut().and_then(|m| m.get_mut(name)) {
        Some(h) => h.0.disable().map(|_| true),
        None => Ok(false),
    }
}

/// Returns `Some(true)`/`Some(false)` for the enabled state of the hook
/// registered under `name`, or `None` if no such hook is registered.
pub fn is_enabled(name: &str) -> Option<bool> {
    let guard = lock();
    guard
        .as_ref()
        .and_then(|m| m.get(name))
        .map(|h| h.0.is_enabled())
}

/// Removes the hook registered under `name` and unhooks it, restoring the
/// original code or pointer.
///
/// Returns `Ok(true)` if a hook was removed and unhooked, `Ok(false)` if no hook
/// is registered under `name`, or an error if unhooking failed.
pub fn unhook(name: &str) -> Result<bool, DetourError> {
    let removed = {
        let mut guard = lock();
        guard.as_mut().and_then(|m| m.remove(name))
    };
    match removed {
        Some(h) => h.0.unhook().map(|_| true),
        None => Ok(false),
    }
}

/// Removes and unhooks **every** registered hook.
///
/// Each hook is dropped, which restores its target via RAII. Intended for a
/// single teardown point such as `DLL_PROCESS_DETACH`. Returns the number of
/// hooks that were torn down.
pub fn unhook_all() -> usize {
    let map = {
        let mut guard = lock();
        guard.take()
    };
    match map {
        Some(m) => {
            let n = m.len();
            drop(m); // dropping each SendHook(Hook) unhooks via RAII
            n
        }
        None => 0,
    }
}

/// Returns the names of all currently registered hooks.
pub fn names() -> Vec<String> {
    let guard = lock();
    guard
        .as_ref()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

/// Returns the number of currently registered hooks.
pub fn count() -> usize {
    let guard = lock();
    guard.as_ref().map(|m| m.len()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DetourTransaction;

    #[inline(never)]
    extern "system" fn reg_target() -> u32 {
        std::hint::black_box(7)
    }
    extern "system" fn reg_detour() -> u32 {
        std::hint::black_box(77)
    }

    fn install_one() -> Hook {
        let mut tx = DetourTransaction::begin();
        tx.update_all_threads();
        tx.attach(reg_target as *mut u8, reg_detour as *const u8)
            .expect("attach");
        let mut hooks = tx.commit().expect("commit");
        hooks.remove(0)
    }

    #[test]
    fn register_toggle_and_unhook_all() {
        let target: extern "system" fn() -> u32 = reg_target;
        assert_eq!(target(), 7, "sanity before hook");

        assert!(register("reg-a", install_one()).is_none());
        assert!(names().contains(&"reg-a".to_string()));
        assert_eq!(target(), 77, "hook should be active once registered");
        assert_eq!(is_enabled("reg-a"), Some(true));

        assert_eq!(disable("reg-a").unwrap(), true);
        assert_eq!(target(), 7, "disabled hook should not intercept");
        assert_eq!(is_enabled("reg-a"), Some(false));

        assert_eq!(enable("reg-a").unwrap(), true);
        assert_eq!(target(), 77, "re-enabled hook should intercept again");

        // Unknown names are reported, not errors.
        assert_eq!(enable("nope").unwrap(), false);
        assert_eq!(is_enabled("nope"), None);

        let torn = unhook_all();
        assert!(torn >= 1);
        assert_eq!(count(), 0);
        assert_eq!(target(), 7, "unhook_all should restore the original");
    }

    #[test]
    fn take_returns_without_unhooking() {
        register("reg-take", install_one());
        let hook = take("reg-take").expect("take should return the hook");
        assert_eq!(count(), 0);
        // Hook is still active until we drop/unhook it ourselves.
        let target: extern "system" fn() -> u32 = reg_target;
        assert_eq!(target(), 77, "taken hook is still installed");
        hook.unhook().expect("manual unhook");
        assert_eq!(target(), 7);
    }
}
