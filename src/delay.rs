// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Delay / on-load hooks: hook a function in a module that is not loaded yet.
//!
//! Every other hook in NeoHook needs the target to already be resolvable. But a
//! plugin DLL, a lazily-loaded codec, or a graphics backend chosen at runtime
//! may only appear *after* your code runs. A delay hook bridges that gap: you
//! register the module + export name up front, and NeoHook installs the hook the
//! moment that module is brought into the process.
//!
//! It works by inline-hooking `ntdll!LdrLoadDll` - the single chokepoint every
//! `LoadLibrary*` call funnels through - once, the first time you register. When
//! a load completes, NeoHook re-checks the pending list and installs any hook
//! whose module is now present. If the module is already loaded when you
//! register, the hook is installed immediately.
//!
//! The actual redirect uses an [`crate::int3::Int3Hook`] (a single `0xCC` byte
//! plus a vectored handler) rather than a jump-patch trampoline. This matters
//! because the install runs inside the `LdrLoadDll` call while the loader lock
//! is held: an INT3 hook needs no thread suspension, so it cannot deadlock
//! against the loader, whereas a thread-suspending inline patch could.
//!
//! ## Limitations
//!
//! * **Full replacement.** Like an INT3 or VEH hook, the detour replaces the
//!   target; there is no trampoline to call the original through.
//! * **Capacity.** Each installed delay hook consumes one INT3 slot
//!   ([`crate::int3::MAX_HOOKS`]).

use std::ffi::{CString, c_void};
use std::fmt;
use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::System::LibraryLoader::GetProcAddress;

use crate::int3::Int3Hook;
use crate::transaction::{Hook, TransactionCore};

/// `NTSTATUS NTAPI LdrLoadDll(PCWSTR, PULONG, PUNICODE_STRING, PVOID*)`.
type LdrLoadDllFn =
    unsafe extern "system" fn(*const u16, *mut u32, *const c_void, *mut *mut c_void) -> i32;

/// A single pending or active delay-hook request.
struct Pending {
    id: u64,
    /// Lower-cased module file name, e.g. `"winmm.dll"`.
    module: String,
    func: String,
    detour: *const u8,
    /// The active INT3 hook once the module has been loaded and resolved.
    hook: Option<Int3Hook>,
}

/// Shared state: the pending list plus the single inline hook on `LdrLoadDll`.
struct DelayManager {
    next_id: u64,
    pending: Vec<Pending>,
    /// The inline hook installed on `ntdll!LdrLoadDll`, present while any delay
    /// hook is registered.
    ldr_hook: Option<Hook>,
}

// SAFETY: `Hook`/`Int3Hook`/`*const u8` are not `Send` by default, but they hold
// process-global code addresses with no thread affinity and every access is
// serialized through `MANAGER`'s mutex.
unsafe impl Send for DelayManager {}

static MANAGER: Mutex<DelayManager> = Mutex::new(DelayManager {
    next_id: 1,
    pending: Vec::new(),
    ldr_hook: None,
});

/// Trampoline to the real `LdrLoadDll`, set when the inline hook is installed.
static ORIG_LDR: OnceLock<LdrLoadDllFn> = OnceLock::new();

/// Errors produced while registering a delay hook.
#[derive(Debug)]
pub enum DelayHookError {
    /// A null detour pointer or an empty module/function name was supplied.
    InvalidParameter,
    /// `ntdll!LdrLoadDll` could not be resolved or inline-hooked.
    LdrHookFailed,
}

impl fmt::Display for DelayHookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameter => write!(f, "invalid delay-hook parameters"),
            Self::LdrHookFailed => write!(f, "failed to hook ntdll!LdrLoadDll"),
        }
    }
}

impl std::error::Error for DelayHookError {}

/// A registered delay / on-load hook.
///
/// Created with [`DelayHook::register`]. The hook becomes active automatically
/// when its module is loaded (or immediately, if the module is already present).
/// Dropping the guard - or calling [`DelayHook::unhook`] - removes the pending
/// request and, if it was already installed, restores the original byte.
#[derive(Debug)]
pub struct DelayHook {
    id: u64,
}

impl DelayHook {
    /// Registers a hook to be installed when `module` is loaded.
    ///
    /// `module` is a DLL file name (e.g. `"d3d11.dll"`) and `func` is an exported
    /// function name. If `module` is already loaded, the hook is installed before
    /// this call returns.
    ///
    /// # Errors
    ///
    /// * [`DelayHookError::InvalidParameter`] if `detour` is null or a name is
    ///   empty.
    /// * [`DelayHookError::LdrHookFailed`] if the one-time `LdrLoadDll` hook could
    ///   not be installed.
    ///
    /// # Safety
    ///
    /// `detour` must be a function pointer with an ABI/signature compatible with
    /// the eventual target, since it is entered with the target's original
    /// register and stack state (full replacement, no trampoline).
    pub unsafe fn register(
        module: &str,
        func: &str,
        detour: *const u8,
    ) -> Result<Self, DelayHookError> {
        if detour.is_null() || module.is_empty() || func.is_empty() {
            return Err(DelayHookError::InvalidParameter);
        }

        let mut mgr = lock_manager();
        ensure_ldr_hook(&mut mgr)?;

        let id = mgr.next_id;
        mgr.next_id += 1;

        let mut pending = Pending {
            id,
            module: module.to_ascii_lowercase(),
            func: func.to_string(),
            detour,
            hook: None,
        };

        // If the module is already loaded, install right away.
        if let Some(target) = resolve_loaded(&pending.module, &pending.func) {
            pending.hook = unsafe { Int3Hook::install(target, detour) }.ok();
        }

        mgr.pending.push(pending);
        Ok(Self { id })
    }

    /// Returns whether the underlying module has been loaded and the hook is now
    /// actively installed (`true`), or still pending a load (`false`).
    pub fn is_active(&self) -> bool {
        let mgr = lock_manager();
        mgr.pending
            .iter()
            .find(|p| p.id == self.id)
            .map(|p| p.hook.is_some())
            .unwrap_or(false)
    }

    /// Removes the request and, if it was installed, restores the original byte.
    pub fn unhook(mut self) -> Result<(), DelayHookError> {
        self.remove();
        Ok(())
    }

    fn remove(&mut self) {
        let mut mgr = lock_manager();
        if let Some(pos) = mgr.pending.iter().position(|p| p.id == self.id) {
            let pending = mgr.pending.remove(pos);
            if let Some(hook) = pending.hook {
                let _ = hook.unhook();
            }
        }
        // Once no delay hooks remain, retire the LdrLoadDll inline hook.
        if mgr.pending.is_empty() {
            if let Some(hook) = mgr.ldr_hook.take() {
                let _ = hook.unhook();
            }
        }
    }
}

impl Drop for DelayHook {
    fn drop(&mut self) {
        self.remove();
    }
}

/// Locks the manager, recovering from a poisoned mutex.
fn lock_manager() -> std::sync::MutexGuard<'static, DelayManager> {
    MANAGER.lock().unwrap_or_else(|p| p.into_inner())
}

/// Resolves an export in a module **only if it is already loaded** (never
/// triggers a load), so the on-load detection observes natural loads.
fn resolve_loaded(module_lower: &str, func: &str) -> Option<*const u8> {
    let h = crate::get_module_handle(module_lower)?;
    let cfunc = CString::new(func).ok()?;
    let addr = unsafe { GetProcAddress(h, cfunc.as_ptr() as *const u8) };
    addr.map(|a| a as *const u8)
}

/// Installs the one-time inline hook on `ntdll!LdrLoadDll` if it is not already
/// present. Must be called with the manager lock held.
fn ensure_ldr_hook(mgr: &mut DelayManager) -> Result<(), DelayHookError> {
    if mgr.ldr_hook.is_some() {
        return Ok(());
    }

    let target = crate::find_function("ntdll.dll", "LdrLoadDll")
        .ok_or(DelayHookError::LdrHookFailed)?;

    let mut tx = TransactionCore::begin();
    tx.update_all_threads();
    let tramp = tx
        .attach(target as *mut u8, hooked_ldr_load_dll as *const u8)
        .map_err(|_| DelayHookError::LdrHookFailed)?;
    let hooks = tx.commit().map_err(|_| DelayHookError::LdrHookFailed)?;

    let _ = ORIG_LDR.set(unsafe { std::mem::transmute::<*mut u8, LdrLoadDllFn>(tramp) });
    mgr.ldr_hook = hooks.into_iter().next();
    Ok(())
}

/// Inline detour on `LdrLoadDll`: forward to the original, then - on success -
/// install any pending hook whose module just became resolvable.
unsafe extern "system" fn hooked_ldr_load_dll(
    path: *const u16,
    flags: *mut u32,
    name: *const c_void,
    handle: *mut *mut c_void,
) -> i32 {
    let status = match ORIG_LDR.get() {
        Some(orig) => unsafe { orig(path, flags, name, handle) },
        None => return 0,
    };

    // NT_SUCCESS(status): the module is mapped, so its exports can be resolved.
    if status >= 0 {
        install_ready_pending();
    }

    status
}

/// Walks the pending list and installs any not-yet-active hook whose module is
/// now loaded. Runs after a load completes; never holds the lock across a load.
fn install_ready_pending() {
    let mut mgr = lock_manager();
    for pending in mgr.pending.iter_mut() {
        if pending.hook.is_some() {
            continue;
        }
        if let Some(target) = resolve_loaded(&pending.module, &pending.func) {
            pending.hook = unsafe { Int3Hook::install(target, pending.detour) }.ok();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;

    unsafe extern "system" fn fake_time() -> u32 {
        0xABCD_1234
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    #[test]
    fn register_rejects_invalid_parameters() {
        assert!(matches!(
            unsafe { DelayHook::register("winmm.dll", "timeGetTime", std::ptr::null()) },
            Err(DelayHookError::InvalidParameter)
        ));
        assert!(matches!(
            unsafe { DelayHook::register("", "timeGetTime", fake_time as *const u8) },
            Err(DelayHookError::InvalidParameter)
        ));
    }

    #[test]
    fn installs_when_module_is_loaded_later() {
        // winmm.dll is usually not loaded into a fresh test process; registering
        // first and loading afterwards exercises the LdrLoadDll path. (If it is
        // already loaded, the immediate-install path still leaves the hook
        // active, so the end-state assertions below hold either way.)
        let hook = unsafe { DelayHook::register("winmm.dll", "timeGetTime", fake_time as *const u8) }
            .expect("register should succeed");

        // Force the load; our LdrLoadDll detour installs the pending hook.
        let module = unsafe { LoadLibraryW(wide("winmm.dll").as_ptr()) };
        assert!(!module.is_null(), "winmm.dll should load");

        assert!(
            hook.is_active(),
            "the hook should be active after the module is loaded"
        );

        // Resolve and call the real export: the INT3 redirect should win.
        let proc = unsafe {
            GetProcAddress(module, c"timeGetTime".as_ptr() as *const u8)
        }
        .expect("timeGetTime should resolve");
        let time_get_time: unsafe extern "system" fn() -> u32 = unsafe { std::mem::transmute(proc) };
        assert_eq!(
            unsafe { time_get_time() },
            0xABCD_1234,
            "delay hook should intercept the call"
        );

        hook.unhook().expect("unhook");
        assert_ne!(
            unsafe { time_get_time() },
            0xABCD_1234,
            "original should be restored after unhook"
        );
    }
}
