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
//!
//! When the hooked module is unloaded, the hook drops back to pending (and is
//! installed again on the next load) without writing to the old address. Unloads
//! are observed through `LdrRegisterDllNotification`; the notification is
//! registered with the first delay hook and unregistered with the last.

use std::ffi::{CString, c_void};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Mutex, TryLockError};

use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    GetModuleHandleExW, GetProcAddress,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

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
    /// Base of the module image holding the hook's target, recorded at install.
    /// (A forwarded export can live in another module than `module`.)
    module_base: usize,
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

/// Trampoline to the real `LdrLoadDll`. Replaced on every install of the inline
/// hook, because removing the hook retires the previous trampoline.
static ORIG_LDR: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());

/// Set by the unload notification when it could not take the manager lock
/// without blocking; the next manager lock re-validates every installed hook.
static UNLOAD_MISSED: AtomicBool = AtomicBool::new(false);

/// Whether the unload notification is registered. Without it, every manager
/// lock re-validates installed hooks as if an unload had been missed.
static UNLOAD_NOTIFIED: AtomicBool = AtomicBool::new(false);

/// Cookie of the registered unload notification, or null.
static NOTIFICATION_COOKIE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// `LDR_DLL_NOTIFICATION_REASON_UNLOADED`.
const LDR_DLL_NOTIFICATION_REASON_UNLOADED: u32 = 2;

/// `LDR_DLL_UNLOADED_NOTIFICATION_DATA` (same layout as the loaded variant).
#[repr(C)]
struct LdrDllNotificationData {
    flags: u32,
    full_dll_name: *const c_void,
    base_dll_name: *const c_void,
    dll_base: *mut c_void,
    size_of_image: u32,
}

/// `VOID CALLBACK LdrDllNotification(ULONG, PCLDR_DLL_NOTIFICATION_DATA, PVOID)`.
type LdrDllNotificationFn =
    unsafe extern "system" fn(u32, *const LdrDllNotificationData, *mut c_void);

/// `NTSTATUS NTAPI LdrRegisterDllNotification(ULONG, PLDR_DLL_NOTIFICATION_FUNCTION,
/// PVOID, PVOID*)`.
type LdrRegisterDllNotificationFn =
    unsafe extern "system" fn(u32, LdrDllNotificationFn, *mut c_void, *mut *mut c_void) -> i32;

/// `NTSTATUS NTAPI LdrUnregisterDllNotification(PVOID)`.
type LdrUnregisterDllNotificationFn = unsafe extern "system" fn(*mut c_void) -> i32;

/// `STATUS_INTERNAL_ERROR`, returned if the detour runs without a trampoline.
const STATUS_INTERNAL_ERROR: i32 = 0xC000_00E5_u32 as i32;

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

        // Before any lock: registering takes the loader lock, which a thread
        // loading a library may hold while it waits for our locks.
        register_unload_notification();

        // Transaction lock before the manager: installing the LdrLoadDll hook
        // runs a transaction under the manager. The other order deadlocks
        // against a transaction whose LoadLibrary call waits for the manager in
        // the LdrLoadDll detour.
        crate::transaction::with_transaction_lock(|| unsafe {
            register_locked(module, func, detour)
        })
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
        // Only the manager and then the code lock: removing never waits for an
        // open transaction, so it is safe under the loader lock.
        let last = self.remove_locked();
        // Outside every lock, as registering is.
        if last {
            unregister_unload_notification();
        }
    }

    /// Removes the request; returns whether it was the last one.
    fn remove_locked(&mut self) -> bool {
        let mut mgr = lock_manager();
        if let Some(pos) = mgr.pending.iter().position(|p| p.id == self.id) {
            let pending = mgr.pending.remove(pos);
            if let Some(hook) = pending.hook {
                let _ = hook.unhook();
            }
        }
        // Once no delay hooks remain, retire the LdrLoadDll inline hook.
        if mgr.pending.is_empty()
            && let Some(hook) = mgr.ldr_hook.take()
        {
            let _ = hook.unhook();
        }
        mgr.pending.is_empty()
    }
}

impl Drop for DelayHook {
    fn drop(&mut self) {
        self.remove();
    }
}

/// Body of [`DelayHook::register`], run with the transaction lock held.
unsafe fn register_locked(
    module: &str,
    func: &str,
    detour: *const u8,
) -> Result<DelayHook, DelayHookError> {
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
        module_base: 0,
    };

    // If the module is already loaded, install right away.
    if let Some(target) = resolve_loaded(&pending.module, &pending.func) {
        pending.hook = unsafe { Int3Hook::install(target, detour) }.ok();
        pending.module_base = module_base_of(target).unwrap_or(0);
    }

    mgr.pending.push(pending);
    Ok(DelayHook { id })
}

/// Locks the manager, recovering from a poisoned mutex, and drops every hook
/// whose module is gone (see [`still_installed`]).
fn lock_manager() -> std::sync::MutexGuard<'static, DelayManager> {
    let mut mgr = MANAGER.lock().unwrap_or_else(|p| p.into_inner());
    let missed =
        UNLOAD_MISSED.swap(false, Ordering::AcqRel) || !UNLOAD_NOTIFIED.load(Ordering::Acquire);
    for pending in mgr.pending.iter_mut() {
        let stale = pending
            .hook
            .as_ref()
            .is_some_and(|hook| !still_installed(hook.target(), pending.module_base, missed));
        if stale && let Some(hook) = pending.hook.take() {
            hook.forget();
        }
    }
    mgr
}

/// Whether the hook at `target` still lives in the module image it was
/// installed into. `check_byte` also requires the `0xCC` to still be there,
/// which catches an unload and reload at the same base that the notification
/// did not get to handle.
fn still_installed(target: *const u8, module_base: usize, check_byte: bool) -> bool {
    if module_base == 0 || module_base_of(target) != Some(module_base) {
        return false;
    }
    !check_byte || read_entry_byte(target) == Some(0xCC)
}

/// Reads the byte at `target`, or `None` if it is not mapped. The module can be
/// unloaded by another thread right after its base was looked up, so a plain
/// read could fault.
fn read_entry_byte(target: *const u8) -> Option<u8> {
    let mut byte = 0u8;
    let mut read = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            target.cast(),
            (&mut byte as *mut u8).cast(),
            1,
            &mut read,
        )
    };
    (ok != 0 && read == 1).then_some(byte)
}

/// Base of the loaded module image containing `addr`, if any.
fn module_base_of(addr: *const u8) -> Option<usize> {
    let mut module: HMODULE = std::ptr::null_mut();
    let ok = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            addr as *const u16,
            &mut module,
        )
    };
    (ok != 0 && !module.is_null()).then_some(module as usize)
}

/// Registers [`on_dll_notification`] unless it already is.
///
/// Lock-free: a register racing the unregister of the last hook can end up
/// with a pending hook but no notification, which [`lock_manager`] covers by
/// re-validating every installed hook while none is registered; the next
/// register restores it.
fn register_unload_notification() {
    if !NOTIFICATION_COOKIE.load(Ordering::Acquire).is_null() {
        return;
    }
    let Some(register) = crate::find_function("ntdll.dll", "LdrRegisterDllNotification") else {
        return;
    };
    // SAFETY: the export has the documented signature.
    let register =
        unsafe { std::mem::transmute::<*const u8, LdrRegisterDllNotificationFn>(register) };
    let mut cookie = std::ptr::null_mut();
    let status = unsafe { register(0, on_dll_notification, std::ptr::null_mut(), &mut cookie) };
    if status < 0 || cookie.is_null() {
        return;
    }
    if NOTIFICATION_COOKIE
        .compare_exchange(
            std::ptr::null_mut(),
            cookie,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
    {
        UNLOAD_NOTIFIED.store(true, Ordering::Release);
    } else {
        // Another thread registered one meanwhile.
        unsafe { unregister_cookie(cookie) };
    }
}

/// Unregisters [`on_dll_notification`], so a module holding neohook can be
/// unloaded once its last delay hook is gone. The loader waits for a running
/// callback before it returns.
fn unregister_unload_notification() {
    UNLOAD_NOTIFIED.store(false, Ordering::Release);
    let cookie = NOTIFICATION_COOKIE.swap(std::ptr::null_mut(), Ordering::AcqRel);
    if !cookie.is_null() {
        unsafe { unregister_cookie(cookie) };
    }
}

unsafe fn unregister_cookie(cookie: *mut c_void) {
    let Some(unregister) = crate::find_function("ntdll.dll", "LdrUnregisterDllNotification") else {
        return;
    };
    // SAFETY: the export has the documented signature.
    let unregister =
        unsafe { std::mem::transmute::<*const u8, LdrUnregisterDllNotificationFn>(unregister) };
    unsafe { unregister(cookie) };
}

/// Loader notification: on an unload, drops the hooks whose target lies in the
/// unloaded image without writing to it, so they install again on the next
/// load.
///
/// Runs under the loader lock, so it never blocks: if the manager is busy, it
/// flags the unload and the next [`lock_manager`] re-validates instead.
unsafe extern "system" fn on_dll_notification(
    reason: u32,
    data: *const LdrDllNotificationData,
    _context: *mut c_void,
) {
    if reason != LDR_DLL_NOTIFICATION_REASON_UNLOADED || data.is_null() {
        return;
    }
    let base = unsafe { (*data).dll_base } as usize;
    let end = base.saturating_add(unsafe { (*data).size_of_image } as usize);

    let mut mgr = match MANAGER.try_lock() {
        Ok(mgr) => mgr,
        Err(TryLockError::Poisoned(p)) => p.into_inner(),
        Err(TryLockError::WouldBlock) => {
            UNLOAD_MISSED.store(true, Ordering::Release);
            return;
        }
    };
    for pending in mgr.pending.iter_mut() {
        let unloaded = pending
            .hook
            .as_ref()
            .is_some_and(|hook| (base..end).contains(&(hook.target() as usize)));
        if unloaded && let Some(hook) = pending.hook.take() {
            hook.forget();
        }
    }
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

    let target =
        crate::find_function("ntdll.dll", "LdrLoadDll").ok_or(DelayHookError::LdrHookFailed)?;

    let mut tx = TransactionCore::begin();
    tx.update_all_threads();
    let tramp = tx
        .attach(target as *mut u8, hooked_ldr_load_dll as *const u8)
        .map_err(|_| DelayHookError::LdrHookFailed)?;
    // Publish the trampoline before the commit makes the detour reachable, so
    // a load racing with the install already forwards to the real LdrLoadDll.
    ORIG_LDR.store(tramp, Ordering::Release);
    let hooks = tx.commit().map_err(|_| DelayHookError::LdrHookFailed)?;

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
    let tramp = ORIG_LDR.load(Ordering::Acquire);
    if tramp.is_null() {
        // Never report success for a load that did not happen.
        return STATUS_INTERNAL_ERROR;
    }
    // SAFETY: `tramp` is the trampoline of the live LdrLoadDll hook.
    let orig = unsafe { std::mem::transmute::<*mut u8, LdrLoadDllFn>(tramp) };
    let status = unsafe { orig(path, flags, name, handle) };

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
            // This runs under the loader lock. The INT3 install waits only for
            // the code lock, whose holders never wait for the loader lock.
            pending.hook = unsafe { Int3Hook::install(target, pending.detour) }.ok();
            pending.module_base = module_base_of(target).unwrap_or(0);
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
        let hook =
            unsafe { DelayHook::register("winmm.dll", "timeGetTime", fake_time as *const u8) }
                .expect("register should succeed");

        // Force the load; our LdrLoadDll detour installs the pending hook.
        let module = unsafe { LoadLibraryW(wide("winmm.dll").as_ptr()) };
        assert!(!module.is_null(), "winmm.dll should load");

        assert!(
            hook.is_active(),
            "the hook should be active after the module is loaded"
        );

        // Resolve and call the real export: the INT3 redirect should win.
        let proc = unsafe { GetProcAddress(module, c"timeGetTime".as_ptr() as *const u8) }
            .expect("timeGetTime should resolve");
        let time_get_time: unsafe extern "system" fn() -> u32 =
            unsafe { std::mem::transmute(proc) };
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

    #[test]
    fn unload_notification_is_unregistered_with_the_last_hook() {
        // A module that unloads after removing its delay hooks must not leave
        // the loader calling into its unmapped notification callback.
        let hook =
            unsafe { DelayHook::register("kernel32.dll", "GetTickCount", fake_time as *const u8) }
                .expect("register");
        assert!(
            UNLOAD_NOTIFIED.load(Ordering::Acquire),
            "notification registered while a delay hook exists"
        );
        drop(hook);
        assert!(
            !UNLOAD_NOTIFIED.load(Ordering::Acquire),
            "notification unregistered with the last delay hook"
        );
    }

    #[test]
    fn stale_check_survives_a_module_unmapped_after_the_lookup() {
        use windows_sys::Win32::System::Memory::{
            MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
        };
        // The module can be unloaded between finding its base and reading the
        // entry byte; the read must then fail instead of faulting.
        let page = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                0x1000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        } as *mut u8;
        assert!(!page.is_null());
        unsafe { *page = 0xCC };
        assert_eq!(read_entry_byte(page), Some(0xCC));
        unsafe { VirtualFree(page.cast(), 0, MEM_RELEASE) };
        assert_eq!(read_entry_byte(page), None);
    }

    #[test]
    fn int3_handler_goes_with_a_delay_hook_whose_module_was_unloaded() {
        use windows_sys::Win32::Foundation::FreeLibrary;
        // A module nothing else in the test process loads, so it really
        // unloads.
        let name = wide("msimg32.dll");
        let module = unsafe { LoadLibraryW(name.as_ptr()) };
        assert!(!module.is_null(), "msimg32.dll loads");
        let hook =
            unsafe { DelayHook::register("msimg32.dll", "AlphaBlend", fake_time as *const u8) }
                .expect("register");
        assert!(hook.is_active(), "installed right away");
        assert_ne!(unsafe { FreeLibrary(module) }, 0);
        assert!(!hook.is_active(), "dropped back to pending by the unload");

        drop(hook);
        assert!(
            !crate::int3::handler_registered(),
            "the INT3 handler outlived the last delay hook"
        );
    }

    unsafe extern "system" fn fake_tick_count() -> u32 {
        0x1234_5678
    }

    /// The trampoline `hooked_ldr_load_dll` forwards to right now.
    fn forwarded_ldr() -> *const u8 {
        ORIG_LDR.load(Ordering::Acquire)
    }

    #[test]
    fn reregistering_forwards_to_the_new_ldr_trampoline() {
        // kernel32 is always loaded, so these install immediately; only the
        // LdrLoadDll hook lifecycle matters here.
        let first = unsafe {
            DelayHook::register("kernel32.dll", "GetTickCount", fake_tick_count as *const u8)
        }
        .expect("first register");
        drop(first);

        let second = unsafe {
            DelayHook::register("kernel32.dll", "GetTickCount", fake_tick_count as *const u8)
        }
        .expect("second register");

        let current = lock_manager()
            .ldr_hook
            .as_ref()
            .expect("LdrLoadDll hook installed")
            .original_ptr();
        assert_eq!(
            forwarded_ldr(),
            current,
            "LdrLoadDll detour must forward to the trampoline of the live hook"
        );

        // Free the first trampoline, then load a module through the detour.
        crate::reclaim();
        let module = unsafe { LoadLibraryW(wide("version.dll").as_ptr()) };
        assert!(
            !module.is_null(),
            "a load through the re-installed hook works"
        );

        drop(second);
    }
}
