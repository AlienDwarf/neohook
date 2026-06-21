// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::DetourError;
use crate::introspect;
use crate::transaction::{Hook, TransactionCore};
use std::ffi::{CStr, CString, c_char, c_void};
use windows_sys::Win32::Foundation::HMODULE;

/// High-level wrapper around [`TransactionCore`].
///
/// This type provides an ergonomic transaction-based interface for installing
/// and managing detours. A transaction can be started with [`Self::begin`],
/// populated with pending hooks, and then either committed or aborted.
///
/// Any resources tracked by the transaction are cleaned up automatically when
/// the transaction is dropped.
#[repr(C)]
pub struct DetourTransaction {
    /// Internal transaction state.
    ///
    /// This is wrapped in an `Option` so the transaction can be safely moved
    /// out during [`Self::commit`] or [`Self::abort`], preventing accidental
    /// reuse after completion.
    pub(crate) inner: Option<TransactionCore>,
}

impl DetourTransaction {
    /// Begins a new detour transaction.
    ///
    /// The returned transaction can be used to register inline or IAT hooks and
    /// then apply them atomically with [`Self::commit`].
    pub fn begin() -> Self {
        Self {
            inner: Some(TransactionCore::begin()),
        }
    }

    /// Suspends the given thread and tracks it for the duration of the transaction.
    /// Will be resumed when the transaction is committed or aborted.
    ///
    /// The caller only provides the thread ID. NeoHook opens and owns the required thread handle internally.
    ///
    /// This can be used to keep other threads from executing code while hooks
    /// are being installed.
    ///
    /// # Errors
    ///
    /// Returns `Err(DetourError::NotStarted)` if the transaction has already
    /// been committed or aborted.
    pub fn update_thread(&mut self, thread_id: u32) -> Result<(), DetourError> {
        self.inner
            .as_mut()
            .ok_or(DetourError::NotStarted)?
            .update_thread(thread_id)
    }

    /// Suspends all threads in the current process except the calling thread and
    /// registers them to be resumed later.
    ///
    /// This is a convenience method for preparing a transaction before hooks are
    /// attached and committed.
    pub fn update_all_threads(&mut self) {
        if let Some(tx) = &mut self.inner {
            tx.update_all_threads();
        }
    }

    /// Registers an inline hook to be installed when the transaction is
    /// committed.
    ///
    /// On success, returns the trampoline pointer that can be used to call the
    /// original function body.
    ///
    /// # Errors
    ///
    /// Returns `Err(DetourError::NotStarted)` if the transaction has already
    /// been committed or aborted.
    ///
    /// Propagates any error that occurs while preparing the inline hook.
    pub fn attach(&mut self, target: *mut u8, detour: *const u8) -> Result<*mut u8, DetourError> {
        self.inner
            .as_mut()
            .ok_or(DetourError::NotStarted)?
            .attach(target, detour)
    }

    /// Resolves a byte signature inside a module and registers an inline hook on
    /// the matched address, to be installed when the transaction is committed.
    ///
    /// This is the signature-based counterpart to [`Self::attach`]: instead of a
    /// raw pointer or an export name, the target is located by scanning the
    /// module's executable regions for `pattern` (IDA / x64dbg syntax, e.g.
    /// `"48 8B 05 ?? ?? ?? ?? E8"`). The module is loaded if it is not already
    /// present. On success, returns the trampoline pointer that can be used to
    /// call the original function body.
    ///
    /// # Errors
    ///
    /// - [`DetourError::NotStarted`] if the transaction has already been
    ///   committed or aborted.
    /// - [`DetourError::Pattern`] if `pattern` is not a valid signature.
    /// - [`DetourError::PatternNotFound`] if the signature does not match in the
    ///   module (or the module could not be found/loaded).
    /// - Any error propagated while preparing the inline hook.
    pub fn attach_pattern(
        &mut self,
        module_name: &str,
        pattern: &str,
        detour: *const u8,
    ) -> Result<*mut u8, DetourError> {
        let pattern = crate::scan::Pattern::parse(pattern)?;
        let target = crate::scan::scan_module_by_name(module_name, &pattern)
            .ok_or(DetourError::PatternNotFound)?;

        self.inner
            .as_mut()
            .ok_or(DetourError::NotStarted)?
            .attach(target as *mut u8, detour)
    }

    /// Resolves an exported function by name and registers an inline hook on it,
    /// to be installed when the transaction is committed.
    ///
    /// This is the convenience counterpart to [`Self::attach`] for the common
    /// case of hooking a named export: instead of resolving the address yourself
    /// with `GetProcAddress`, pass the module and function name. The module is
    /// loaded if it is not already present (mirroring [`crate::find_function`]).
    /// On success, returns the trampoline pointer that can be used to call the
    /// original function body.
    ///
    /// Unlike [`Self::attach_iat`] / [`Self::attach_eat`] - which rewrite a
    /// single table slot - this patches the function body itself, so it
    /// intercepts **every** caller in the process, no matter how they resolved
    /// the address.
    ///
    /// # Errors
    ///
    /// - [`DetourError::NotStarted`] if the transaction has already been
    ///   committed or aborted.
    /// - [`DetourError::InvalidParameter`] if the module could not be
    ///   found/loaded or the export does not exist.
    /// - Any error propagated while preparing the inline hook.
    pub fn attach_export(
        &mut self,
        module_name: &str,
        function_name: &str,
        detour: *const u8,
    ) -> Result<*mut u8, DetourError> {
        let target = crate::find_function(module_name, function_name)
            .ok_or(DetourError::InvalidParameter)?;

        self.inner
            .as_mut()
            .ok_or(DetourError::NotStarted)?
            .attach(target as *mut u8, detour)
    }

    /// Registers an IAT hook to be installed when the transaction is committed.
    ///
    ///
    /// # Errors
    ///
    /// Returns `Err(DetourError::NotStarted)` if the transaction has already
    /// been committed or aborted.
    ///
    /// Propagates any error that occurs while preparing the IAT hook.
    pub fn attach_iat(
        &mut self,
        h_module: windows_sys::Win32::Foundation::HMODULE,
        target_dll: &str,
        target_func: &str,
        detour: *const u8,
    ) -> Result<(), DetourError> {
        self.inner
            .as_mut()
            .ok_or(DetourError::NotStarted)?
            .attach_iat(h_module, target_dll, target_func, detour)
    }

    /// Registers an EAT hook to be installed when the transaction is committed.
    ///
    /// Redirects the named export of `h_module` for every consumer that resolves
    /// it after commit (e.g. via `GetProcAddress`).
    ///
    /// # Errors
    ///
    /// Returns `Err(DetourError::NotStarted)` if the transaction has already
    /// been committed or aborted.
    ///
    /// Propagates any error that occurs while preparing the EAT hook (invalid
    /// module, missing export, or a forwarder target).
    pub fn attach_eat(
        &mut self,
        h_module: windows_sys::Win32::Foundation::HMODULE,
        target_func: &str,
        detour: *const u8,
    ) -> Result<(), DetourError> {
        self.inner
            .as_mut()
            .ok_or(DetourError::NotStarted)?
            .attach_eat(h_module, target_func, detour)
    }

    /// Registers a VTable hook to be installed when the transaction is committed.
    ///
    /// On success, returns the original function pointer currently stored in the
    /// selected VTable slot.
    ///
    /// # Errors
    ///
    /// Returns `Err(DetourError::NotStarted)` if the transaction has already
    /// been committed or aborted.
    ///
    /// Propagates VTable validation/protection errors from the transaction core.
    pub fn attach_vtable(
        &mut self,
        vtable: *mut *mut u8,
        index: usize,
        detour: *const u8,
    ) -> Result<*mut u8, DetourError> {
        self.inner
            .as_mut()
            .ok_or(DetourError::NotStarted)?
            .attach_vtable(vtable, index, detour)
    }

    /// Registers a per-instance VTable hook to be installed when the
    /// transaction is committed.
    ///
    /// The object's VTable is cloned so only that instance is affected.
    ///
    /// # Errors
    ///
    /// Returns `Err(DetourError::NotStarted)` if the transaction has already
    /// been committed or aborted.
    ///
    /// Propagates validation, protection, and allocation errors from the
    /// transaction core.
    pub fn attach_vtable_instance(
        &mut self,
        object_vptr: *mut *mut u8,
        index: usize,
        vtable_len: usize,
        detour: *const u8,
    ) -> Result<*mut u8, DetourError> {
        self.inner
            .as_mut()
            .ok_or(DetourError::NotStarted)?
            .attach_vtable_instance(object_vptr, index, vtable_len, detour)
    }

    /// Queues an installed hook to be detached when the transaction commits.
    ///
    /// If a later operation in the same transaction fails, the hook is
    /// re-enabled before the commit error is returned. On success, `hook` is
    /// made inert and dropping it afterwards is a no-op.
    pub fn detach(&mut self, hook: &mut Hook) -> Result<(), DetourError> {
        self.inner
            .as_mut()
            .ok_or(DetourError::NotStarted)?
            .detach(hook)
    }

    /// Commits the transaction and returns the installed hooks.
    ///
    /// All pending hooks are applied. On success, ownership of the installed
    /// hooks is returned to the caller.
    ///
    /// # Errors
    ///
    /// Returns `Err(DetourError::NotStarted)` if the transaction has already
    /// been committed or aborted.
    ///
    /// Propagates any error that occurs while applying the pending hooks.
    pub fn commit(mut self) -> Result<Vec<Hook>, DetourError> {
        let mut tx = self.inner.take().ok_or(DetourError::NotStarted)?;
        tx.commit()
    }

    /// Aborts the transaction and discards all pending hooks.
    ///
    /// Any tracked threads are resumed as part of the abort process. Calling
    /// this on an already finished transaction has no effect.
    pub fn abort(&mut self) {
        if let Some(mut tx) = self.inner.take() {
            tx.abort();
        }
    }

    #[cfg(debug_assertions)]
    pub fn dump_state(&self) {
        if let Some(inner) = &self.inner {
            inner.dump_state();
        }
    }
}

impl Drop for DetourTransaction {
    fn drop(&mut self) {
        self.abort();
    }
}

// ----------------- FFI Entry Points (C-Interfaces) -----------------

/// Resolves a function pointer to the first real code address by following
/// common leading jump stubs and import thunks.
///
/// Returns null if `pointer` is null. If the pointer does not reference a
/// recognized jump stub, the original pointer is returned.
///
/// # Safety
/// `pointer` and any thunk slots it references must point to readable process
/// memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_code_from_pointer(pointer: *const u8) -> *mut u8 {
    unsafe { crate::detour_code_from_pointer(pointer) }
}

/// Begins a new detour transaction and returns an opaque transaction pointer.
///
/// The returned pointer is owned by the caller and must later be passed to
/// another transaction API function, such as `detours_transaction_commit`.
///
/// Returns a non-null pointer on success.
#[unsafe(no_mangle)]
pub extern "C" fn detours_transaction_begin() -> *mut DetourTransaction {
    Box::into_raw(Box::new(DetourTransaction::begin()))
}

/// Opens, suspends, and tracks the thread identified by `thread_id`.
///
/// Returns `1` if the transaction pointer is valid and the request was accepted,
/// or `0` if `tx` is null or the transaction is no longer pending.
///
/// Invalid, inaccessible, or skipped thread IDs are treated as non-fatal and
/// still return `1`, matching NeoHook's best-effort thread tracking behavior.
///
/// # Safety
/// `tx` must be a valid transaction pointer previously returned by
/// `detours_transaction_begin()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_transaction_update_thread(
    tx: *mut DetourTransaction,
    thread_id: u32,
) -> i32 {
    if tx.is_null() {
        return 0;
    }

    let tx_ref = unsafe { &mut *tx };
    tx_ref.update_thread(thread_id).map(|_| 1).unwrap_or(0)
}

/// Attaches an inline detour to the given transaction.
///
///
/// Returns the trampoline pointer for the original function on success, or
/// null on failure.
///
/// The returned trampoline can be used to call the original function body.
///
/// # Safety
/// `tx` must be a valid transaction pointer previously returned by
/// `detours_transaction_begin()`.
/// `target` and `detour` must be valid pointers to the target function and
/// detour function, respectively.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_transaction_attach(
    tx: *mut DetourTransaction,
    target: *mut u8,
    detour: *const u8,
) -> *mut u8 {
    if tx.is_null() {
        return std::ptr::null_mut();
    }
    let tx_ref = unsafe { &mut *tx };

    tx_ref
        .attach(target, detour)
        .unwrap_or(std::ptr::null_mut())
}

/// Queues a single hook from an opaque hook handle to be detached when the
/// transaction commits.
///
/// On success, the selected hook is removed from `handle` during commit. The
/// handle remains valid and any other hooks stored in it remain active.
///
/// Returns `1` if the detach was queued, or `0` if `tx`/`handle` is null, the
/// transaction is no longer pending, or `idx` is out of bounds.
///
/// # Safety
/// `tx` must be a valid transaction pointer returned by
/// `detours_transaction_begin()`. `handle` must be a valid handle returned by
/// `detours_transaction_commit()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_transaction_detach(
    tx: *mut DetourTransaction,
    handle: *mut c_void,
    idx: usize,
) -> i32 {
    if tx.is_null() || handle.is_null() {
        return 0;
    }

    let tx_ref = unsafe { &mut *tx };
    tx_ref
        .inner
        .as_mut()
        .ok_or(DetourError::NotStarted)
        .and_then(|inner| unsafe { inner.detach_handle_index(handle, idx) })
        .map(|_| 1)
        .unwrap_or(0)
}

/// Commits a detour transaction and returns an opaque handle to the installed
/// hooks.
///
/// On success, returns a non-null opaque handle that can be queried with
/// `detours_handle_len()` and `detours_handle_get_original_ptr()`, and must
/// eventually be released with `detours_handle_unhook_and_free()`.
///
/// Returns null if the transaction could not be committed.
///
/// # Safety
/// `tx` must be a valid transaction pointer previously returned by
/// `detours_transaction_begin()`. Ownership of `tx` is consumed by this
/// function, regardless of success or failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_transaction_commit(tx: *mut DetourTransaction) -> *mut c_void {
    if tx.is_null() {
        return std::ptr::null_mut();
    }
    let tx_box = unsafe { Box::from_raw(tx) };
    match tx_box.commit() {
        Ok(v) => Box::into_raw(Box::new(v)) as *mut c_void,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Returns the number of installed hooks stored in an opaque hook handle.
///
/// Returns `0` if `handle` is null.
///
/// # Safety
/// `handle` must be a valid handle previously returned by
/// `detours_transaction_commit()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_handle_len(handle: *mut c_void) -> usize {
    if handle.is_null() {
        return 0;
    }
    let vec = unsafe { &*(handle as *mut Vec<Hook>) };
    vec.len()
}

/// Returns the original function pointer associated with the hook at `idx`.
///
/// For inline hooks, this is the trampoline entry managed by NeoHook.
/// For IAT hooks, this is the original imported function pointer.
///
/// Returns null if `handle` is null or if `idx` is out of bounds.
///
/// # Safety
/// `handle` must be a valid handle previously returned by
/// `detours_transaction_commit()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_handle_get_original_ptr(
    handle: *mut c_void,
    idx: usize,
) -> *const u8 {
    if handle.is_null() {
        return std::ptr::null();
    }
    let vec = unsafe { &*(handle as *mut Vec<Hook>) };

    vec.get(idx)
        .map(|d| d.original_ptr())
        .unwrap_or(std::ptr::null())
}

/// Enables (`enabled != 0`) or disables (`enabled == 0`) the hook at `idx`
/// without unhooking it.
///
/// Disabling restores the original code/pointer while keeping the hook
/// installed; enabling re-applies the detour. This is cheaper than a full
/// unhook/rehook cycle.
///
/// Returns `1` on success, `0` if `handle` is null, `idx` is out of bounds, or
/// the toggle failed.
///
/// # Safety
/// `handle` must be a valid handle previously returned by
/// `detours_transaction_commit()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_handle_set_enabled(
    handle: *mut c_void,
    idx: usize,
    enabled: i32,
) -> i32 {
    if handle.is_null() {
        return 0;
    }
    let vec = unsafe { &mut *(handle as *mut Vec<Hook>) };

    match vec.get_mut(idx) {
        Some(hook) => {
            let result = if enabled != 0 {
                hook.enable()
            } else {
                hook.disable()
            };
            result.map(|_| 1).unwrap_or(0)
        }
        None => 0,
    }
}

/// Returns `1` if the hook at `idx` is currently enabled, `0` otherwise (also
/// `0` if `handle` is null or `idx` is out of bounds).
///
/// # Safety
/// `handle` must be a valid handle previously returned by
/// `detours_transaction_commit()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_handle_is_enabled(handle: *mut c_void, idx: usize) -> i32 {
    if handle.is_null() {
        return 0;
    }
    let vec = unsafe { &*(handle as *mut Vec<Hook>) };
    vec.get(idx).map(|h| h.is_enabled() as i32).unwrap_or(0)
}

/// Unhooks all installed hooks referenced by `handle` and frees the handle.
///
/// Dropping the internal hook vector triggers unhooking through RAII.
///
/// Returns 1 if the handle was accepted for destruction, 0 if null.
///
/// # Safety
/// `handle` must be a valid handle previously returned by
/// `detours_transaction_commit()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_handle_unhook_and_free(handle: *mut c_void) -> i32 {
    if handle.is_null() {
        return 0;
    }
    let _vec_box = unsafe { Box::from_raw(handle as *mut Vec<Hook>) };
    // Dropping the vector drops all hooks, which triggers unhooking via RAII.
    1
}

/// Attaches an IAT detour to the given transaction.
///
/// Returns `1` on success and `0` on failure.
///
/// # Safety
/// `tx` must be a valid transaction pointer previously returned by
/// `detours_transaction_begin()`. `h_module` must be a valid module handle
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_transaction_attach_iat(
    tx: *mut DetourTransaction,
    h_module: *mut core::ffi::c_void,
    target_dll: *const std::ffi::c_char,
    target_func: *const std::ffi::c_char,
    detour: *const u8,
) -> i32 {
    if tx.is_null() || target_dll.is_null() || target_func.is_null() || detour.is_null() {
        return 0;
    }

    let tx_ref = unsafe { &mut *tx };

    let target_dll = match unsafe { std::ffi::CStr::from_ptr(target_dll) }.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let target_func = match unsafe { std::ffi::CStr::from_ptr(target_func) }.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    tx_ref
        .attach_iat(
            h_module as windows_sys::Win32::Foundation::HMODULE,
            target_dll,
            target_func,
            detour,
        )
        .map(|_| 1)
        .unwrap_or(0)
}

/// Attaches an EAT detour to the given transaction.
///
/// Redirects the named export of `h_module` for consumers that resolve it after
/// commit. Returns `1` on success and `0` on failure.
///
/// # Safety
/// `tx` must be a valid transaction pointer previously returned by
/// `detours_transaction_begin()`. `h_module` must be a valid module handle and
/// `target_func` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_transaction_attach_eat(
    tx: *mut DetourTransaction,
    h_module: *mut core::ffi::c_void,
    target_func: *const std::ffi::c_char,
    detour: *const u8,
) -> i32 {
    if tx.is_null() || target_func.is_null() || detour.is_null() {
        return 0;
    }

    let tx_ref = unsafe { &mut *tx };

    let target_func = match unsafe { std::ffi::CStr::from_ptr(target_func) }.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    tx_ref
        .attach_eat(
            h_module as windows_sys::Win32::Foundation::HMODULE,
            target_func,
            detour,
        )
        .map(|_| 1)
        .unwrap_or(0)
}

/// Attaches a VTable detour to the given transaction.
///
/// Returns the original function pointer in the selected slot on success,
/// or null on failure.
///
/// # Safety
/// `tx` must be a valid transaction pointer previously returned by
/// `detours_transaction_begin()`. `vtable` must point to a valid VTable and
/// `index` must refer to an existing slot. `detour` must have a compatible
/// ABI/signature for the selected virtual method.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_transaction_attach_vtable(
    tx: *mut DetourTransaction,
    vtable: *mut *mut u8,
    index: usize,
    detour: *const u8,
) -> *mut u8 {
    if tx.is_null() || vtable.is_null() || detour.is_null() {
        return std::ptr::null_mut();
    }

    let tx_ref = unsafe { &mut *tx };

    tx_ref
        .attach_vtable(vtable, index, detour)
        .unwrap_or(std::ptr::null_mut())
}

/// Attaches a per-instance VTable detour to the given transaction.
///
/// Returns the original function pointer stored in the selected slot on
/// success, or null on failure.
///
/// # Safety
/// `tx` must be a valid transaction pointer previously returned by
/// `detours_transaction_begin()`. `object_vptr` must point to the object's
/// vptr field, and `vtable_len` must cover the entire VTable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_transaction_attach_vtable_instance(
    tx: *mut DetourTransaction,
    object_vptr: *mut *mut u8,
    index: usize,
    vtable_len: usize,
    detour: *const u8,
) -> *mut u8 {
    if tx.is_null() || object_vptr.is_null() || detour.is_null() {
        return std::ptr::null_mut();
    }

    let tx_ref = unsafe { &mut *tx };

    tx_ref
        .attach_vtable_instance(object_vptr, index, vtable_len, detour)
        .unwrap_or(std::ptr::null_mut())
}

/// Suspends all threads in the current process except the calling thread and
/// registers them to be resumed later as part of the transaction.
///
/// Returns `1` if the transaction pointer is valid and the request was accepted,
/// or `0` if `tx` is null or the transaction is no longer pending.
///
/// # Safety
/// `tx` must be a valid transaction pointer previously returned by
/// `detours_transaction_begin()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_transaction_update_all_threads(tx: *mut DetourTransaction) -> i32 {
    if tx.is_null() {
        return 0;
    }

    let tx_ref = unsafe { &mut *tx };
    if tx_ref.inner.is_none() {
        return 0;
    }

    tx_ref.update_all_threads();
    1
}

/// Aborts the given transaction, discarding all pending hooks and resuming any
/// tracked threads.
///
/// Calling this on an already finished transaction has no effect.
///
/// # Safety
/// `tx` must be a valid transaction pointer previously returned by
/// `detours_transaction_begin()`. Ownership of `tx` is consumed by this
/// function and it must not be used again afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_transaction_abort(tx: *mut DetourTransaction) -> i32 {
    if tx.is_null() {
        return 0;
    }

    let mut tx_box = unsafe { Box::from_raw(tx) };
    tx_box.abort();
    1
}

// ----------------- FFI Entry Points: Module / PE Introspection -----------------
//
// Variable-length results (modules / exports / imports) follow NeoHook's opaque
// handle pattern: an enumerate call returns a boxed handle, the caller queries
// the length and indexes individual fields, then releases the handle with the
// matching `*_free` function. String fields are returned as `const char*`
// pointers that stay valid until the handle is freed.

/// Sentinel returned by `detours_imports_ordinal` for a by-name import.
const IMPORT_BY_NAME: u32 = u32::MAX;

struct ModuleEntryC {
    base: *mut c_void,
    size: u32,
    name: CString,
}

struct ExportEntryC {
    ordinal: u32,
    name: Option<CString>,
    address: *const u8,
    forwarder: Option<CString>,
}

struct ImportEntryC {
    dll: CString,
    name: Option<CString>,
    ordinal: Option<u16>,
    address: *const u8,
}

fn to_cstring(s: String) -> CString {
    CString::new(s).unwrap_or_default()
}

/// Enumerates the modules loaded in the calling process.
///
/// Returns an opaque handle to be queried with `detours_modules_len()` /
/// `detours_modules_*()` and released with `detours_modules_free()`. The handle
/// is non-null even when no modules are reported.
#[unsafe(no_mangle)]
pub extern "C" fn detours_enumerate_modules() -> *mut c_void {
    let entries: Vec<ModuleEntryC> = introspect::enumerate_modules()
        .into_iter()
        .map(|m| ModuleEntryC {
            base: m.base,
            size: m.size,
            name: to_cstring(m.name),
        })
        .collect();
    Box::into_raw(Box::new(entries)) as *mut c_void
}

/// Returns the number of modules in a handle from `detours_enumerate_modules()`.
///
/// Returns `0` if `handle` is null.
///
/// # Safety
/// `handle` must be a valid handle returned by `detours_enumerate_modules()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_modules_len(handle: *mut c_void) -> usize {
    if handle.is_null() {
        return 0;
    }
    unsafe { &*(handle as *mut Vec<ModuleEntryC>) }.len()
}

/// Returns the base address (`HMODULE`) of the module at `idx`, or null if
/// `handle` is null or `idx` is out of bounds.
///
/// # Safety
/// `handle` must be a valid handle returned by `detours_enumerate_modules()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_modules_base(handle: *mut c_void, idx: usize) -> *mut c_void {
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let vec = unsafe { &*(handle as *mut Vec<ModuleEntryC>) };
    vec.get(idx).map(|m| m.base).unwrap_or(std::ptr::null_mut())
}

/// Returns the image size of the module at `idx`, or `0` if `handle` is null or
/// `idx` is out of bounds.
///
/// # Safety
/// `handle` must be a valid handle returned by `detours_enumerate_modules()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_modules_size(handle: *mut c_void, idx: usize) -> u32 {
    if handle.is_null() {
        return 0;
    }
    let vec = unsafe { &*(handle as *mut Vec<ModuleEntryC>) };
    vec.get(idx).map(|m| m.size).unwrap_or(0)
}

/// Returns the file name of the module at `idx` as a NUL-terminated string, or
/// null if `handle` is null or `idx` is out of bounds. The pointer is valid
/// until the handle is freed.
///
/// # Safety
/// `handle` must be a valid handle returned by `detours_enumerate_modules()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_modules_name(handle: *mut c_void, idx: usize) -> *const c_char {
    if handle.is_null() {
        return std::ptr::null();
    }
    let vec = unsafe { &*(handle as *mut Vec<ModuleEntryC>) };
    vec.get(idx)
        .map(|m| m.name.as_ptr())
        .unwrap_or(std::ptr::null())
}

/// Frees a module handle returned by `detours_enumerate_modules()`.
///
/// # Safety
/// `handle` must be a valid handle returned by `detours_enumerate_modules()`
/// and must not be used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_modules_free(handle: *mut c_void) {
    if !handle.is_null() {
        drop(unsafe { Box::from_raw(handle as *mut Vec<ModuleEntryC>) });
    }
}

/// Returns the entry point of the module identified by `h_module`.
///
/// When `h_module` is null, the entry point of the main executable is returned.
/// Returns null if the module headers are invalid or it has no entry point.
///
/// # Safety
/// `h_module`, when non-null, must be the base address of a valid PE module
/// loaded in the current process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_get_entry_point(h_module: *mut c_void) -> *mut u8 {
    introspect::get_entry_point(h_module as HMODULE)
        .map(|p| p as *mut u8)
        .unwrap_or(std::ptr::null_mut())
}

/// Enumerates the exports (EAT) of the module identified by `h_module`.
///
/// Returns an opaque handle to be queried with `detours_exports_len()` /
/// `detours_exports_*()` and released with `detours_exports_free()`. Returns
/// null if the module's PE headers are invalid.
///
/// # Safety
/// `h_module` must be the base address of a valid PE module loaded in the
/// current process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_enumerate_exports(h_module: *mut c_void) -> *mut c_void {
    let exports = match unsafe { introspect::enumerate_exports(h_module as HMODULE) } {
        Ok(v) => v,
        Err(_) => return std::ptr::null_mut(),
    };

    let entries: Vec<ExportEntryC> = exports
        .into_iter()
        .map(|e| ExportEntryC {
            ordinal: e.ordinal,
            name: e.name.map(to_cstring),
            address: e.address,
            forwarder: e.forwarder.map(to_cstring),
        })
        .collect();
    Box::into_raw(Box::new(entries)) as *mut c_void
}

/// Returns the number of exports in a handle from `detours_enumerate_exports()`.
///
/// Returns `0` if `handle` is null.
///
/// # Safety
/// `handle` must be a valid handle returned by `detours_enumerate_exports()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_exports_len(handle: *mut c_void) -> usize {
    if handle.is_null() {
        return 0;
    }
    unsafe { &*(handle as *mut Vec<ExportEntryC>) }.len()
}

/// Returns the ordinal of the export at `idx`, or `0` if `handle` is null or
/// `idx` is out of bounds.
///
/// # Safety
/// `handle` must be a valid handle returned by `detours_enumerate_exports()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_exports_ordinal(handle: *mut c_void, idx: usize) -> u32 {
    if handle.is_null() {
        return 0;
    }
    let vec = unsafe { &*(handle as *mut Vec<ExportEntryC>) };
    vec.get(idx).map(|e| e.ordinal).unwrap_or(0)
}

/// Returns the name of the export at `idx`, or null if it is exported by ordinal
/// only (or `handle` is null / `idx` is out of bounds). Valid until free.
///
/// # Safety
/// `handle` must be a valid handle returned by `detours_enumerate_exports()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_exports_name(handle: *mut c_void, idx: usize) -> *const c_char {
    if handle.is_null() {
        return std::ptr::null();
    }
    let vec = unsafe { &*(handle as *mut Vec<ExportEntryC>) };
    vec.get(idx)
        .and_then(|e| e.name.as_ref())
        .map(|n| n.as_ptr())
        .unwrap_or(std::ptr::null())
}

/// Returns the resolved code address of the export at `idx`, or null if
/// `handle` is null or `idx` is out of bounds.
///
/// # Safety
/// `handle` must be a valid handle returned by `detours_enumerate_exports()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_exports_address(handle: *mut c_void, idx: usize) -> *const u8 {
    if handle.is_null() {
        return std::ptr::null();
    }
    let vec = unsafe { &*(handle as *mut Vec<ExportEntryC>) };
    vec.get(idx).map(|e| e.address).unwrap_or(std::ptr::null())
}

/// Returns the forwarder target (`"OTHERDLL.Function"`) of the export at `idx`,
/// or null if it is not a forwarder (or `handle` is null / `idx` is out of
/// bounds). Valid until free.
///
/// # Safety
/// `handle` must be a valid handle returned by `detours_enumerate_exports()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_exports_forwarder(
    handle: *mut c_void,
    idx: usize,
) -> *const c_char {
    if handle.is_null() {
        return std::ptr::null();
    }
    let vec = unsafe { &*(handle as *mut Vec<ExportEntryC>) };
    vec.get(idx)
        .and_then(|e| e.forwarder.as_ref())
        .map(|f| f.as_ptr())
        .unwrap_or(std::ptr::null())
}

/// Frees an export handle returned by `detours_enumerate_exports()`.
///
/// # Safety
/// `handle` must be a valid handle returned by `detours_enumerate_exports()`
/// and must not be used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_exports_free(handle: *mut c_void) {
    if !handle.is_null() {
        drop(unsafe { Box::from_raw(handle as *mut Vec<ExportEntryC>) });
    }
}

/// Enumerates the imports of the module identified by `h_module` across all of
/// its imported DLLs.
///
/// Returns an opaque handle to be queried with `detours_imports_len()` /
/// `detours_imports_*()` and released with `detours_imports_free()`. Returns
/// null if the module's PE headers are invalid.
///
/// # Safety
/// `h_module` must be the base address of a valid PE module loaded in the
/// current process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_enumerate_imports(h_module: *mut c_void) -> *mut c_void {
    let imports = match unsafe { introspect::enumerate_imports(h_module as HMODULE) } {
        Ok(v) => v,
        Err(_) => return std::ptr::null_mut(),
    };

    let entries: Vec<ImportEntryC> = imports
        .into_iter()
        .map(|i| ImportEntryC {
            dll: to_cstring(i.dll),
            name: i.name.map(to_cstring),
            ordinal: i.ordinal,
            address: i.address,
        })
        .collect();
    Box::into_raw(Box::new(entries)) as *mut c_void
}

/// Returns the number of imports in a handle from `detours_enumerate_imports()`.
///
/// Returns `0` if `handle` is null.
///
/// # Safety
/// `handle` must be a valid handle returned by `detours_enumerate_imports()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_imports_len(handle: *mut c_void) -> usize {
    if handle.is_null() {
        return 0;
    }
    unsafe { &*(handle as *mut Vec<ImportEntryC>) }.len()
}

/// Returns the source DLL name of the import at `idx`, or null if `handle` is
/// null or `idx` is out of bounds. Valid until free.
///
/// # Safety
/// `handle` must be a valid handle returned by `detours_enumerate_imports()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_imports_dll(handle: *mut c_void, idx: usize) -> *const c_char {
    if handle.is_null() {
        return std::ptr::null();
    }
    let vec = unsafe { &*(handle as *mut Vec<ImportEntryC>) };
    vec.get(idx)
        .map(|i| i.dll.as_ptr())
        .unwrap_or(std::ptr::null())
}

/// Returns the name of the import at `idx`, or null if it is imported by ordinal
/// (or `handle` is null / `idx` is out of bounds). Valid until free.
///
/// # Safety
/// `handle` must be a valid handle returned by `detours_enumerate_imports()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_imports_name(handle: *mut c_void, idx: usize) -> *const c_char {
    if handle.is_null() {
        return std::ptr::null();
    }
    let vec = unsafe { &*(handle as *mut Vec<ImportEntryC>) };
    vec.get(idx)
        .and_then(|i| i.name.as_ref())
        .map(|n| n.as_ptr())
        .unwrap_or(std::ptr::null())
}

/// Returns the ordinal of the import at `idx`, or `0xFFFFFFFF` if it is imported
/// by name (or `handle` is null / `idx` is out of bounds).
///
/// # Safety
/// `handle` must be a valid handle returned by `detours_enumerate_imports()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_imports_ordinal(handle: *mut c_void, idx: usize) -> u32 {
    if handle.is_null() {
        return IMPORT_BY_NAME;
    }
    let vec = unsafe { &*(handle as *mut Vec<ImportEntryC>) };
    vec.get(idx)
        .and_then(|i| i.ordinal)
        .map(|o| o as u32)
        .unwrap_or(IMPORT_BY_NAME)
}

/// Returns the bound IAT address of the import at `idx`, or null if `handle` is
/// null or `idx` is out of bounds.
///
/// # Safety
/// `handle` must be a valid handle returned by `detours_enumerate_imports()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_imports_address(handle: *mut c_void, idx: usize) -> *const u8 {
    if handle.is_null() {
        return std::ptr::null();
    }
    let vec = unsafe { &*(handle as *mut Vec<ImportEntryC>) };
    vec.get(idx).map(|i| i.address).unwrap_or(std::ptr::null())
}

/// Frees an import handle returned by `detours_enumerate_imports()`.
///
/// # Safety
/// `handle` must be a valid handle returned by `detours_enumerate_imports()`
/// and must not be used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_imports_free(handle: *mut c_void) {
    if !handle.is_null() {
        drop(unsafe { Box::from_raw(handle as *mut Vec<ImportEntryC>) });
    }
}

/// Resolves an exported function by name within a module, loading the module if
/// it is not already present.
///
/// Returns null if `module`/`func` are null or not valid UTF-8, or if the
/// function cannot be resolved.
///
/// # Safety
/// `module` and `func` must be valid NUL-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_find_function(
    module: *const c_char,
    func: *const c_char,
) -> *const u8 {
    if module.is_null() || func.is_null() {
        return std::ptr::null();
    }
    let module = match unsafe { CStr::from_ptr(module) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null(),
    };
    let func = match unsafe { CStr::from_ptr(func) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null(),
    };
    crate::find_function(module, func).unwrap_or(std::ptr::null())
}

/// Resolves an exported function by ordinal within a module, loading the module
/// if it is not already present.
///
/// Returns null if `module` is null or not valid UTF-8, or if the ordinal
/// cannot be resolved.
///
/// # Safety
/// `module` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_find_function_by_ordinal(
    module: *const c_char,
    ordinal: u16,
) -> *const u8 {
    if module.is_null() {
        return std::ptr::null();
    }
    let module = match unsafe { CStr::from_ptr(module) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null(),
    };
    crate::find_function_by_ordinal(module, ordinal).unwrap_or(std::ptr::null())
}

// ----------------- FFI Entry Points: pattern / signature scanning ------------

/// Resolves a byte signature inside the module identified by `h_module`,
/// returning the address of the first match in its executable regions.
///
/// `pattern` is an IDA / x64dbg-style signature string (e.g.
/// `"48 8B 05 ?? ?? ?? ?? E8"`). Returns null if `pattern` is null, not valid
/// UTF-8, not a valid signature, or does not match.
///
/// # Safety
/// `h_module` must be the base address of a valid PE module loaded in the
/// current process, and `pattern` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_scan_module(
    h_module: *mut c_void,
    pattern: *const c_char,
) -> *const u8 {
    if pattern.is_null() {
        return std::ptr::null();
    }
    let Ok(pattern) = (unsafe { CStr::from_ptr(pattern) }).to_str() else {
        return std::ptr::null();
    };
    let Ok(pattern) = crate::scan::Pattern::parse(pattern) else {
        return std::ptr::null();
    };
    unsafe { crate::scan::scan_module(h_module as HMODULE, &pattern) }.unwrap_or(std::ptr::null())
}

/// Resolves a byte signature inside a module identified by name, loading the
/// module if it is not already present.
///
/// Returns the address of the first match in the module's executable regions,
/// or null if `module`/`pattern` are null, not valid UTF-8, `pattern` is not a
/// valid signature, or it does not match.
///
/// # Safety
/// `module` and `pattern` must be valid NUL-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_scan_module_by_name(
    module: *const c_char,
    pattern: *const c_char,
) -> *const u8 {
    if module.is_null() || pattern.is_null() {
        return std::ptr::null();
    }
    let Ok(module) = (unsafe { CStr::from_ptr(module) }).to_str() else {
        return std::ptr::null();
    };
    let Ok(pattern) = (unsafe { CStr::from_ptr(pattern) }).to_str() else {
        return std::ptr::null();
    };
    let Ok(pattern) = crate::scan::Pattern::parse(pattern) else {
        return std::ptr::null();
    };
    crate::scan::scan_module_by_name(module, &pattern).unwrap_or(std::ptr::null())
}

/// Scans `len` bytes starting at `start` for the first occurrence of a byte
/// signature, limited to committed, readable regions.
///
/// `pattern` is an IDA / x64dbg-style signature string. Returns null if
/// `start`/`pattern` are null, `pattern` is not valid UTF-8 or not a valid
/// signature, or it does not match.
///
/// # Safety
/// `start` must point into this process's address space, and `pattern` must be
/// a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_scan_range(
    start: *const u8,
    len: usize,
    pattern: *const c_char,
) -> *const u8 {
    if start.is_null() || pattern.is_null() {
        return std::ptr::null();
    }
    let Ok(pattern) = (unsafe { CStr::from_ptr(pattern) }).to_str() else {
        return std::ptr::null();
    };
    let Ok(pattern) = crate::scan::Pattern::parse(pattern) else {
        return std::ptr::null();
    };
    unsafe { crate::scan::scan_range(start, len, &pattern) }.unwrap_or(std::ptr::null())
}

/// Resolves a byte signature inside a module and queues an inline hook on the
/// matched address.
///
/// On success, returns the trampoline pointer for calling the original. Returns
/// null if `tx`/`module`/`pattern` are null, the arguments are not valid UTF-8,
/// `pattern` is not a valid signature, it does not match, or the hook could not
/// be prepared.
///
/// # Safety
/// `tx` must be a valid transaction pointer returned by
/// `detours_transaction_begin()`, and `module`/`pattern` must be valid
/// NUL-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_transaction_attach_pattern(
    tx: *mut DetourTransaction,
    module: *const c_char,
    pattern: *const c_char,
    detour: *const u8,
) -> *mut u8 {
    if tx.is_null() || module.is_null() || pattern.is_null() {
        return std::ptr::null_mut();
    }
    let Ok(module) = (unsafe { CStr::from_ptr(module) }).to_str() else {
        return std::ptr::null_mut();
    };
    let Ok(pattern) = (unsafe { CStr::from_ptr(pattern) }).to_str() else {
        return std::ptr::null_mut();
    };

    let tx_ref = unsafe { &mut *tx };
    tx_ref
        .attach_pattern(module, pattern, detour)
        .unwrap_or(std::ptr::null_mut())
}

/// Resolves an exported function by name and queues an inline hook on it.
///
/// Convenience entry point combining `detours_find_function` and
/// `detours_transaction_attach`: loads `module` if needed, resolves `func`, and
/// queues an inline hook on the function body (intercepting every caller).
///
/// On success, returns the trampoline pointer for calling the original. Returns
/// null if `tx`/`module`/`func` are null, the arguments are not valid UTF-8, the
/// export could not be resolved, or the hook could not be prepared.
///
/// # Safety
/// `tx` must be a valid transaction pointer returned by
/// `detours_transaction_begin()`, and `module`/`func` must be valid
/// NUL-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_transaction_attach_export(
    tx: *mut DetourTransaction,
    module: *const c_char,
    func: *const c_char,
    detour: *const u8,
) -> *mut u8 {
    if tx.is_null() || module.is_null() || func.is_null() {
        return std::ptr::null_mut();
    }
    let Ok(module) = (unsafe { CStr::from_ptr(module) }).to_str() else {
        return std::ptr::null_mut();
    };
    let Ok(func) = (unsafe { CStr::from_ptr(func) }).to_str() else {
        return std::ptr::null_mut();
    };

    let tx_ref = unsafe { &mut *tx };
    tx_ref
        .attach_export(module, func, detour)
        .unwrap_or(std::ptr::null_mut())
}

// ----------------- FFI Entry Points: VEH (hardware breakpoint) hooking -------

/// Installs a VEH (hardware-breakpoint) hook redirecting `target` to `detour`.
///
/// Returns an opaque hook pointer on success, or null on failure (null
/// arguments, all four breakpoint slots in use, the target already hooked, or
/// handler registration failure). The returned pointer must be released with
/// `detours_veh_unhook`.
///
/// # Safety
/// `target` must point at the entry of a real function in executable memory and
/// `detour` must be a function pointer with a compatible ABI/signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_veh_install(
    target: *const u8,
    detour: *const u8,
) -> *mut crate::veh::VehHook {
    match unsafe { crate::veh::VehHook::install(target, detour) } {
        Ok(hook) => Box::into_raw(Box::new(hook)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Installs a VEH hook that also exposes a callable gateway to the original
/// function, retrievable with `detours_veh_original`.
///
/// Behaves like `detours_veh_install`, but lets the detour forward to the
/// original (e.g. to use its return value) without re-triggering the
/// breakpoint. Returns null on failure, including when the original gateway
/// could not be built. The returned pointer must be released with
/// `detours_veh_unhook`.
///
/// # Safety
/// `target` must point at the entry of a real function in executable memory and
/// `detour` must be a function pointer with a compatible ABI/signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_veh_install_with_original(
    target: *const u8,
    detour: *const u8,
) -> *mut crate::veh::VehHook {
    match unsafe { crate::veh::VehHook::install_with_original(target, detour) } {
        Ok(hook) => Box::into_raw(Box::new(hook)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Returns the callable original-function pointer for a VEH hook installed with
/// `detours_veh_install_with_original`, or null if `hook` is null or was
/// installed without a gateway.
///
/// # Safety
/// `hook` must be a valid pointer previously returned by `detours_veh_install*`
/// and still live (not yet unhooked).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_veh_original(hook: *const crate::veh::VehHook) -> *const u8 {
    if hook.is_null() {
        return std::ptr::null();
    }
    unsafe { &*hook }.original_ptr().unwrap_or(std::ptr::null())
}

/// Removes a VEH hook installed by `detours_veh_install` and frees it.
///
/// Returns `1` if the hook was accepted for removal, or `0` if `hook` is null.
///
/// # Safety
/// `hook` must be a valid pointer previously returned by `detours_veh_install`
/// and must not be used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_veh_unhook(hook: *mut crate::veh::VehHook) -> i32 {
    if hook.is_null() {
        return 0;
    }
    let hook = unsafe { Box::from_raw(hook) };
    // Dropping the box clears the breakpoint via RAII; be explicit for clarity.
    let _ = hook.unhook();
    1
}

// ----------------- FFI Entry Points: mid-function detours --------------------

/// Installs a mid-function / arbitrary-address detour redirecting `target` to
/// the context handler `handler`.
///
/// Unlike entry-point hooks, `target` may be any instruction boundary. The
/// handler is called with a pointer to a `HookContext` snapshot of the
/// general-purpose registers and flags, which it may read or modify before the
/// original instructions resume.
///
/// Returns an opaque hook pointer on success, or null on failure (null
/// arguments, allocation failure, or non-relocatable bytes at `target`). The
/// returned pointer must be released with `detours_midhook_unhook`.
///
/// # Safety
/// `target` must point at the start of a real instruction in executable memory,
/// and `handler` must be a valid context-handler function pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_midhook_install(
    target: *const u8,
    handler: crate::midhook::MidHookHandler,
) -> *mut crate::midhook::MidHook {
    if target.is_null() {
        return std::ptr::null_mut();
    }
    match unsafe { crate::midhook::MidHook::install(target, handler) } {
        Ok(hook) => Box::into_raw(Box::new(hook)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Removes a mid-function detour installed by `detours_midhook_install` and
/// frees it, restoring the original bytes at the target.
///
/// Returns `1` if the hook was accepted for removal, or `0` if `hook` is null.
///
/// # Safety
/// `hook` must be a valid pointer previously returned by
/// `detours_midhook_install` and must not be used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_midhook_unhook(hook: *mut crate::midhook::MidHook) -> i32 {
    if hook.is_null() {
        return 0;
    }
    let hook = unsafe { Box::from_raw(hook) };
    // Dropping the box restores the original bytes via RAII; be explicit.
    let _ = hook.unhook();
    1
}

// ----------------- FFI Entry Points: INT3 software-breakpoint hooking --------

/// Installs an INT3 (software-breakpoint) hook redirecting `target` to `detour`.
///
/// Patches a single `0xCC` byte at `target` and routes the resulting breakpoint
/// through a vectored exception handler. Unlike `detours_veh_install`, there is
/// no four-hook limit (up to `INT3_MAX_HOOKS` targets) and threads created after
/// the install still trap.
///
/// Returns an opaque hook pointer on success, or null on failure (null
/// arguments, all slots in use, the target already hooked, handler registration
/// failure, or the patch byte could not be written). The returned pointer must
/// be released with `detours_int3_unhook`.
///
/// # Safety
/// `target` must point at the entry of a real function in executable memory and
/// `detour` must be a function pointer with a compatible ABI/signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_int3_install(
    target: *const u8,
    detour: *const u8,
) -> *mut crate::int3::Int3Hook {
    match unsafe { crate::int3::Int3Hook::install(target, detour) } {
        Ok(hook) => Box::into_raw(Box::new(hook)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Installs an INT3 hook that also exposes a callable gateway to the original
/// function, retrievable with `detours_int3_original`.
///
/// Behaves like `detours_int3_install`, but lets the detour forward to the
/// original (e.g. to use its return value) without re-triggering the
/// breakpoint. Returns null on failure, including when the original gateway
/// could not be built. The returned pointer must be released with
/// `detours_int3_unhook`.
///
/// # Safety
/// `target` must point at the entry of a real function in executable memory and
/// `detour` must be a function pointer with a compatible ABI/signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_int3_install_with_original(
    target: *const u8,
    detour: *const u8,
) -> *mut crate::int3::Int3Hook {
    match unsafe { crate::int3::Int3Hook::install_with_original(target, detour) } {
        Ok(hook) => Box::into_raw(Box::new(hook)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Returns the callable original-function pointer for an INT3 hook installed
/// with `detours_int3_install_with_original`, or null if `hook` is null or was
/// installed without a gateway.
///
/// # Safety
/// `hook` must be a valid pointer previously returned by `detours_int3_install*`
/// and still live (not yet unhooked).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_int3_original(hook: *const crate::int3::Int3Hook) -> *const u8 {
    if hook.is_null() {
        return std::ptr::null();
    }
    unsafe { &*hook }.original_ptr().unwrap_or(std::ptr::null())
}

/// Removes an INT3 hook installed by `detours_int3_install` and frees it,
/// restoring the original byte at the target.
///
/// Returns `1` if the hook was accepted for removal, or `0` if `hook` is null.
///
/// # Safety
/// `hook` must be a valid pointer previously returned by `detours_int3_install`
/// and must not be used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_int3_unhook(hook: *mut crate::int3::Int3Hook) -> i32 {
    if hook.is_null() {
        return 0;
    }
    let hook = unsafe { Box::from_raw(hook) };
    // Dropping the box restores the original byte via RAII; be explicit.
    let _ = hook.unhook();
    1
}

// ----------------- FFI Entry Points: relative-reference resolving ------------

/// Resolves the absolute target of a near branch (`call`/`jmp`/`jcc rel`) at
/// `addr` by decoding the instruction.
///
/// Returns the branch target, or null if `addr` is null/unreadable, does not
/// decode, or is not a near-branch instruction.
///
/// # Safety
/// `addr` must point into this process's address space.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_resolve_call_target(addr: *const u8) -> *const u8 {
    unsafe { crate::resolve::resolve_call_target(addr) }.unwrap_or(std::ptr::null())
}

/// Resolves the absolute address referenced by a RIP-relative memory operand at
/// `addr` (e.g. `lea`/`mov [rip+disp32]`) by decoding the instruction.
///
/// Returns the referenced address, or null if `addr` is null/unreadable, does
/// not decode, or has no RIP-relative operand.
///
/// # Safety
/// `addr` must point into this process's address space.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_resolve_rip_relative(addr: *const u8) -> *const u8 {
    unsafe { crate::resolve::resolve_rip_relative(addr) }.unwrap_or(std::ptr::null())
}

/// Resolves a relative reference from its raw encoding: returns
/// `addr + instr_len + *(int32_t*)(addr + disp_offset)`.
///
/// # Safety
/// `addr` must be readable for at least `disp_offset + 4` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_resolve_relative(
    addr: *const u8,
    disp_offset: usize,
    instr_len: usize,
) -> *const u8 {
    unsafe { crate::resolve::resolve_relative(addr, disp_offset, instr_len) }
}

// ----------------- FFI Entry Points: delay / on-load hooking -----------------

/// Registers a delay / on-load hook that installs automatically when `module` is
/// loaded (or immediately, if it is already present).
///
/// Returns an opaque hook pointer on success, or null on failure (null
/// arguments, not valid UTF-8, or the one-time `LdrLoadDll` hook failed). The
/// returned pointer must be released with `detours_delay_unhook`.
///
/// # Safety
/// `module` and `func` must be valid NUL-terminated C strings, and `detour` must
/// be a function pointer with an ABI/signature compatible with the eventual
/// target (full replacement, no trampoline).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_delay_register(
    module: *const c_char,
    func: *const c_char,
    detour: *const u8,
) -> *mut crate::delay::DelayHook {
    if module.is_null() || func.is_null() {
        return std::ptr::null_mut();
    }
    let Ok(module) = (unsafe { CStr::from_ptr(module) }).to_str() else {
        return std::ptr::null_mut();
    };
    let Ok(func) = (unsafe { CStr::from_ptr(func) }).to_str() else {
        return std::ptr::null_mut();
    };
    match unsafe { crate::delay::DelayHook::register(module, func, detour) } {
        Ok(hook) => Box::into_raw(Box::new(hook)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Returns `1` if the delay hook's module has been loaded and the hook is now
/// installed, or `0` if it is still pending (or `hook` is null).
///
/// # Safety
/// `hook` must be a valid pointer previously returned by
/// `detours_delay_register`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_delay_is_active(hook: *const crate::delay::DelayHook) -> i32 {
    if hook.is_null() {
        return 0;
    }
    unsafe { (*hook).is_active() as i32 }
}

/// Removes a delay hook registered by `detours_delay_register` and frees it,
/// restoring the original byte if it had already been installed.
///
/// Returns `1` if the hook was accepted for removal, or `0` if `hook` is null.
///
/// # Safety
/// `hook` must be a valid pointer previously returned by
/// `detours_delay_register` and must not be used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_delay_unhook(hook: *mut crate::delay::DelayHook) -> i32 {
    if hook.is_null() {
        return 0;
    }
    let hook = unsafe { Box::from_raw(hook) };
    let _ = hook.unhook();
    1
}

#[cfg(test)]
mod attach_export_tests {
    use super::*;

    #[test]
    fn attach_export_rejects_unknown_export() {
        let mut tx = DetourTransaction::begin();
        let err = tx
            .attach_export(
                "kernel32.dll",
                "DefinitelyNotARealExport_123",
                detours_transaction_attach as *const u8,
            )
            .expect_err("an unknown export must not resolve");
        assert!(matches!(err, DetourError::InvalidParameter));
    }

    #[test]
    fn attach_export_rejects_unknown_module() {
        let mut tx = DetourTransaction::begin();
        let err = tx
            .attach_export(
                "fantasy_dll_999.dll",
                "Whatever",
                detours_transaction_attach as *const u8,
            )
            .expect_err("an unknown module must not resolve");
        assert!(matches!(err, DetourError::InvalidParameter));
    }

    #[test]
    fn attach_export_hooks_a_real_export() {
        // GetCurrentProcessId is a tiny, side-effect-free kernel32 export; hook
        // it by name, confirm the detour wins, then unhook via RAII.
        use std::sync::OnceLock;
        use windows_sys::Win32::System::Threading::GetCurrentProcessId;

        type Fn0 = unsafe extern "system" fn() -> u32;
        static ORIG: OnceLock<Fn0> = OnceLock::new();

        unsafe extern "system" fn detour() -> u32 {
            0xABCD_1234
        }

        let real = unsafe { GetCurrentProcessId() };
        assert_ne!(real, 0xABCD_1234);

        let mut tx = DetourTransaction::begin();
        tx.update_all_threads();
        let tramp = tx
            .attach_export("kernel32.dll", "GetCurrentProcessId", detour as *const u8)
            .expect("attach_export should resolve and queue the hook");
        let hooks = tx.commit().expect("commit should succeed");

        let _ = ORIG.set(unsafe { std::mem::transmute::<*mut u8, Fn0>(tramp) });

        assert_eq!(
            unsafe { GetCurrentProcessId() },
            0xABCD_1234,
            "the named-export hook should intercept the call"
        );
        // The trampoline still reaches the real implementation.
        assert_eq!(unsafe { (ORIG.get().unwrap())() }, real);

        drop(hooks); // RAII restores the original bytes.
        assert_eq!(
            unsafe { GetCurrentProcessId() },
            real,
            "original should be restored after unhook"
        );
    }
}
