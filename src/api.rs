// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::DetourError;
use crate::transaction::{Hook, TransactionCore};
use std::ffi::c_void;

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
