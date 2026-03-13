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
    /// If `orig_out` is non-null, the original imported function pointer is
    /// written there once the hook has been installed successfully.
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
        orig_out: *mut *mut u8,
    ) -> Result<(), DetourError> {
        self.inner
            .as_mut()
            .ok_or(DetourError::NotStarted)?
            .attach_iat(h_module, target_dll, target_func, detour, orig_out)
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
        self.inner.as_ref().unwrap().dump_state();
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

#[unsafe(no_mangle)]
pub extern "C" fn detours_transaction_update_thread(
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
/// `tx` must be a valid transaction pointer previously returned by
/// `detours_transaction_begin()`.
///
/// Returns the trampoline pointer for the original function on success, or
/// null on failure.
///
/// The returned trampoline can be used to call the original function body.
#[unsafe(no_mangle)]
pub extern "C" fn detours_transaction_attach(
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
/// `tx` must be a valid transaction pointer previously returned by
/// `detours_transaction_begin()`. Ownership of `tx` is consumed by this
/// function, regardless of success or failure.
///
/// On success, returns a non-null opaque handle that can be queried with
/// `detours_handle_len()` and `detours_handle_get_trampoline()`, and must
/// eventually be released with `detours_handle_unhook_and_free()`.
///
/// Returns null if the transaction could not be committed.
#[unsafe(no_mangle)]
pub extern "C" fn detours_transaction_commit(tx: *mut DetourTransaction) -> *mut c_void {
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
/// `handle` must be a valid handle previously returned by
/// `detours_transaction_commit()`.
///
/// Returns `0` if `handle` is null.
#[unsafe(no_mangle)]
pub extern "C" fn detours_handle_len(handle: *mut c_void) -> usize {
    if handle.is_null() {
        return 0;
    }
    let vec = unsafe { &*(handle as *mut Vec<Hook>) };
    vec.len()
}

/// Returns the trampoline pointer (that is, the original function entry) for
/// the hook at `idx`.
///
/// This works for both inline hooks and IAT hooks.
///
/// `handle` must be a valid handle previously returned by
/// `detours_transaction_commit()`.
///
/// Returns null if `handle` is null or if `idx` is out of bounds.
#[unsafe(no_mangle)]
pub extern "C" fn detours_handle_get_trampoline(handle: *mut c_void, idx: usize) -> *const u8 {
    if handle.is_null() {
        return std::ptr::null();
    }
    let vec = unsafe { &*(handle as *mut Vec<Hook>) };

    vec.get(idx)
        .map(|d| d.original_ptr())
        .unwrap_or(std::ptr::null())
}

/// Unhooks all installed hooks referenced by `handle` and frees the handle.
///
/// `handle` must be a valid handle previously returned by
/// `detours_transaction_commit()`.
///
/// Dropping the internal hook vector triggers unhooking through RAII.
///
/// Returns `1` on success and `0` if `handle` is null.
#[unsafe(no_mangle)]
pub extern "C" fn detours_handle_unhook_and_free(handle: *mut c_void) -> i32 {
    if handle.is_null() {
        return 0;
    }
    let _vec_box = unsafe { Box::from_raw(handle as *mut Vec<Hook>) };
    // Dropping the vector drops all hooks, which triggers unhooking via RAII.
    1
}
