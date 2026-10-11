// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::DetourError;
use crate::introspect;
use crate::midhook::HookContext;
use crate::transaction::{Hook, TransactionCore};
use std::ffi::{CStr, CString, c_char, c_void};
use std::marker::PhantomData;
use windows_sys::Win32::Foundation::HMODULE;

/// Runs an FFI body, returning `on_panic` instead of letting a panic cross the C
/// ABI boundary.
///
/// A panic unwinding out of an `extern "C"` function aborts the whole host
/// process. Most of NeoHook's internals return `Result` rather than panicking
/// (and the relocation engine already contains its own panics), but a deep,
/// unexpected panic in an engine path would otherwise take the host down.
/// Wrapping an entry point converts it into the function's normal failure value
/// (a null pointer or `0`) instead.
///
/// The entry points that drive the hooking engine are wrapped: transaction
/// begin, thread tracking, attach, detach, commit and abort; the hook-handle
/// toggle and release; VEH, mid-function and INT3 install and unhook; delay-hook
/// register and unhook; watchdog create, guard, unguard and destroy; and stub
/// reclamation. Plain accessors and the read-only introspection functions are
/// not wrapped.
fn ffi_guard<T>(on_panic: T, body: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(_) => on_panic,
    }
}

/// High-level wrapper around [`TransactionCore`].
///
/// This type provides an ergonomic transaction-based interface for installing
/// and managing detours. A transaction can be started with [`Self::begin`],
/// populated with pending hooks, and then either committed or aborted.
///
/// Any resources tracked by the transaction are cleaned up automatically when
/// the transaction is dropped.
///
/// The lifetime ties the transaction to the hooks queued with
/// [`Self::detach`]: they stay borrowed until the transaction is committed,
/// aborted or dropped.
#[repr(C)]
pub struct DetourTransaction<'a> {
    /// Internal transaction state.
    ///
    /// This is wrapped in an `Option` so the transaction can be safely moved
    /// out during [`Self::commit`] or [`Self::abort`], preventing accidental
    /// reuse after completion.
    pub(crate) inner: Option<TransactionCore>,
    pub(crate) detached: PhantomData<&'a mut Hook>,
}

impl<'a> DetourTransaction<'a> {
    /// Begins a new detour transaction.
    ///
    /// The returned transaction can be used to register inline or IAT hooks and
    /// then apply them atomically with [`Self::commit`].
    pub fn begin() -> Self {
        // Opportunistically release stubs retired by earlier teardowns now that
        // we are on a thread that holds no transaction lock. Cheap no-op when the
        // quarantine is empty (the common case).
        crate::reclaim::reclaim();
        Self {
            inner: Some(TransactionCore::begin()),
            detached: PhantomData,
        }
    }

    /// Tracks the given thread for the duration of the transaction. It is
    /// suspended while the commit patches code and resumed afterwards.
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

    /// Tracks all threads in the current process except the calling thread, so
    /// the commit suspends them while it patches code.
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
    ///
    /// `hook` stays mutably borrowed for the rest of the transaction, so it can
    /// be neither moved nor dropped before the commit applies the detach. To
    /// queue several hooks from one collection, borrow them disjointly, e.g.
    /// with `iter_mut()`.
    pub fn detach(&mut self, hook: &'a mut Hook) -> Result<(), DetourError> {
        let inner = self.inner.as_mut().ok_or(DetourError::NotStarted)?;
        // SAFETY: the `'a` borrow keeps `hook` alive and in place until this
        // transaction is committed, aborted or dropped.
        unsafe { inner.detach(hook) }
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

    /// Prints a human-readable snapshot of the transaction to standard output.
    ///
    /// A debugging aid for inspecting what a transaction is about to do: its
    /// status, the threads it has suspended, every pending hook, and whether it
    /// holds the process-wide transaction lock. Does nothing once the
    /// transaction has been committed or aborted.
    ///
    /// This writes to the host process's stdout, so call it only from a process
    /// you control - and never between suspending threads and resuming them,
    /// where taking the stdout lock can deadlock against a suspended holder.
    pub fn dump_state(&self) {
        if let Some(inner) = &self.inner {
            inner.dump_state();
        }
    }
}

impl Drop for DetourTransaction<'_> {
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
pub extern "C" fn detours_transaction_begin() -> *mut DetourTransaction<'static> {
    ffi_guard(std::ptr::null_mut(), || {
        Box::into_raw(Box::new(DetourTransaction::begin()))
    })
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
    tx: *mut DetourTransaction<'static>,
    thread_id: u32,
) -> i32 {
    ffi_guard(0, || {
        if tx.is_null() {
            return 0;
        }

        let tx_ref = unsafe { &mut *tx };
        tx_ref.update_thread(thread_id).map(|_| 1).unwrap_or(0)
    })
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
    tx: *mut DetourTransaction<'static>,
    target: *mut u8,
    detour: *const u8,
) -> *mut u8 {
    ffi_guard(std::ptr::null_mut(), || {
        if tx.is_null() {
            return std::ptr::null_mut();
        }
        let tx_ref = unsafe { &mut *tx };

        tx_ref
            .attach(target, detour)
            .unwrap_or(std::ptr::null_mut())
    })
}

/// Queues a single hook from an opaque hook handle to be detached when the
/// transaction commits.
///
/// On success, the selected hook is removed from `handle` during commit. The
/// handle remains valid and any other hooks stored in it remain active. Indices
/// are stable: the detached hook leaves an empty slot behind, so every other
/// index keeps naming the same hook and `detours_handle_len()` does not change.
/// Every `detours_handle_*` accessor treats an empty slot like an out-of-range
/// index, and it cannot be detached again.
///
/// Returns `1` if the detach was queued, or `0` if `tx`/`handle` is null, the
/// transaction is no longer pending, or `idx` is out of bounds or names an
/// already detached hook.
///
/// # Safety
/// `tx` must be a valid transaction pointer returned by
/// `detours_transaction_begin()`. `handle` must be a valid handle returned by
/// `detours_transaction_commit()`, and it must stay valid until `tx` is
/// committed or aborted: freeing it in between (for example with
/// `detours_handle_unhook_and_free`) leaves the queued detach pointing at freed
/// memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_transaction_detach(
    tx: *mut DetourTransaction<'static>,
    handle: *mut c_void,
    idx: usize,
) -> i32 {
    ffi_guard(0, || {
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
    })
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
pub unsafe extern "C" fn detours_transaction_commit(
    tx: *mut DetourTransaction<'static>,
) -> *mut c_void {
    ffi_guard(std::ptr::null_mut(), || {
        if tx.is_null() {
            return std::ptr::null_mut();
        }
        let tx_box = unsafe { Box::from_raw(tx) };
        match tx_box.commit() {
            Ok(v) => {
                let slots: HandleSlots = v.into_iter().map(Some).collect();
                Box::into_raw(Box::new(slots)) as *mut c_void
            }
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Storage behind a hook handle returned by `detours_transaction_commit()`.
///
/// A hook detached through `detours_transaction_detach()` leaves `None` in its
/// slot, so the index of every other hook stays the same.
pub(crate) type HandleSlots = Vec<Option<Hook>>;

/// Runs `f` on the hook in slot `idx` of `handle` under the transaction lock,
/// so it cannot race a commit on another thread detaching from the same handle.
///
/// Returns `missing` if `handle` is null, `idx` is out of bounds or the slot was
/// emptied by a detach.
///
/// # Safety
/// `handle` must be null or a valid handle returned by
/// `detours_transaction_commit()`.
unsafe fn with_handle_slot<R>(
    handle: *mut c_void,
    idx: usize,
    missing: R,
    f: impl FnOnce(&mut Hook) -> R,
) -> R {
    if handle.is_null() {
        return missing;
    }
    crate::transaction::with_code_lock(|| {
        let slots = unsafe { &mut *(handle as *mut HandleSlots) };
        match slots.get_mut(idx).and_then(Option::as_mut) {
            Some(hook) => f(hook),
            None => missing,
        }
    })
}

/// Returns the number of hook slots in an opaque hook handle.
///
/// This is the number of hooks the handle was committed with. Detaching a hook
/// with `detours_transaction_detach()` empties its slot without shrinking the
/// handle, so indices stay valid; the `detours_handle_*` accessors treat an
/// emptied slot like an out-of-range index.
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
    crate::transaction::with_code_lock(|| unsafe { &*(handle as *mut HandleSlots) }.len())
}

/// Returns the original function pointer associated with the hook at `idx`.
///
/// For inline hooks, this is the trampoline entry managed by NeoHook.
/// For IAT hooks, this is the original imported function pointer.
///
/// Returns null if `handle` is null, if `idx` is out of bounds or if the hook
/// at `idx` was detached.
///
/// # Safety
/// `handle` must be a valid handle previously returned by
/// `detours_transaction_commit()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_handle_get_original_ptr(
    handle: *mut c_void,
    idx: usize,
) -> *const u8 {
    unsafe { with_handle_slot(handle, idx, std::ptr::null(), |hook| hook.original_ptr()) }
}

/// Enables (`enabled != 0`) or disables (`enabled == 0`) the hook at `idx`
/// without unhooking it.
///
/// Disabling restores the original code/pointer while keeping the hook
/// installed; enabling re-applies the detour. This is cheaper than a full
/// unhook/rehook cycle.
///
/// Returns `1` on success, `0` if `handle` is null, `idx` is out of bounds,
/// the hook at `idx` was detached, or the toggle failed.
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
    ffi_guard(0, || unsafe {
        with_handle_slot(handle, idx, 0, |hook| {
            let result = if enabled != 0 {
                hook.enable()
            } else {
                hook.disable()
            };
            result.map(|_| 1).unwrap_or(0)
        })
    })
}

/// Returns `1` if the hook at `idx` is currently enabled, `0` otherwise (also
/// `0` if `handle` is null, `idx` is out of bounds or the hook at `idx` was
/// detached).
///
/// # Safety
/// `handle` must be a valid handle previously returned by
/// `detours_transaction_commit()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_handle_is_enabled(handle: *mut c_void, idx: usize) -> i32 {
    unsafe { with_handle_slot(handle, idx, 0, |hook| hook.is_enabled() as i32) }
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
    ffi_guard(0, || {
        if handle.is_null() {
            return 0;
        }
        let _vec_box = unsafe { Box::from_raw(handle as *mut HandleSlots) };
        // Dropping the vector drops all hooks, which triggers unhooking via RAII.
        1
    })
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
    tx: *mut DetourTransaction<'static>,
    h_module: *mut core::ffi::c_void,
    target_dll: *const std::ffi::c_char,
    target_func: *const std::ffi::c_char,
    detour: *const u8,
) -> i32 {
    ffi_guard(0, || {
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
    })
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
    tx: *mut DetourTransaction<'static>,
    h_module: *mut core::ffi::c_void,
    target_func: *const std::ffi::c_char,
    detour: *const u8,
) -> i32 {
    ffi_guard(0, || {
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
    })
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
    tx: *mut DetourTransaction<'static>,
    vtable: *mut *mut u8,
    index: usize,
    detour: *const u8,
) -> *mut u8 {
    ffi_guard(std::ptr::null_mut(), || {
        if tx.is_null() || vtable.is_null() || detour.is_null() {
            return std::ptr::null_mut();
        }

        let tx_ref = unsafe { &mut *tx };

        tx_ref
            .attach_vtable(vtable, index, detour)
            .unwrap_or(std::ptr::null_mut())
    })
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
    tx: *mut DetourTransaction<'static>,
    object_vptr: *mut *mut u8,
    index: usize,
    vtable_len: usize,
    detour: *const u8,
) -> *mut u8 {
    ffi_guard(std::ptr::null_mut(), || {
        if tx.is_null() || object_vptr.is_null() || detour.is_null() {
            return std::ptr::null_mut();
        }

        let tx_ref = unsafe { &mut *tx };

        tx_ref
            .attach_vtable_instance(object_vptr, index, vtable_len, detour)
            .unwrap_or(std::ptr::null_mut())
    })
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
pub unsafe extern "C" fn detours_transaction_update_all_threads(
    tx: *mut DetourTransaction<'static>,
) -> i32 {
    ffi_guard(0, || {
        if tx.is_null() {
            return 0;
        }

        let tx_ref = unsafe { &mut *tx };
        if tx_ref.inner.is_none() {
            return 0;
        }

        tx_ref.update_all_threads();
        1
    })
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
pub unsafe extern "C" fn detours_transaction_abort(tx: *mut DetourTransaction<'static>) -> i32 {
    ffi_guard(0, || {
        if tx.is_null() {
            return 0;
        }

        let mut tx_box = unsafe { Box::from_raw(tx) };
        tx_box.abort();
        1
    })
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

/// Resolves `symbol` within `module` to its absolute address using `dbghelp`,
/// covering PDB symbols (when symbols are available) as well as exports - so
/// non-exported functions can be located by name.
///
/// Returns null if either argument is null or not valid UTF-8, `dbghelp` cannot
/// initialize, the module cannot be found, or the symbol is unknown.
///
/// # Safety
/// `module` and `symbol` must be valid NUL-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_resolve_symbol(
    module: *const c_char,
    symbol: *const c_char,
) -> *const u8 {
    if module.is_null() || symbol.is_null() {
        return std::ptr::null();
    }
    let Ok(module) = (unsafe { CStr::from_ptr(module) }).to_str() else {
        return std::ptr::null();
    };
    let Ok(symbol) = (unsafe { CStr::from_ptr(symbol) }).to_str() else {
        return std::ptr::null();
    };
    crate::resolve_symbol(module, symbol).unwrap_or(std::ptr::null())
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
    tx: *mut DetourTransaction<'static>,
    module: *const c_char,
    pattern: *const c_char,
    detour: *const u8,
) -> *mut u8 {
    ffi_guard(std::ptr::null_mut(), || {
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
    })
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
    tx: *mut DetourTransaction<'static>,
    module: *const c_char,
    func: *const c_char,
    detour: *const u8,
) -> *mut u8 {
    ffi_guard(std::ptr::null_mut(), || {
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
    })
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
    ffi_guard(std::ptr::null_mut(), || {
        match unsafe { crate::veh::VehHook::install(target, detour) } {
            Ok(hook) => Box::into_raw(Box::new(hook)),
            Err(_) => std::ptr::null_mut(),
        }
    })
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
    ffi_guard(std::ptr::null_mut(), || {
        match unsafe { crate::veh::VehHook::install_with_original(target, detour) } {
            Ok(hook) => Box::into_raw(Box::new(hook)),
            Err(_) => std::ptr::null_mut(),
        }
    })
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
    ffi_guard(0, || {
        if hook.is_null() {
            return 0;
        }
        let hook = unsafe { Box::from_raw(hook) };
        // Dropping the box clears the breakpoint via RAII; be explicit for clarity.
        let _ = hook.unhook();
        1
    })
}

// ----------------- FFI Entry Points: mid-function detours --------------------

/// A handler invoked at a mid-function hook site with a pointer to the captured
/// [`HookContext`].
///
/// The handler runs with every general-purpose register, the flags, all XMM
/// registers and `MXCSR` snapshotted and restored around it, so it may freely
/// clobber registers and modify the context block in place. It must not block
/// indefinitely or unwind across the FFI boundary.
///
/// The handler uses the C calling convention (`__cdecl` on x86), like the rest
/// of the C ABI. Pass `NULL` and installation fails.
// The nullable C-ABI form of `crate::MidHookHandler`, which build.rs renames to
// `MidHookHandler` in the header (so the non-nullable alias must never appear
// in an FFI signature). The pointer is spelled out rather than
// `Option<MidHookHandler>` because cbindgen cannot see through
// `Option<SomeAlias>` and would emit an opaque struct.
pub type DetoursMidHookHandler = Option<unsafe extern "C" fn(context: *mut HookContext)>;

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
/// and `handler`, when non-null, must be a valid context-handler function
/// pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_midhook_install(
    target: *const u8,
    handler: DetoursMidHookHandler,
) -> *mut crate::midhook::MidHook {
    ffi_guard(std::ptr::null_mut(), || {
        let Some(handler) = handler else {
            return std::ptr::null_mut();
        };
        if target.is_null() {
            return std::ptr::null_mut();
        }
        match unsafe { crate::midhook::MidHook::install(target, handler) } {
            Ok(hook) => Box::into_raw(Box::new(hook)),
            Err(_) => std::ptr::null_mut(),
        }
    })
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
    ffi_guard(0, || {
        if hook.is_null() {
            return 0;
        }
        let hook = unsafe { Box::from_raw(hook) };
        // Dropping the box restores the original bytes via RAII; be explicit.
        let _ = hook.unhook();
        1
    })
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
    ffi_guard(std::ptr::null_mut(), || {
        match unsafe { crate::int3::Int3Hook::install(target, detour) } {
            Ok(hook) => Box::into_raw(Box::new(hook)),
            Err(_) => std::ptr::null_mut(),
        }
    })
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
    ffi_guard(std::ptr::null_mut(), || {
        match unsafe { crate::int3::Int3Hook::install_with_original(target, detour) } {
            Ok(hook) => Box::into_raw(Box::new(hook)),
            Err(_) => std::ptr::null_mut(),
        }
    })
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
    ffi_guard(0, || {
        if hook.is_null() {
            return 0;
        }
        let hook = unsafe { Box::from_raw(hook) };
        // Dropping the box restores the original byte via RAII; be explicit.
        let _ = hook.unhook();
        1
    })
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
    ffi_guard(std::ptr::null_mut(), || {
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
    })
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
    ffi_guard(0, || {
        if hook.is_null() {
            return 0;
        }
        let hook = unsafe { Box::from_raw(hook) };
        let _ = hook.unhook();
        1
    })
}

// ----------------- FFI Entry Points: anti-tamper watchdog --------------------

/// Creates an anti-tamper watchdog whose background thread re-applies tampered
/// byte patches every `interval_ms` milliseconds.
///
/// Returns an opaque watchdog pointer (non-null), which must later be released
/// with `detours_watchdog_destroy`. An `interval_ms` of `0` is treated as 1 ms.
#[unsafe(no_mangle)]
pub extern "C" fn detours_watchdog_create(interval_ms: u32) -> *mut crate::watchdog::Watchdog {
    ffi_guard(std::ptr::null_mut(), || {
        let interval = std::time::Duration::from_millis(interval_ms.max(1) as u64);
        Box::into_raw(Box::new(crate::watchdog::Watchdog::with_interval(interval)))
    })
}

/// Snapshots `len` bytes at `target` and guards them, returning a non-zero guard
/// id usable with `detours_watchdog_unguard`.
///
/// Install the hook first: the bytes are read now and become the image the
/// watchdog re-applies. Returns `0` if `wd`/`target` is null or `len` is zero.
///
/// # Safety
/// `wd` must be a valid watchdog pointer from `detours_watchdog_create`, and
/// `target` must point at `len` readable bytes for the lifetime of the guard.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_watchdog_guard(
    wd: *mut crate::watchdog::Watchdog,
    target: *const u8,
    len: usize,
) -> u64 {
    ffi_guard(0, || {
        if wd.is_null() {
            return 0;
        }
        let wd = unsafe { &*wd };
        match unsafe { wd.guard(target, len) } {
            Ok(id) => id.raw(),
            Err(_) => 0,
        }
    })
}

/// Stops guarding the region identified by `id`.
///
/// Returns `1` if a matching region was being guarded, `0` otherwise (including
/// when `wd` is null). Call this before unhooking the target.
///
/// # Safety
/// `wd` must be a valid watchdog pointer from `detours_watchdog_create`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_watchdog_unguard(
    wd: *mut crate::watchdog::Watchdog,
    id: u64,
) -> i32 {
    ffi_guard(0, || {
        if wd.is_null() {
            return 0;
        }
        let wd = unsafe { &*wd };
        wd.unguard(crate::watchdog::GuardId::from_raw(id)) as i32
    })
}

/// Returns how many times the watchdog has rewritten a tampered region since it
/// was created, or `0` if `wd` is null.
///
/// # Safety
/// `wd` must be a valid watchdog pointer from `detours_watchdog_create`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_watchdog_restorations(
    wd: *const crate::watchdog::Watchdog,
) -> u64 {
    if wd.is_null() {
        return 0;
    }
    unsafe { &*wd }.restorations()
}

/// Sets the watchdog's reaction to tampering: re-apply the patch
/// (`detect_only == 0`, the default) or only report it (`detect_only != 0`).
///
/// Returns `1` on success, or `0` if `wd` is null.
///
/// # Safety
/// `wd` must be a valid watchdog pointer from `detours_watchdog_create`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_watchdog_set_mode(
    wd: *const crate::watchdog::Watchdog,
    detect_only: i32,
) -> i32 {
    if wd.is_null() {
        return 0;
    }
    let mode = if detect_only != 0 {
        crate::watchdog::WatchMode::DetectOnly
    } else {
        crate::watchdog::WatchMode::Restore
    };
    unsafe { &*wd }.set_mode(mode);
    1
}

/// Callback invoked once per tamper episode by a watchdog. `restored` is `1` if
/// the watchdog rewrote the canonical bytes this sweep, `0` otherwise. The
/// `expected`/`found` buffers are each `len` bytes and valid only for the
/// duration of the call. `user` is the opaque pointer passed to
/// `detours_watchdog_set_on_tamper`.
///
/// Pass `NULL` to clear an installed callback.
// The `Option` belongs in the alias, not at the call site: cbindgen renders
// `Option<FnPtr>` as a plain nullable function pointer, but cannot see through
// `Option<SomeAlias>` and would emit an opaque, uncallable struct instead.
pub type DetoursTamperCallback = Option<
    unsafe extern "C" fn(
        guard_id: u64,
        target: *const u8,
        expected: *const u8,
        found: *const u8,
        len: usize,
        restored: i32,
        user: *mut c_void,
    ),
>;

/// Installs (`cb != NULL`) or clears (`cb == NULL`) the tamper callback. The
/// callback runs on the watchdog's background thread.
///
/// Returns `1` on success, or `0` if `wd` is null.
///
/// # Safety
/// `wd` must be a valid watchdog pointer from `detours_watchdog_create`. `cb`,
/// when non-null, must be callable for the watchdog's lifetime, and `user` is
/// passed through unchanged on every invocation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_watchdog_set_on_tamper(
    wd: *const crate::watchdog::Watchdog,
    cb: DetoursTamperCallback,
    user: *mut c_void,
) -> i32 {
    if wd.is_null() {
        return 0;
    }
    let wd = unsafe { &*wd };
    match cb {
        None => wd.clear_on_tamper(),
        Some(cb) => {
            // Carry `user` as an integer so the closure stays `Send + Sync`.
            let user = user as usize;
            wd.on_tamper(move |ev: &crate::watchdog::TamperEvent| {
                // SAFETY: `cb` is a valid C function pointer and `user` is opaque
                // to NeoHook; the byte slices are valid for this call.
                unsafe {
                    cb(
                        ev.guard_id.raw(),
                        ev.target,
                        ev.expected.as_ptr(),
                        ev.found.as_ptr(),
                        ev.expected.len(),
                        ev.restored as i32,
                        user as *mut c_void,
                    );
                }
            });
        }
    }
    1
}

/// Stops the watchdog's background thread and frees it.
///
/// Returns `1` if the watchdog was accepted for destruction, or `0` if null.
///
/// # Safety
/// `wd` must be a valid watchdog pointer previously returned by
/// `detours_watchdog_create` and must not be used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_watchdog_destroy(wd: *mut crate::watchdog::Watchdog) -> i32 {
    ffi_guard(0, || {
        if wd.is_null() {
            return 0;
        }
        // Dropping the box stops and joins the background thread via RAII.
        drop(unsafe { Box::from_raw(wd) });
        1
    })
}

// ---------------------------------------------------------------------------
// Control Flow Guard (CFG) awareness
// ---------------------------------------------------------------------------

/// Returns `1` if NeoHook will register Control Flow Guard call targets for this
/// process, `0` otherwise.
///
/// Reflects a `detours_cfg_set_enforcement` override if one is set, otherwise the
/// process's CFG mitigation policy. See [`crate::cfg`].
#[unsafe(no_mangle)]
pub extern "C" fn detours_cfg_is_enforced() -> i32 {
    crate::cfg::is_enforced() as i32
}

/// Overrides CFG handling: `mode < 0` returns to auto-detection, `mode == 0`
/// forces it off (the whole layer becomes a no-op), `mode > 0` forces it on.
#[unsafe(no_mangle)]
pub extern "C" fn detours_cfg_set_enforcement(mode: i32) {
    let state = match mode {
        m if m < 0 => None,
        0 => Some(false),
        _ => Some(true),
    };
    crate::cfg::set_enforcement(state);
}

/// Marks `entry` as a valid Control Flow Guard indirect-call target, so
/// runtime-generated code can be reached through a guarded indirect call.
///
/// Returns `1` if the target was registered, `0` if registration was skipped
/// (CFG not enforced) or `entry` is null. See [`crate::cfg::register_valid_target`].
///
/// # Safety
/// `entry` must point at the entry of executable, committed memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_cfg_register_valid_target(entry: *const u8) -> i32 {
    crate::cfg::register_valid_target(entry) as i32
}

// ---------------------------------------------------------------------------
// Deferred stub reclamation
// ---------------------------------------------------------------------------

/// Releases executable stubs (trampolines, gateways, export stubs) retired by
/// earlier unhooks, once no thread is executing inside them.
///
/// NeoHook does this automatically at the start of every transaction; call it
/// directly from code that only ever unhooks and never installs again, to bound
/// the memory held by the reclamation quarantine. See [`crate::reclaim`].
#[unsafe(no_mangle)]
pub extern "C" fn detours_reclaim() {
    ffi_guard((), || {
        crate::reclaim::reclaim();
    })
}

// --- signature inference -----------------------------------------------------

/// Most arguments a [`DetoursSignature`] holds; more are reported through
/// `truncated`.
pub const DETOURS_MAX_SIGNATURE_ARGS: usize = 32;

/// [`DetoursSignature::convention`]: the x64 Windows convention.
pub const DETOURS_CONVENTION_WIN64: u8 = 0;
/// [`DetoursSignature::convention`]: x86, stack arguments removed by the caller.
pub const DETOURS_CONVENTION_CDECL: u8 = 1;
/// [`DetoursSignature::convention`]: x86, stack arguments removed by the callee.
pub const DETOURS_CONVENTION_STDCALL: u8 = 2;
/// [`DetoursSignature::convention`]: x86, first two arguments in `ecx` / `edx`.
pub const DETOURS_CONVENTION_FASTCALL: u8 = 3;
/// [`DetoursSignature::convention`]: x86, `this` in `ecx`.
pub const DETOURS_CONVENTION_THISCALL: u8 = 4;

/// Argument or return kind: 8-bit integer.
pub const DETOURS_VALUE_KIND_INT8: u8 = 0;
/// Argument or return kind: 16-bit integer.
pub const DETOURS_VALUE_KIND_INT16: u8 = 1;
/// Argument or return kind: 32-bit integer.
pub const DETOURS_VALUE_KIND_INT32: u8 = 2;
/// Argument or return kind: 64-bit integer (on x64 possibly a pointer that is
/// never dereferenced).
pub const DETOURS_VALUE_KIND_INT64: u8 = 3;
/// Argument or return kind: a pointer, used as an address.
pub const DETOURS_VALUE_KIND_POINTER: u8 = 4;
/// Argument or return kind: 32-bit floating point.
pub const DETOURS_VALUE_KIND_FLOAT: u8 = 5;
/// Argument or return kind: 64-bit floating point.
pub const DETOURS_VALUE_KIND_DOUBLE: u8 = 6;
/// Argument or return kind: present, but nothing reveals its type.
pub const DETOURS_VALUE_KIND_UNKNOWN: u8 = 7;

// The C constants are literals so cbindgen can emit them; keep them in step
// with the Rust enums.
const _: () = {
    assert!(crate::CallingConvention::Win64 as u8 == DETOURS_CONVENTION_WIN64);
    assert!(crate::CallingConvention::Cdecl as u8 == DETOURS_CONVENTION_CDECL);
    assert!(crate::CallingConvention::Stdcall as u8 == DETOURS_CONVENTION_STDCALL);
    assert!(crate::CallingConvention::Fastcall as u8 == DETOURS_CONVENTION_FASTCALL);
    assert!(crate::CallingConvention::Thiscall as u8 == DETOURS_CONVENTION_THISCALL);
    assert!(crate::ValueKind::Int8 as u8 == DETOURS_VALUE_KIND_INT8);
    assert!(crate::ValueKind::Int16 as u8 == DETOURS_VALUE_KIND_INT16);
    assert!(crate::ValueKind::Int32 as u8 == DETOURS_VALUE_KIND_INT32);
    assert!(crate::ValueKind::Int64 as u8 == DETOURS_VALUE_KIND_INT64);
    assert!(crate::ValueKind::Pointer as u8 == DETOURS_VALUE_KIND_POINTER);
    assert!(crate::ValueKind::Float as u8 == DETOURS_VALUE_KIND_FLOAT);
    assert!(crate::ValueKind::Double as u8 == DETOURS_VALUE_KIND_DOUBLE);
    assert!(crate::ValueKind::Unknown as u8 == DETOURS_VALUE_KIND_UNKNOWN);
};

/// One inferred argument, as returned by [`detours_infer_signature`].
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DetoursArgGuess {
    /// The rough type of the argument, one of `DETOURS_VALUE_KIND_*`.
    pub kind: u8,
    /// `1` if the argument is on the stack, `0` if it is in a register.
    pub on_stack: u8,
    /// The register name (`"rcx"`, `"xmm1"`, `"ecx"`), NUL-terminated; empty
    /// for a stack argument.
    pub register_name: [c_char; 8],
    /// Byte offset from the stack pointer at entry, for a stack argument.
    pub stack_offset: u32,
    /// How sure the analysis is about this argument, from 0.0 to 1.0.
    pub confidence: f32,
}

/// An inferred signature, filled in by [`detours_infer_signature`]. Allocated
/// by the caller; it holds no pointers and needs no release.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DetoursSignature {
    /// The calling convention the code matches, one of `DETOURS_CONVENTION_*`.
    pub convention: u8,
    /// `1` if the function returns a value, `0` for `void`.
    pub has_return: u8,
    /// The rough type of the return value, one of `DETOURS_VALUE_KIND_*`;
    /// meaningless when `has_return` is 0.
    pub returns: u8,
    /// `0` if a path could not be followed to its end, so arguments used only
    /// there may be missing.
    pub complete: u8,
    /// `1` if the function has more than [`DETOURS_MAX_SIGNATURE_ARGS`]
    /// arguments and only the first ones are in `args`.
    pub truncated: u8,
    /// Bytes the function removes from the stack on return (`ret N`), x86 only.
    pub stack_cleanup: u32,
    /// Number of valid entries in `args`.
    pub arg_count: u32,
    /// The arguments, in declaration order.
    pub args: [DetoursArgGuess; DETOURS_MAX_SIGNATURE_ARGS],
}

impl DetoursSignature {
    fn from_guess(guess: &crate::SignatureGuess) -> Self {
        let empty = DetoursArgGuess {
            kind: DETOURS_VALUE_KIND_UNKNOWN,
            on_stack: 0,
            register_name: [0; 8],
            stack_offset: 0,
            confidence: 0.0,
        };
        let mut out = Self {
            convention: guess.convention as u8,
            has_return: guess.returns.is_some() as u8,
            returns: guess.returns.unwrap_or(crate::ValueKind::Unknown) as u8,
            complete: guess.complete as u8,
            truncated: (guess.args.len() > DETOURS_MAX_SIGNATURE_ARGS) as u8,
            stack_cleanup: guess.stack_cleanup,
            arg_count: guess.args.len().min(DETOURS_MAX_SIGNATURE_ARGS) as u32,
            args: [empty; DETOURS_MAX_SIGNATURE_ARGS],
        };
        for (slot, arg) in out.args.iter_mut().zip(&guess.args) {
            slot.kind = arg.kind as u8;
            slot.confidence = arg.confidence;
            match arg.location {
                crate::ArgLocation::Register(name) => {
                    // Names are at most 5 bytes; the rest stays NUL.
                    for (dst, &src) in slot.register_name.iter_mut().zip(name.as_bytes()) {
                        *dst = src as c_char;
                    }
                }
                crate::ArgLocation::Stack(offset) => {
                    slot.on_stack = 1;
                    slot.stack_offset = offset;
                }
            }
        }
        out
    }
}

/// Infers the argument count and types, return type and calling convention of
/// the function at `func` from its machine code, writing the result to `out`.
///
/// The result is a best-effort estimate; see `neohook::infer_signature` for
/// what the analysis can and cannot see.
///
/// Returns `1` on success, or `0` if `func` or `out` is null or the code is
/// not readable.
///
/// # Safety
/// `func` must point at the start of a function in mapped memory, and `out` at
/// writable storage for a `DetoursSignature`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_infer_signature(
    func: *const u8,
    out: *mut DetoursSignature,
) -> i32 {
    if func.is_null() || out.is_null() {
        return 0;
    }
    ffi_guard(0, || match unsafe { crate::infer_signature(func) } {
        Ok(guess) => {
            unsafe { out.write(DetoursSignature::from_guess(&guess)) };
            1
        }
        Err(_) => 0,
    })
}

/// Like [`detours_infer_signature`], for the export `func` of `module` (loaded
/// if it is not already present).
///
/// Returns `1` on success, or `0` if an argument is null or not valid UTF-8,
/// the export cannot be resolved, or its code is not readable.
///
/// # Safety
/// `module` and `func` must be valid NUL-terminated C strings, and `out` must
/// point at writable storage for a `DetoursSignature`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn detours_infer_signature_by_name(
    module: *const c_char,
    func: *const c_char,
    out: *mut DetoursSignature,
) -> i32 {
    if module.is_null() || func.is_null() || out.is_null() {
        return 0;
    }
    let Ok(module) = (unsafe { CStr::from_ptr(module) }).to_str() else {
        return 0;
    };
    let Ok(func) = (unsafe { CStr::from_ptr(func) }).to_str() else {
        return 0;
    };
    ffi_guard(0, || match crate::infer_signature_by_name(module, func) {
        Ok(guess) => {
            unsafe { out.write(DetoursSignature::from_guess(&guess)) };
            1
        }
        Err(_) => 0,
    })
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

#[cfg(test)]
mod signature_ffi_tests {
    use super::*;
    use crate::{ArgGuess, ArgLocation, CallingConvention, SignatureGuess, ValueKind};

    fn arg(location: ArgLocation, kind: ValueKind) -> ArgGuess {
        ArgGuess {
            location,
            kind,
            confidence: 0.5,
        }
    }

    #[test]
    fn from_guess_copies_registers_and_stack_slots() {
        let guess = SignatureGuess {
            convention: CallingConvention::Win64,
            args: vec![
                arg(ArgLocation::Register("xmm1"), ValueKind::Double),
                arg(ArgLocation::Stack(0x28), ValueKind::Pointer),
            ],
            returns: None,
            stack_cleanup: 0,
            complete: true,
        };
        let sig = DetoursSignature::from_guess(&guess);
        assert_eq!(sig.convention, DETOURS_CONVENTION_WIN64);
        assert_eq!(sig.has_return, 0);
        assert_eq!(sig.complete, 1);
        assert_eq!(sig.truncated, 0);
        assert_eq!(sig.arg_count, 2);

        let name = unsafe { CStr::from_ptr(sig.args[0].register_name.as_ptr()) };
        assert_eq!(name.to_str().unwrap(), "xmm1");
        assert_eq!(sig.args[0].on_stack, 0);
        assert_eq!(sig.args[0].kind, DETOURS_VALUE_KIND_DOUBLE);

        assert_eq!(sig.args[1].on_stack, 1);
        assert_eq!(sig.args[1].stack_offset, 0x28);
        assert_eq!(sig.args[1].register_name, [0; 8]);
        assert_eq!(sig.args[1].kind, DETOURS_VALUE_KIND_POINTER);
        assert_eq!(sig.args[1].confidence, 0.5);
    }

    #[test]
    fn from_guess_truncates_past_the_capacity() {
        let guess = SignatureGuess {
            convention: CallingConvention::Cdecl,
            args: (0..DETOURS_MAX_SIGNATURE_ARGS + 5)
                .map(|i| arg(ArgLocation::Stack(4 + 4 * i as u32), ValueKind::Int32))
                .collect(),
            returns: Some(ValueKind::Int64),
            stack_cleanup: 0,
            complete: false,
        };
        let sig = DetoursSignature::from_guess(&guess);
        assert_eq!(sig.truncated, 1);
        assert_eq!(sig.arg_count as usize, DETOURS_MAX_SIGNATURE_ARGS);
        assert_eq!(sig.has_return, 1);
        assert_eq!(sig.returns, DETOURS_VALUE_KIND_INT64);
        assert_eq!(sig.complete, 0);
        let last = sig.args[DETOURS_MAX_SIGNATURE_ARGS - 1];
        assert_eq!(
            last.stack_offset,
            4 + 4 * (DETOURS_MAX_SIGNATURE_ARGS as u32 - 1)
        );
    }
}
