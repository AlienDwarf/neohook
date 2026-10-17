// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::DetourError;
use std::alloc::{Layout, alloc, dealloc};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, OnceLock};
use windows_sys::Win32::System::Memory::{PAGE_READWRITE, VirtualProtect};

#[derive(Debug)]
enum InternalVTableHookError {
    NullVTable,
    NullDetour,
    NullObject,
    InvalidLength,
    IndexOutOfRange,
    /// Another live hook already redirects the slot.
    SlotTaken,
    AllocationFailed,
    ProtectFailed(std::io::Error),
}

#[derive(Debug)]
pub enum VTableHookError {
    /// One or more pointers/arguments were invalid.
    InvalidParameter,
    /// Memory for a cloned VTable could not be allocated.
    AllocationFailed,
    /// Changing page protection for the VTable slot failed.
    ProtectFailed(std::io::Error),
}

impl fmt::Display for VTableHookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameter => write!(f, "invalid VTable hook parameters"),
            Self::AllocationFailed => write!(f, "failed to allocate memory for cloned VTable"),
            Self::ProtectFailed(e) => write!(f, "failed to change page protection: {e}"),
        }
    }
}

impl std::error::Error for VTableHookError {}

impl From<InternalVTableHookError> for VTableHookError {
    fn from(err: InternalVTableHookError) -> Self {
        match err {
            InternalVTableHookError::NullVTable
            | InternalVTableHookError::NullDetour
            | InternalVTableHookError::NullObject
            | InternalVTableHookError::InvalidLength
            | InternalVTableHookError::IndexOutOfRange
            | InternalVTableHookError::SlotTaken => Self::InvalidParameter,
            InternalVTableHookError::AllocationFailed => Self::AllocationFailed,
            InternalVTableHookError::ProtectFailed(e) => Self::ProtectFailed(e),
        }
    }
}

#[inline]
fn map_err(err: InternalVTableHookError) -> VTableHookError {
    err.into()
}

/// Installed VTable hook guard.
///
/// This patches a slot in a VTable, not an object's vptr itself. Therefore all
/// objects that dispatch through the same VTable observe the hook.
#[derive(Debug)]
pub struct VTableHook {
    slot: *mut *mut u8,
    original_ptr: *mut u8,
    detour: *mut u8,
    /// Whether this hook still holds the claim on `slot`.
    claimed: bool,
    active: bool,
    enabled: bool,
}

impl VTableHook {
    /// Hooks a single VTable slot and returns a guard that restores the original
    /// slot pointer on drop.
    ///
    /// # Safety
    /// - `vtable` must point to a valid VTable array.
    /// - `index` must refer to a valid slot inside that VTable.
    /// - `detour` must be a function pointer with a compatible ABI/signature.
    ///
    /// # Errors
    ///
    /// Returns [`VTableHookError::InvalidParameter`] if `vtable` or `detour`
    /// is null, or if another live hook already redirects the slot.
    ///
    /// Returns [`VTableHookError::ProtectFailed`] if changing protection on the
    /// selected VTable slot fails.
    pub unsafe fn install(
        vtable: *mut *mut u8,
        index: usize,
        detour: *const u8,
    ) -> Result<Self, VTableHookError> {
        if vtable.is_null() {
            return Err(map_err(InternalVTableHookError::NullVTable));
        }
        if detour.is_null() {
            return Err(map_err(InternalVTableHookError::NullDetour));
        }

        // The slot is dispatched through a CFG-guarded indirect call; mark the
        // detour as a valid call target so dispatch holds under strict CFG /
        // export suppression. No-op otherwise and when CFG is not enforced.
        crate::cfg::register_valid_target(detour);

        let slot = unsafe { vtable.add(index) };
        let slot_size = std::mem::size_of::<*mut u8>();

        // Serialized with every other code and table write on the page.
        let original_ptr = crate::transaction::with_code_lock(|| {
            if !crate::transaction::claim_table_slot(slot as usize) {
                return Err(map_err(InternalVTableHookError::SlotTaken));
            }
            let mut old_protect = 0u32;
            if unsafe {
                crate::mem::virtual_protect_same_execute(
                    slot.cast(),
                    slot_size,
                    PAGE_READWRITE,
                    &mut old_protect,
                )
            } == 0
            {
                let err = std::io::Error::last_os_error();
                crate::transaction::release_table_slot(slot as usize);
                return Err(map_err(InternalVTableHookError::ProtectFailed(err)));
            }

            let original_ptr = unsafe { *slot };
            unsafe {
                *slot = detour as *mut u8;
            }

            let mut ignored = 0u32;
            if unsafe { VirtualProtect(slot.cast(), slot_size, old_protect, &mut ignored) } == 0 {
                let protect_err = std::io::Error::last_os_error();
                unsafe {
                    *slot = original_ptr;
                }
                let _ =
                    unsafe { VirtualProtect(slot.cast(), slot_size, old_protect, &mut ignored) };
                crate::transaction::release_table_slot(slot as usize);

                return Err(map_err(InternalVTableHookError::ProtectFailed(protect_err)));
            }
            Ok(original_ptr)
        })?;

        Ok(Self {
            slot,
            original_ptr,
            detour: detour as *mut u8,
            claimed: true,
            active: true,
            enabled: true,
        })
    }

    /// Returns the original function pointer that was stored in the patched slot.
    pub fn original_ptr(&self) -> *const u8 {
        self.original_ptr
    }

    /// Returns whether the slot currently points at the detour.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Restores the original slot pointer while keeping the hook so it can be
    /// re-enabled later.
    pub fn disable(&mut self) -> Result<(), DetourError> {
        if !self.enabled {
            return Ok(());
        }
        Self::write_slot(self.slot, self.original_ptr)?;
        self.enabled = false;
        Ok(())
    }

    /// Re-points the slot at the detour after a [`Self::disable`]. Fails with
    /// [`DetourError::InvalidParameter`] once the hook has been detached.
    pub fn enable(&mut self) -> Result<(), DetourError> {
        if !self.active {
            return Err(DetourError::InvalidParameter);
        }
        if self.enabled {
            return Ok(());
        }
        Self::write_slot(self.slot, self.detour)?;
        self.enabled = true;
        Ok(())
    }

    /// Unhooks this VTable hook by restoring the original slot pointer.
    pub fn unhook(mut self) -> Result<(), DetourError> {
        if !self.active {
            return Ok(());
        }
        self.perform_unhook()?;
        self.active = false;
        Ok(())
    }

    fn perform_unhook(&self) -> Result<(), DetourError> {
        Self::write_slot(self.slot, self.original_ptr)
    }

    pub(crate) fn detach_finalize(&mut self) {
        let restored = !self.enabled || self.disable().is_ok();
        self.active = false;
        self.enabled = false;
        // A detached hook frees its slot for the next hook right away.
        if restored && self.claimed {
            crate::transaction::release_table_slot(self.slot as usize);
            self.claimed = false;
        }
    }

    /// Writes `value` into `slot`, flipping page protection around the write.
    /// Serialized with every other code and table write on the page.
    fn write_slot(slot: *mut *mut u8, value: *mut u8) -> Result<(), DetourError> {
        crate::transaction::with_code_lock(|| Self::write_slot_locked(slot, value))
    }

    fn write_slot_locked(slot: *mut *mut u8, value: *mut u8) -> Result<(), DetourError> {
        if slot.is_null() {
            return Err(map_err(InternalVTableHookError::NullVTable).into());
        }

        let slot_size = std::mem::size_of::<*mut u8>();
        let mut old_protect = 0u32;
        if unsafe {
            crate::mem::virtual_protect_same_execute(
                slot.cast(),
                slot_size,
                PAGE_READWRITE,
                &mut old_protect,
            )
        } == 0
        {
            return Err(map_err(InternalVTableHookError::ProtectFailed(
                std::io::Error::last_os_error(),
            ))
            .into());
        }

        let previous = unsafe { *slot };
        unsafe {
            *slot = value;
        }

        let mut ignored = 0u32;
        if unsafe { VirtualProtect(slot.cast(), slot_size, old_protect, &mut ignored) } == 0 {
            // Leave the slot as it was, so `enabled` still describes it.
            let err = std::io::Error::last_os_error();
            unsafe {
                *slot = previous;
            }
            let _ = unsafe { VirtualProtect(slot.cast(), slot_size, old_protect, &mut ignored) };
            return Err(map_err(InternalVTableHookError::ProtectFailed(err)).into());
        }

        Ok(())
    }
}

impl Drop for VTableHook {
    fn drop(&mut self) {
        // A slot still pointing at the detour stays claimed, so no later hook
        // stacks on it.
        if self.claimed && (!self.active || self.perform_unhook().is_ok()) {
            crate::transaction::release_table_slot(self.slot as usize);
        }
    }
}

/// Heap storage for a per-instance VTable clone, released on drop unless a hook
/// takes it over.
pub(crate) struct ClonedVtable {
    ptr: *mut u8,
    len: usize,
}

/// A clone holds `len` slots followed by one ownership flag per slot.
fn clone_layout(len: usize) -> Option<Layout> {
    let size = len
        .checked_mul(std::mem::size_of::<*mut u8>())?
        .checked_add(len)?;
    Layout::from_size_align(size, std::mem::align_of::<*mut u8>()).ok()
}

impl ClonedVtable {
    /// Allocates room for a clone of a VTable with `len` slots.
    pub(crate) fn new(len: usize) -> Result<Self, VTableHookError> {
        if len == 0 {
            return Err(map_err(InternalVTableHookError::InvalidLength));
        }
        let layout =
            clone_layout(len).ok_or_else(|| map_err(InternalVTableHookError::AllocationFailed))?;
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            return Err(map_err(InternalVTableHookError::AllocationFailed));
        }
        Ok(Self { ptr, len })
    }
}

impl Drop for ClonedVtable {
    fn drop(&mut self) {
        if let Some(layout) = clone_layout(self.len) {
            unsafe { dealloc(self.ptr, layout) };
        }
    }
}

/// A VTable clone shared by every instance hook on one object, keyed in
/// [`instance_clones`] by the object's vptr field.
struct SharedClone {
    clone: usize,
    len: usize,
    original_vtable: usize,
    /// Installed hooks using this clone.
    hooks: usize,
}

/// The clones of instance-hooked objects. A second hook on the same object
/// patches the existing clone instead of cloning the clone, so the hooks can be
/// removed in any order; the clone is released with the last of them.
///
/// Only touched under the code lock, so no suspended thread can hold it while a
/// commit installs inside its suspend window. Inserting there does not
/// allocate, as [`reserve_instance_clones`] made room beforehand.
fn instance_clones() -> &'static Mutex<HashMap<usize, SharedClone>> {
    static CLONES: OnceLock<Mutex<HashMap<usize, SharedClone>>> = OnceLock::new();
    CLONES.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) fn reserve_instance_clones(additional: usize) {
    crate::transaction::with_code_lock(|| {
        let _ = instance_clones()
            .lock()
            .map(|mut clones| clones.reserve(additional));
    });
}

/// Whether a live instance hook redirects slot `index` of the object whose vptr
/// field is `object_vptr`.
pub(crate) fn instance_slot_hooked(object_vptr: *mut *mut u8, index: usize) -> bool {
    crate::transaction::with_code_lock(|| {
        instance_clones().lock().is_ok_and(|clones| {
            clones.get(&(object_vptr as usize)).is_some_and(|shared| {
                index < shared.len && unsafe { *owned_flag(shared.clone, shared.len, index) }
            })
        })
    })
}

/// The flag marking slot `index` of a clone as owned by a hook, enabled or not.
/// The flags follow the `len` slots in the clone's allocation.
unsafe fn owned_flag(clone: usize, len: usize, index: usize) -> *mut bool {
    unsafe { (clone as *mut *mut u8).add(len).cast::<bool>().add(index) }
}

/// Installed per-instance VTable hook guard.
///
/// This clones the object's VTable, patches the selected slot in the clone,
/// and then redirects the object to the cloned VTable. Only that object is
/// affected. Further instance hooks on the same object share the clone, each
/// patching its own slot; a slot can be hooked only once.
#[derive(Debug)]
pub struct VTableInstanceHook {
    object_vptr: *mut *mut u8,
    cloned_vtable: *mut u8,
    index: usize,
    original_ptr: *mut u8,
    detour: *mut u8,
    active: bool,
    enabled: bool,
}

impl VTableInstanceHook {
    /// Hooks a single object's VTable by cloning the table, patching the clone,
    /// and redirecting the object's vptr to the cloned table. If the object is
    /// already instance-hooked, the slot is patched in the existing clone.
    ///
    /// # Safety
    /// - `object_vptr` must point to the object's vptr field.
    /// - `vtable_len` must cover the full VTable so the clone is valid.
    /// - `index` must refer to an existing slot in that VTable.
    /// - `detour` must be a function pointer with a compatible ABI/signature.
    ///
    /// # Errors
    ///
    /// Returns [`VTableHookError::InvalidParameter`] if one of the arguments is
    /// invalid, the selected slot is out of range, or an instance hook already
    /// redirects that slot of the object.
    ///
    /// Returns [`VTableHookError::AllocationFailed`] if memory for the cloned
    /// VTable cannot be allocated.
    ///
    /// Returns [`VTableHookError::ProtectFailed`] if changing protection on the
    /// object's vptr field fails.
    pub unsafe fn install(
        object_vptr: *mut *mut u8,
        vtable_len: usize,
        index: usize,
        detour: *const u8,
    ) -> Result<Self, VTableHookError> {
        if object_vptr.is_null() {
            return Err(map_err(InternalVTableHookError::NullObject));
        }
        if detour.is_null() {
            return Err(map_err(InternalVTableHookError::NullDetour));
        }
        if vtable_len == 0 {
            return Err(map_err(InternalVTableHookError::InvalidLength));
        }
        if index >= vtable_len {
            return Err(map_err(InternalVTableHookError::IndexOutOfRange));
        }

        let mut table = Some(ClonedVtable::new(vtable_len)?);
        reserve_instance_clones(1);
        unsafe { Self::install_into(object_vptr, index, detour, &mut table) }
    }

    /// Installs the hook into clone storage allocated up front, so a commit can
    /// call this while other threads are suspended without touching the heap.
    ///
    /// `table` is taken only if a new clone is registered. Otherwise - on
    /// failure, or when the object already has a clone - it is left in place
    /// for the caller to release once doing so is safe.
    ///
    /// # Safety
    /// Same contract as [`Self::install`], with `table` sized for the full VTable.
    pub(crate) unsafe fn install_into(
        object_vptr: *mut *mut u8,
        index: usize,
        detour: *const u8,
        table: &mut Option<ClonedVtable>,
    ) -> Result<Self, VTableHookError> {
        if object_vptr.is_null() {
            return Err(map_err(InternalVTableHookError::NullObject));
        }
        if detour.is_null() {
            return Err(map_err(InternalVTableHookError::NullDetour));
        }

        // The cloned slot is dispatched through a CFG-guarded indirect call; mark
        // the detour as a valid call target so dispatch holds under strict CFG /
        // export suppression. No-op otherwise and when CFG is not enforced.
        crate::cfg::register_valid_target(detour);

        // Serialized with every other code and table write on the page, and
        // with every other user of the clone registry.
        crate::transaction::with_code_lock(|| {
            let mut clones = instance_clones()
                .lock()
                .map_err(|_| map_err(InternalVTableHookError::AllocationFailed))?;

            if let Some(shared) = clones.get_mut(&(object_vptr as usize)) {
                if index >= shared.len {
                    return Err(map_err(InternalVTableHookError::IndexOutOfRange));
                }
                // The object must still dispatch through the clone, and no other
                // hook may own the slot.
                let owned = unsafe { owned_flag(shared.clone, shared.len, index) };
                if unsafe { *object_vptr } as usize != shared.clone || unsafe { *owned } {
                    return Err(map_err(InternalVTableHookError::SlotTaken));
                }
                let slot = unsafe { (shared.clone as *mut *mut u8).add(index) };
                let original_ptr = unsafe { *slot };
                unsafe {
                    *slot = detour as *mut u8;
                    *owned = true;
                }
                shared.hooks += 1;
                return Ok(Self {
                    object_vptr,
                    cloned_vtable: shared.clone as *mut u8,
                    index,
                    original_ptr,
                    detour: detour as *mut u8,
                    active: true,
                    enabled: true,
                });
            }

            let Some(storage) = table.as_ref() else {
                return Err(map_err(InternalVTableHookError::AllocationFailed));
            };
            let (cloned_vtable, vtable_len) = (storage.ptr, storage.len);
            if index >= vtable_len {
                return Err(map_err(InternalVTableHookError::IndexOutOfRange));
            }

            let original_vtable = unsafe { *object_vptr };
            if original_vtable.is_null() {
                return Err(map_err(InternalVTableHookError::NullVTable));
            }

            unsafe {
                std::ptr::copy_nonoverlapping(
                    original_vtable as *const *mut u8,
                    cloned_vtable as *mut *mut u8,
                    vtable_len,
                );
            }

            let slot = unsafe { (cloned_vtable as *mut *mut u8).add(index) };
            let original_ptr = unsafe { *slot };
            unsafe {
                *slot = detour as *mut u8;
                std::ptr::write_bytes(
                    owned_flag(cloned_vtable as usize, vtable_len, 0),
                    0,
                    vtable_len,
                );
                *owned_flag(cloned_vtable as usize, vtable_len, index) = true;
            }

            Self::write_vptr_locked(object_vptr, cloned_vtable).map_err(|err| match err {
                DetourError::Vtable(err) => err,
                _ => map_err(InternalVTableHookError::NullObject),
            })?;

            clones.insert(
                object_vptr as usize,
                SharedClone {
                    clone: cloned_vtable as usize,
                    len: vtable_len,
                    original_vtable: original_vtable as usize,
                    hooks: 1,
                },
            );
            // The object now uses the clone; the registry owns and releases it.
            if let Some(storage) = table.take() {
                std::mem::forget(storage);
            }

            Ok(Self {
                object_vptr,
                cloned_vtable,
                index,
                original_ptr,
                detour: detour as *mut u8,
                active: true,
                enabled: true,
            })
        })
    }

    /// Returns the original function pointer that was stored in the patched slot.
    pub fn original_ptr(&self) -> *const u8 {
        self.original_ptr
    }

    /// Returns whether the hooked slot of the cloned VTable currently points at
    /// the detour.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Restores the original pointer in the cloned slot while keeping the clone,
    /// so the hook can be re-enabled later. Other instance hooks on the same
    /// object stay in effect.
    pub fn disable(&mut self) -> Result<(), DetourError> {
        if !self.enabled {
            return Ok(());
        }
        self.write_clone_slot(self.original_ptr)?;
        self.enabled = false;
        Ok(())
    }

    /// Re-points the cloned slot at the detour after a [`Self::disable`].
    /// Fails with [`DetourError::InvalidParameter`] once the hook has been
    /// detached.
    pub fn enable(&mut self) -> Result<(), DetourError> {
        if !self.active {
            return Err(DetourError::InvalidParameter);
        }
        if self.enabled {
            return Ok(());
        }
        self.write_clone_slot(self.detour)?;
        self.enabled = true;
        Ok(())
    }

    /// Writes the hooked slot of the clone. The clone is plain heap memory owned
    /// by the registry, so no protection change is needed.
    fn write_clone_slot(&self, value: *mut u8) -> Result<(), DetourError> {
        if self.cloned_vtable.is_null() {
            return Err(map_err(InternalVTableHookError::NullObject).into());
        }
        crate::transaction::with_code_lock(|| unsafe {
            *(self.cloned_vtable as *mut *mut u8).add(self.index) = value;
        });
        Ok(())
    }

    /// Writes `value` into the object's vptr field, flipping page protection
    /// around the write. The caller holds the code lock.
    fn write_vptr_locked(object_vptr: *mut *mut u8, value: *mut u8) -> Result<(), DetourError> {
        if object_vptr.is_null() {
            return Err(map_err(InternalVTableHookError::NullObject).into());
        }

        let mut old_protect = 0u32;
        if unsafe {
            crate::mem::virtual_protect_same_execute(
                object_vptr.cast(),
                std::mem::size_of::<*mut u8>(),
                PAGE_READWRITE,
                &mut old_protect,
            )
        } == 0
        {
            return Err(map_err(InternalVTableHookError::ProtectFailed(
                std::io::Error::last_os_error(),
            ))
            .into());
        }

        let previous = unsafe { *object_vptr };
        unsafe {
            *object_vptr = value;
        }

        let mut ignored = 0u32;
        if unsafe {
            VirtualProtect(
                object_vptr.cast(),
                std::mem::size_of::<*mut u8>(),
                old_protect,
                &mut ignored,
            )
        } == 0
        {
            // Leave the field as it was, so the caller's state stays accurate.
            let err = std::io::Error::last_os_error();
            unsafe {
                *object_vptr = previous;
            }
            return Err(map_err(InternalVTableHookError::ProtectFailed(err)).into());
        }

        Ok(())
    }

    /// Unhooks the instance hook by restoring the original slot pointer. The
    /// last hook on the object also restores its original VTable pointer and
    /// releases the cloned VTable memory.
    pub fn unhook(mut self) -> Result<(), DetourError> {
        if !self.active {
            return Ok(());
        }
        self.perform_unhook()?;
        self.active = false;
        Ok(())
    }

    fn perform_unhook(&mut self) -> Result<(), DetourError> {
        if self.object_vptr.is_null() || self.cloned_vtable.is_null() {
            return Err(map_err(InternalVTableHookError::NullObject).into());
        }

        let release = crate::transaction::with_code_lock(|| {
            let mut clones = instance_clones()
                .lock()
                .map_err(|_| DetourError::InvalidParameter)?;
            let Some(shared) = clones.get_mut(&(self.object_vptr as usize)) else {
                return Err(DetourError::from(map_err(
                    InternalVTableHookError::NullObject,
                )));
            };

            if shared.hooks == 1 {
                // The last hook: point the object back at its own table before
                // the clone goes away. Left registered if that fails, so nothing
                // frees memory the object still dispatches through.
                if unsafe { *self.object_vptr } as usize == shared.clone {
                    Self::write_vptr_locked(self.object_vptr, shared.original_vtable as *mut u8)?;
                }
                let shared = clones
                    .remove(&(self.object_vptr as usize))
                    .expect("entry looked up above");
                Ok(Some((shared.clone, shared.len)))
            } else {
                unsafe {
                    *(self.cloned_vtable as *mut *mut u8).add(self.index) = self.original_ptr;
                    *owned_flag(shared.clone, shared.len, self.index) = false;
                }
                shared.hooks -= 1;
                Ok(None)
            }
        })?;

        // Clear the pointer immediately so a subsequent `Drop` (e.g. if the
        // guard is still active) cannot release the clone twice.
        self.cloned_vtable = std::ptr::null_mut();
        if let Some((clone, len)) = release
            && let Some(layout) = clone_layout(len)
        {
            unsafe { dealloc(clone as *mut u8, layout) };
        }

        Ok(())
    }

    pub(crate) fn detach_finalize(&mut self) {
        if self.active {
            let _ = self.perform_unhook();
        }
        self.active = false;
        self.enabled = false;
    }
}

impl Drop for VTableInstanceHook {
    fn drop(&mut self) {
        if self.active {
            let _ = self.perform_unhook();
        }
    }
}
