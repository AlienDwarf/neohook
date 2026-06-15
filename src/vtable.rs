// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::DetourError;
use std::alloc::{Layout, alloc, dealloc};
use std::fmt;
use windows_sys::Win32::System::Memory::{PAGE_READWRITE, VirtualProtect};

#[derive(Debug)]
enum InternalVTableHookError {
    NullVTable,
    NullDetour,
    NullObject,
    InvalidLength,
    IndexOutOfRange,
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
            | InternalVTableHookError::IndexOutOfRange => Self::InvalidParameter,
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
    /// is null.
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

        let slot = unsafe { vtable.add(index) };
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
            )));
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
            let _ = unsafe { VirtualProtect(slot.cast(), slot_size, old_protect, &mut ignored) };

            return Err(map_err(InternalVTableHookError::ProtectFailed(protect_err)));
        }

        Ok(Self {
            slot,
            original_ptr,
            detour: detour as *mut u8,
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

    /// Re-points the slot at the detour after a [`Self::disable`].
    pub fn enable(&mut self) -> Result<(), DetourError> {
        if self.enabled {
            return Ok(());
        }
        Self::write_slot(self.slot, self.detour)?;
        self.enabled = true;
        Ok(())
    }

    /// Unhooks this VTable hook by restoring the original slot pointer.
    pub fn unhook(mut self) -> Result<(), DetourError> {
        self.perform_unhook()?;
        self.active = false;
        Ok(())
    }

    fn perform_unhook(&self) -> Result<(), DetourError> {
        Self::write_slot(self.slot, self.original_ptr)
    }

    /// Writes `value` into `slot`, flipping page protection around the write.
    fn write_slot(slot: *mut *mut u8, value: *mut u8) -> Result<(), DetourError> {
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

        unsafe {
            *slot = value;
        }

        let mut ignored = 0u32;
        if unsafe { VirtualProtect(slot.cast(), slot_size, old_protect, &mut ignored) } == 0 {
            return Err(map_err(InternalVTableHookError::ProtectFailed(
                std::io::Error::last_os_error(),
            ))
            .into());
        }

        Ok(())
    }
}

impl Drop for VTableHook {
    fn drop(&mut self) {
        if self.active {
            let _ = self.perform_unhook();
        }
    }
}

/// Installed per-instance VTable hook guard.
///
/// This clones the object's VTable, patches the selected slot in the clone,
/// and then redirects the object to the cloned VTable. Only that object is
/// affected.
#[derive(Debug)]
pub struct VTableInstanceHook {
    object_vptr: *mut *mut u8,
    original_vtable: *mut u8,
    cloned_vtable: *mut u8,
    vtable_len: usize,
    original_ptr: *mut u8,
    active: bool,
    enabled: bool,
}

impl VTableInstanceHook {
    /// Hooks a single object's VTable by cloning the table, patching the clone,
    /// and redirecting the object's vptr to the cloned table.
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
    /// invalid or the selected slot is out of range.
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

        let original_vtable = unsafe { *object_vptr };
        if original_vtable.is_null() {
            return Err(map_err(InternalVTableHookError::NullVTable));
        }

        let original_vtable_ptr = original_vtable as *const *mut u8;

        let layout = Layout::array::<*mut u8>(vtable_len)
            .map_err(|_| map_err(InternalVTableHookError::AllocationFailed))?;

        let cloned_vtable = unsafe { alloc(layout) };
        if cloned_vtable.is_null() {
            return Err(map_err(InternalVTableHookError::AllocationFailed));
        }

        unsafe {
            std::ptr::copy_nonoverlapping(
                original_vtable_ptr,
                cloned_vtable as *mut *mut u8,
                vtable_len,
            );
        }

        let slot = unsafe { (cloned_vtable as *mut *mut u8).add(index) };
        let original_ptr = unsafe { *slot };
        unsafe {
            *slot = detour as *mut u8;
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
            unsafe {
                dealloc(cloned_vtable.cast(), layout);
            }
            return Err(map_err(InternalVTableHookError::ProtectFailed(
                std::io::Error::last_os_error(),
            )));
        }

        unsafe {
            *object_vptr = cloned_vtable;
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
            let restore_err = std::io::Error::last_os_error();
            unsafe {
                *object_vptr = original_vtable;
                dealloc(cloned_vtable.cast(), layout);
            }
            return Err(map_err(InternalVTableHookError::ProtectFailed(restore_err)));
        }

        Ok(Self {
            object_vptr,
            original_vtable,
            cloned_vtable,
            vtable_len,
            original_ptr,
            active: true,
            enabled: true,
        })
    }

    /// Returns the original function pointer that was stored in the patched slot.
    pub fn original_ptr(&self) -> *const u8 {
        self.original_ptr
    }

    /// Returns whether the object currently dispatches through the cloned
    /// (hooked) VTable.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Points the object back at its original VTable while keeping the cloned
    /// table allocated, so the hook can be re-enabled later.
    pub fn disable(&mut self) -> Result<(), DetourError> {
        if !self.enabled {
            return Ok(());
        }
        if self.object_vptr.is_null() || self.original_vtable.is_null() {
            return Err(map_err(InternalVTableHookError::NullObject).into());
        }
        Self::write_vptr(self.object_vptr, self.original_vtable)?;
        self.enabled = false;
        Ok(())
    }

    /// Re-points the object at the cloned VTable after a [`Self::disable`].
    pub fn enable(&mut self) -> Result<(), DetourError> {
        if self.enabled {
            return Ok(());
        }
        if self.object_vptr.is_null() || self.cloned_vtable.is_null() {
            return Err(map_err(InternalVTableHookError::NullObject).into());
        }
        Self::write_vptr(self.object_vptr, self.cloned_vtable)?;
        self.enabled = true;
        Ok(())
    }

    /// Writes `value` into the object's vptr field, flipping page protection
    /// around the write.
    fn write_vptr(object_vptr: *mut *mut u8, value: *mut u8) -> Result<(), DetourError> {
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
            return Err(map_err(InternalVTableHookError::ProtectFailed(
                std::io::Error::last_os_error(),
            ))
            .into());
        }

        Ok(())
    }

    /// Unhooks the instance hook by restoring the original VTable pointer and
    /// releasing the cloned VTable memory.
    pub fn unhook(mut self) -> Result<(), DetourError> {
        self.perform_unhook()?;
        self.active = false;
        Ok(())
    }

    fn perform_unhook(&mut self) -> Result<(), DetourError> {
        if self.object_vptr.is_null()
            || self.original_vtable.is_null()
            || self.cloned_vtable.is_null()
            || self.vtable_len == 0
        {
            return Err(map_err(InternalVTableHookError::NullObject).into());
        }

        // Restore the object's original VTable pointer (idempotent if the hook
        // was already disabled).
        Self::write_vptr(self.object_vptr, self.original_vtable)?;

        let layout =
            Layout::array::<*mut u8>(self.vtable_len).map_err(|_| DetourError::InvalidParameter)?;
        unsafe {
            dealloc(self.cloned_vtable.cast(), layout);
        }
        // Clear the pointer immediately so a subsequent `Drop` (e.g. if the
        // guard is still active) cannot free the same allocation twice.
        self.cloned_vtable = std::ptr::null_mut();

        Ok(())
    }
}

impl Drop for VTableInstanceHook {
    fn drop(&mut self) {
        if self.active {
            let _ = self.perform_unhook();
        }
    }
}
