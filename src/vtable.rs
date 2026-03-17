// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt;
use windows_sys::Win32::System::Memory::{PAGE_READWRITE, VirtualProtect};

#[derive(Debug)]
enum InternalVTableHookError {
    NullVTable,
    NullDetour,
    ProtectFailed(std::io::Error),
}

#[derive(Debug)]
pub enum VTableHookError {
    /// One or more pointers/arguments were invalid.
    InvalidParameter,
    /// Changing page protection for the VTable slot failed.
    ProtectFailed(std::io::Error),
}

impl fmt::Display for VTableHookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameter => write!(f, "invalid VTable hook parameters"),
            Self::ProtectFailed(e) => write!(f, "failed to change page protection: {e}"),
        }
    }
}

impl From<InternalVTableHookError> for VTableHookError {
    fn from(err: InternalVTableHookError) -> Self {
        match err {
            InternalVTableHookError::NullVTable | InternalVTableHookError::NullDetour => {
                Self::InvalidParameter
            }
            InternalVTableHookError::ProtectFailed(e) => Self::ProtectFailed(e),
        }
    }
}

#[inline]
fn map_err(err: InternalVTableHookError) -> VTableHookError {
    err.into()
}

pub struct VTableHook;

impl VTableHook {
    /// Hooks a single VTable slot and returns the original function pointer.
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
    pub unsafe fn hook_entry(
        vtable: *mut *mut u8,
        index: usize,
        detour: *const u8,
    ) -> Result<*mut u8, VTableHookError> {
        if vtable.is_null() {
            return Err(map_err(InternalVTableHookError::NullVTable));
        }
        if detour.is_null() {
            return Err(map_err(InternalVTableHookError::NullDetour));
        }

        let slot = unsafe { vtable.add(index) };
        let slot_size = std::mem::size_of::<*mut u8>();

        // Save the original slot value so callers can forward or restore later.
        let original_ptr = unsafe { *slot };

        let mut old_protect = 0u32;
        let success = unsafe {
            VirtualProtect(
                slot.cast(),
                slot_size,
                PAGE_READWRITE,
                &mut old_protect,
            )
        };

        if success == 0 {
            return Err(map_err(InternalVTableHookError::ProtectFailed(
                std::io::Error::last_os_error(),
            )));
        }

        unsafe {
            // Install detour into the selected virtual dispatch slot.
            *slot = detour as *mut u8;
        }

        let mut ignored = 0u32;
        let restored = unsafe { VirtualProtect(slot.cast(), slot_size, old_protect, &mut ignored) };
        if restored == 0 {
            let protect_err = std::io::Error::last_os_error();
            unsafe {
                // Revert the slot if protection restore fails after patching.
                *slot = original_ptr;
            }
            let _ = unsafe { VirtualProtect(slot.cast(), slot_size, old_protect, &mut ignored) };

            return Err(map_err(InternalVTableHookError::ProtectFailed(protect_err)));
        }

        Ok(original_ptr)
    }
}
