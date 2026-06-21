// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Export Address Table (EAT)
//!
//! Where [`crate::iat`] rewrites a *caller's* Import Address Table so a single
//! module sees a redirected import, EAT hooking rewrites the *target* module's
//! Export Address Table. Every consumer that resolves the export *AFTER* the
//! hook is installed (for example through `GetProcAddress` or by walking the
//! EAT itself) is redirected to the detour. Code that already cached the
//! resolved address keeps calling the original function, exactly like IAT
//! hooking, because only the lookup table is changed - not the function body.
//!
//! ## How the redirect is encoded
//!
//! Each EAT slot is a 32-bit Relative Virtual Address (`AddressOfFunctions[i]`)
//! resolved as `module_base + rva`. To point a slot at a detour we therefore
//! need `detour - module_base` to fit in a `u32`:
//!
//! * On **x86** every address is 32-bit, so `(detour as u32) - (base as u32)`
//!   always round-trips and no extra memory is needed.
//! * On **x86_64** the detour frequently lives more than 4 GB away from the
//!   target module. When the difference does not fit in a `u32`, NeoHook
//!   allocates a tiny jump stub within 2 GB *above* the module base and points
//!   the EAT slot at the stub, which performs an absolute jump to the detour.
//!   The stub is owned by the installed hook and released when it is unhooked.
//!
//! All PE parsing is bounds-checked through [`crate::pe`].

use std::fmt;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Memory::{PAGE_READWRITE, VirtualProtect};
use windows_sys::Win32::System::SystemServices::*;

use crate::pe::{self, ModuleImage, PeError};

#[cfg(target_arch = "x86_64")]
use crate::alloc::{Trampoline, TrampolineAlloc};

// On x86 the stub branch is never taken, but the field type below is shared
// across both targets, so the type still has to be in scope there.
#[cfg(target_arch = "x86")]
use crate::alloc::Trampoline;

/// Errors produced while installing or resolving an EAT hook.
#[derive(Debug)]
pub enum EatHookError {
    /// A null pointer or otherwise unusable argument was supplied.
    InvalidParameter,
    /// The module headers could not be parsed as a valid PE image.
    InvalidPeImage,
    /// The module has no export directory, or it is malformed.
    ExportTableUnavailable,
    /// The requested export name was not found in the module.
    TargetNotFound,
    /// The requested export is a forwarder (`"OTHERDLL.Function"`) rather than
    /// real code in this module, so its EAT slot cannot be redirected.
    TargetIsForwarder,
    /// The detour is too far from the module base to encode as a 32-bit RVA and
    /// no jump stub could be placed within range (x86_64 only).
    DetourUnreachable,
    /// A jump stub for an out-of-range detour could not be allocated.
    AllocationFailed,
    /// Changing page protection on the EAT slot failed.
    ProtectFailed(std::io::Error),
}

impl fmt::Display for EatHookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameter => write!(f, "invalid EAT hook parameters"),
            Self::InvalidPeImage => write!(f, "invalid PE image"),
            Self::ExportTableUnavailable => write!(f, "export table unavailable"),
            Self::TargetNotFound => write!(f, "target export not found"),
            Self::TargetIsForwarder => write!(f, "target export is a forwarder, not code"),
            Self::DetourUnreachable => {
                write!(f, "detour is unreachable as a 32-bit export RVA")
            }
            Self::AllocationFailed => write!(f, "failed to allocate jump stub for detour"),
            Self::ProtectFailed(e) => write!(f, "failed to change page protection: {e}"),
        }
    }
}

impl std::error::Error for EatHookError {}

impl From<PeError> for EatHookError {
    fn from(err: PeError) -> Self {
        match err {
            PeError::NullModule => Self::InvalidParameter,
            PeError::InvalidDosHeader
            | PeError::InvalidNtHeader
            | PeError::InvalidNtSignature
            | PeError::InvalidOptionalHeader => Self::InvalidPeImage,
        }
    }
}

/// The result of installing an EAT hook at a single export slot.
///
/// This is the low-level payload returned by [`EatHook::hook_export`]; the
/// transaction layer wraps it into a `Hook` guard that restores the slot and
/// releases the stub on drop.
pub(crate) struct InstalledEat {
    /// Pointer to the `AddressOfFunctions[index]` RVA entry that was patched.
    pub slot_ptr: *mut u32,
    /// RVA that was stored in the slot before patching.
    pub original_rva: u32,
    /// RVA written into the slot to redirect to the detour (or its stub).
    pub detour_rva: u32,
    /// Resolved address of the original export (`base + original_rva`).
    pub original_ptr: *mut u8,
    /// Jump stub keeping an out-of-range x86_64 detour reachable. `None` when
    /// the detour was encoded directly. Freed when the hook is dropped.
    pub stub: Option<Trampoline>,
}

/// Namespace type for the low-level EAT hooking primitives.
///
/// Mirrors [`crate::iat::IatHook`]: the methods are stateless and operate on a
/// loaded module's export directory.
pub struct EatHook;

impl EatHook {
    /// Installs an EAT hook for `target_func`, redirecting its export slot to
    /// `detour`.
    ///
    /// On success the export's RVA slot points at the detour (directly, or via
    /// an allocated jump stub on x86_64) and an [`InstalledEat`] describing how
    /// to restore it is returned.
    ///
    /// # Safety
    ///
    /// - `h_module` must be the base address of a valid PE module loaded in the
    ///   current process and must remain loaded for the lifetime of the hook.
    /// - `detour` must be a valid function pointer with an ABI/signature
    ///   compatible with the hooked export.
    pub unsafe fn hook_export(
        h_module: windows_sys::Win32::Foundation::HMODULE,
        target_func: &str,
        detour: *const u8,
    ) -> Result<InstalledEat, EatHookError> {
        if h_module.is_null() {
            return Err(EatHookError::InvalidParameter);
        }
        if detour.is_null() {
            return Err(EatHookError::InvalidParameter);
        }

        let image = pe::parse_module_image(h_module)?;
        let (slot_ptr, original_rva) = unsafe { find_export_slot(&image, target_func)? };

        // Resolve the detour to an RVA, building a near jump stub if it cannot
        // be encoded directly. The stub (if any) is owned by the returned value.
        let (detour_rva, stub) = unsafe { resolve_detour_rva(image.base_address, detour)? };

        unsafe { write_export_slot(slot_ptr, detour_rva)? };

        Ok(InstalledEat {
            slot_ptr,
            original_rva,
            detour_rva,
            original_ptr: (image.base_address + original_rva as usize) as *mut u8,
            stub,
        })
    }

    /// Validates that `target_func` is a hookable (non-forwarder) export and
    /// returns a pointer to its EAT slot without modifying anything.
    ///
    /// Used by the transaction layer to fail early, before any thread is
    /// suspended, when the requested export cannot be hooked.
    ///
    /// # Safety
    ///
    /// `h_module` must be the base address of a valid PE module loaded in the
    /// current process.
    pub unsafe fn find_export_address(
        h_module: windows_sys::Win32::Foundation::HMODULE,
        target_func: &str,
    ) -> Result<*mut u32, EatHookError> {
        let image = pe::parse_module_image(h_module)?;
        let (slot_ptr, _original_rva) = unsafe { find_export_slot(&image, target_func)? };
        Ok(slot_ptr)
    }

    /// Writes `rva` into a previously located EAT slot, flipping page protection
    /// around the write.
    ///
    /// Used to toggle a hook between its detour and original RVA
    /// (enable/disable) and to restore it on unhook.
    ///
    /// # Safety
    ///
    /// `slot_ptr` must point at a valid `AddressOfFunctions` entry inside a
    /// module that is still loaded.
    pub unsafe fn write_export_rva(slot_ptr: *mut u32, rva: u32) -> Result<(), EatHookError> {
        unsafe { write_export_slot(slot_ptr, rva) }
    }
}

/// Locates the EAT slot (`&AddressOfFunctions[index]`) for the named export and
/// returns `(slot_ptr, original_rva)`.
///
/// Rejects forwarder exports, whose RVA points back into the export directory
/// at a `"OTHERDLL.Function"` string rather than at code.
unsafe fn find_export_slot(
    image: &ModuleImage,
    target_func: &str,
) -> Result<(*mut u32, u32), EatHookError> {
    let (exp_rva, exp_size) = pe::data_directory(image, IMAGE_DIRECTORY_ENTRY_EXPORT as usize)
        .ok_or(EatHookError::ExportTableUnavailable)?;

    let dir_ptr = pe::rva_to_ptr::<IMAGE_EXPORT_DIRECTORY>(image, exp_rva)
        .ok_or(EatHookError::ExportTableUnavailable)?;
    let dir = unsafe { *dir_ptr };

    let number_of_functions = dir.NumberOfFunctions as usize;
    let number_of_names = dir.NumberOfNames as usize;
    let functions_rva = dir.AddressOfFunctions as usize;
    let names_rva = dir.AddressOfNames as usize;
    let name_ordinals_rva = dir.AddressOfNameOrdinals as usize;

    let exp_end = exp_rva.saturating_add(exp_size);

    // Walk the parallel AddressOfNames / AddressOfNameOrdinals arrays looking for
    // the requested name. The name ordinal is the index into AddressOfFunctions.
    for i in 0..number_of_names {
        let Some(name_rva) = read_u32(image, names_rva, i) else {
            continue;
        };
        let Some(name) = pe::read_c_string_from_rva(image, name_rva as usize) else {
            continue;
        };
        if name != target_func {
            continue;
        }

        let Some(func_index) = read_u16(image, name_ordinals_rva, i) else {
            return Err(EatHookError::ExportTableUnavailable);
        };
        let func_index = func_index as usize;
        if func_index >= number_of_functions {
            return Err(EatHookError::ExportTableUnavailable);
        }

        let slot_rva = functions_rva
            .checked_add(
                func_index
                    .checked_mul(std::mem::size_of::<u32>())
                    .ok_or(EatHookError::ExportTableUnavailable)?,
            )
            .ok_or(EatHookError::ExportTableUnavailable)?;

        let slot_ptr = pe::rva_to_mut_ptr::<u32>(image, slot_rva)
            .ok_or(EatHookError::ExportTableUnavailable)?;
        let original_rva = unsafe { *slot_ptr };

        // An RVA pointing back inside the export directory is a forwarder string,
        // not code, and must not be redirected.
        if (original_rva as usize) >= exp_rva && (original_rva as usize) < exp_end {
            return Err(EatHookError::TargetIsForwarder);
        }

        return Ok((slot_ptr, original_rva));
    }

    Err(EatHookError::TargetNotFound)
}

/// Resolves `detour` to an export RVA relative to `base`.
///
/// Returns the RVA plus an optional jump stub that must outlive the hook. On
/// x86 the difference always fits in a `u32`; on x86_64 a stub is built when it
/// does not.
unsafe fn resolve_detour_rva(
    base: usize,
    detour: *const u8,
) -> Result<(u32, Option<Trampoline>), EatHookError> {
    #[cfg(target_arch = "x86")]
    {
        // 32-bit address space: wrapping subtraction always round-trips through
        // base + rva, so the detour is directly reachable. Consumers resolve the
        // export and call it indirectly; mark the detour as a valid CFG call
        // target so the redirect holds under strict CFG / export suppression
        // (no-op otherwise, see crate::cfg).
        crate::cfg::register_valid_target(detour);
        let rva = (detour as u32).wrapping_sub(base as u32);
        Ok((rva, None))
    }

    #[cfg(target_arch = "x86_64")]
    {
        let diff = (detour as usize).wrapping_sub(base);
        // Directly encodable when the detour sits above the base within 4 GB.
        // The slot then points straight at the detour, which consumers call
        // indirectly; mark it as a valid CFG call target (no-op unless strict
        // CFG / export suppression is in effect). The out-of-range stub path
        // below is covered by the stub's own `make_rx`.
        if detour as usize >= base && diff <= u32::MAX as usize {
            crate::cfg::register_valid_target(detour);
            return Ok((diff as u32, None));
        }

        // Otherwise place a 14-byte absolute-jump stub above the module base,
        // within 4 GB, so its RVA fits in a u32, and point the slot at the stub.
        const STUB_LEN: usize = 14;
        let stub = unsafe { TrampolineAlloc::alloc_export_stub(base, STUB_LEN) }
            .ok_or(EatHookError::DetourUnreachable)?;

        let stub_addr = stub.ptr as usize;
        unsafe { write_abs_jump_stub(stub.ptr, detour) };
        // Leave the stub executable; `make_rx` tightens it from RWX to RX.
        let _ = stub.make_rx();
        unsafe {
            windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache(
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                stub.ptr as _,
                STUB_LEN,
            );
        }

        let rva = (stub_addr - base) as u32;
        Ok((rva, Some(stub)))
    }
}

/// Writes an absolute `jmp [rip+0]; <dst>` thunk (`FF 25 00 00 00 00` + 8-byte
/// target) into `src`.
#[cfg(target_arch = "x86_64")]
unsafe fn write_abs_jump_stub(src: *mut u8, dst: *const u8) {
    unsafe {
        src.add(0).write(0xFF);
        src.add(1).write(0x25);
        src.add(2).write(0x00);
        src.add(3).write(0x00);
        src.add(4).write(0x00);
        src.add(5).write(0x00);
        std::ptr::copy_nonoverlapping((dst as u64).to_le_bytes().as_ptr(), src.add(6), 8);
    }
}

/// Writes a 32-bit RVA into an EAT slot, flipping the page to writable for the
/// duration of the store.
unsafe fn write_export_slot(slot_ptr: *mut u32, rva: u32) -> Result<(), EatHookError> {
    if slot_ptr.is_null() {
        return Err(EatHookError::InvalidParameter);
    }

    let size = std::mem::size_of::<u32>();
    let mut old_protect = 0u32;
    if unsafe { VirtualProtect(slot_ptr.cast(), size, PAGE_READWRITE, &mut old_protect) } == 0 {
        return Err(EatHookError::ProtectFailed(std::io::Error::last_os_error()));
    }

    unsafe { slot_ptr.write(rva) };

    let mut ignored = 0u32;
    if unsafe { VirtualProtect(slot_ptr.cast(), size, old_protect, &mut ignored) } == 0 {
        return Err(EatHookError::ProtectFailed(std::io::Error::last_os_error()));
    }

    Ok(())
}

/// Reads the `index`-th `u32` of an array located at `base_rva`, bounds-checked.
fn read_u32(image: &ModuleImage, base_rva: usize, index: usize) -> Option<u32> {
    let rva = base_rva.checked_add(index.checked_mul(std::mem::size_of::<u32>())?)?;
    let ptr = pe::rva_to_ptr::<u32>(image, rva)?;
    Some(unsafe { *ptr })
}

/// Reads the `index`-th `u16` of an array located at `base_rva`, bounds-checked.
fn read_u16(image: &ModuleImage, base_rva: usize, index: usize) -> Option<u16> {
    let rva = base_rva.checked_add(index.checked_mul(std::mem::size_of::<u16>())?)?;
    let ptr = pe::rva_to_ptr::<u16>(image, rva)?;
    Some(unsafe { *ptr })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module;

    #[test]
    fn hook_export_rejects_null_module() {
        let err = unsafe {
            EatHook::hook_export(std::ptr::null_mut(), "GetTickCount", dummy as *const u8)
        };
        assert!(matches!(err, Err(EatHookError::InvalidParameter)));
    }

    #[test]
    fn hook_export_rejects_null_detour() {
        let h = module::get_module_handle("kernel32.dll").expect("kernel32 handle");
        let err = unsafe { EatHook::hook_export(h, "GetTickCount", std::ptr::null()) };
        assert!(matches!(err, Err(EatHookError::InvalidParameter)));
    }

    #[test]
    fn find_export_address_rejects_missing_export() {
        let h = module::get_module_handle("kernel32.dll").expect("kernel32 handle");
        let err = unsafe { EatHook::find_export_address(h, "DefinitelyNotARealExport_123") };
        assert!(matches!(err, Err(EatHookError::TargetNotFound)));
    }

    #[test]
    fn find_export_address_resolves_known_export() {
        let h = module::get_module_handle("kernel32.dll").expect("kernel32 handle");
        let slot = unsafe { EatHook::find_export_address(h, "GetProcAddress") }
            .expect("GetProcAddress should be exported by kernel32");
        assert!(!slot.is_null());
    }

    #[test]
    fn find_export_address_rejects_invalid_module() {
        let mut stack_value = 0u32;
        let fake = (&mut stack_value as *mut u32).cast::<core::ffi::c_void>()
            as windows_sys::Win32::Foundation::HMODULE;
        assert!(unsafe { EatHook::find_export_address(fake, "GetProcAddress") }.is_err());
    }

    extern "system" fn dummy() {}
}
