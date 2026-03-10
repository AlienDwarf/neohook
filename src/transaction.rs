use crate::DetourError;
use crate::alloc::{Trampoline, TrampolineAlloc};
use crate::disasm;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Threading::*;

/// Main struct to manage a detour transaction, which can include multiple hooks
/// - `Relative5` is a 5-byte relative jump `E9 xx xx xx xx` that can be used when the detour target is within +/- 2GB of the hook site.
/// - `Absolute14` is a 14-byte absolute jump `FF 25 00 00 00 00 [8-byte address]` that can be used when the detour target is further than +/- 2GB away from the hook site __(x64 only)__.
#[derive(Clone, Copy, Debug)]
pub enum JumpType {
    Relative5,
    Absolute14,
}

/// Struct to hold data for an inline hook, which includes the target function address,
/// the detour function address, the trampoline address,
/// the length of given bytes, the type of jump to use, and the original bytes that were overwritten.
pub struct HookData {
    pub target: *mut u8,
    pub detour: *const u8,
    pub trampoline: Trampoline,
    pub stolen_len: usize,
    pub jump_type: JumpType,
    pub orig_bytes: Vec<u8>,
}

/// Enum, used internally in DetourTransaction, to represent either
/// an inline hook or an IAT hook that is pending to be committed.
pub enum PendingHook {
    Inline(HookData),
    Iat {
        module: HMODULE,
        target_dll: String,
        target_func: String,
        detour: *const u8,
        orig_out: *mut *mut u8,
    },
}

/// Enum to represent an installed detour, which can be either an inline hook or an IAT hook.
#[derive(Debug)]
pub enum Detour {
    Inline(InstalledHook),
    Iat(IatDetour),
}

impl Detour {
    /// Returns the original function pointer for this detour, which can be used to call the original function.
    /// For an inline hook, this is the pointer to the trampoline. For an IAT hook, this is the original function pointer stored in the IAT.
    pub fn original_ptr(&self) -> *const u8 {
        match self {
            Detour::Inline(h) => h.original_ptr(),
            Detour::Iat(h) => h.original_ptr,
        }
    }

    /// Unhooks this detour restoring the original bytes or original ptr
    pub fn unhook(self) -> Result<(), DetourError> {
        match self {
            Detour::Inline(h) => h.unhook(),
            Detour::Iat(h) => h.unhook(),
        }
    }
}

/// Helper struct to manage the allocation of trampolines, which are used for inline hooks.
#[derive(Debug)]
pub struct InstalledHook {
    pub target: *mut u8,
    pub trampoline: Trampoline,
    pub stolen_len: usize,
    pub orig_bytes: Vec<u8>,
    pub jump_type: JumpType,
}

impl InstalledHook {
    /// Returns the original function pointer for this inline hook, which is the address of the trampoline.
    pub fn original_ptr(&self) -> *const u8 {
        // .ptr is  *mut u8, we cast to *const u8
        self.trampoline.ptr as *const u8
    }

    /// Unhooks this inline hook by restoring the original bytes at the target address.
    pub fn unhook(self) -> Result<(), DetourError> {
        unsafe {
            let mut old = 0u32;
            // Get current protection and add execute permissions
            crate::mem::virtual_protect_same_execute(
                self.target,
                self.stolen_len,
                windows_sys::Win32::System::Memory::PAGE_READWRITE,
                &mut old,
            );

            // copy the original bytes back to the target function
            std::ptr::copy_nonoverlapping(self.orig_bytes.as_ptr(), self.target, self.stolen_len);

            // CPU-Cache flush so CPU has to read from RAM not from L1 L2 L3 cache
            windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache(
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                self.target as _,
                self.stolen_len,
            );

            // Restore original protection
            windows_sys::Win32::System::Memory::VirtualProtect(
                self.target as _,
                self.stolen_len,
                old,
                &mut old,
            );
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct IatDetour {
    pub module: HMODULE,
    pub dll_name: String,
    pub func_name: String,
    pub original_ptr: *mut u8,
}

impl IatDetour {
    pub fn unhook(&self) -> Result<(), DetourError> {
        unsafe {
            crate::iat::IatHook::hook_import(
                self.module,
                &self.dll_name,
                &self.func_name,
                self.original_ptr,
            )
            .ok_or(DetourError::InvalidParameter)?;
            Ok(())
        }
    }
}

impl Drop for IatDetour {
    fn drop(&mut self) {
        // Auto-unhook when dropped, best effort, ignore errors
        let _ = self.unhook();
    }
}

pub struct DetourTransaction {
    threads: Vec<HANDLE>,
    pending_hooks: Vec<PendingHook>,
    is_pending: bool,
}

impl DetourTransaction {
    pub fn begin() -> Self {
        Self {
            threads: Vec::new(),
            pending_hooks: Vec::new(),
            is_pending: true,
        }
    }

    pub fn update_thread(&mut self, h_thread: HANDLE) -> Result<(), DetourError> {
        if !self.is_pending {
            return Err(DetourError::NotStarted);
        }
        self.threads.push(h_thread);
        Ok(())
    }

    pub fn update_all_threads(&mut self) {
        let items = crate::threads::ThreadEnumerator::enumerate_process_threads();
        let threads = items;
        for h in threads {
            self.threads.push(h);
        }
    }

    pub fn attach(&mut self, target: *mut u8, detour: *const u8) -> Result<*mut u8, DetourError> {
        if !self.is_pending {
            return Err(DetourError::NotStarted);
        }

        // --- architecture ---

        // case A: 64-Bit (x86_64)
        // We check if the target is < 2GB away (Relative5) or further (Absolute14).
        #[cfg(target_arch = "x86_64")]
        let (jump_type, required_space) = {
            let rel = (detour as i64) - (target as i64) - 5;
            if (i32::MIN as i64..=i32::MAX as i64).contains(&rel) {
                (JumpType::Relative5, 5)
            } else {
                (JumpType::Absolute14, 14)
            }
        };

        // case B: 32-Bit (x86)
        // We can directly set the jump type to Relative5 for x86, because the address space is limited to 4GB.
        #[cfg(target_arch = "x86")]
        let (jump_type, required_space) = (JumpType::Relative5, 5);

        // ------------------------------------------

        let stolen_len = unsafe {
            disasm::Disassembler::get_instruction_len(target, required_space)
                .map_err(|_| DetourError::InvalidParameter)
        }?;

        // Allocate memory. rwx is required for the trampoline, we switch to rx later
        let tramp_capacity = 64usize;
        let trampoline_handle = unsafe {
            TrampolineAlloc::alloc_nearby_trampoline(target, 64)
                .ok_or(DetourError::AllocationFailed)?
        };
        let trampoline = trampoline_handle.ptr;

        // Relocation
        let tramp_len = unsafe {
            disasm::Disassembler::relocate(target, trampoline, stolen_len)
                .map_err(|_| DetourError::RelocationFailed)
        }?;

        if tramp_len > tramp_capacity {
            return Err(DetourError::RelocationFailed);
        }

        // Switch to RX via helper
        let _ = trampoline_handle.make_rx();
        // ---------------------------------

        let data = HookData {
            target,
            detour,
            trampoline: trampoline_handle,
            stolen_len,
            jump_type,
            orig_bytes: unsafe {
                std::slice::from_raw_parts(target as *const u8, stolen_len).to_vec()
            },
        };

        self.pending_hooks.push(PendingHook::Inline(data));
        Ok(trampoline)
    }

    pub fn attach_iat(
        &mut self,
        h_module: HMODULE,
        target_dll: &str,
        target_func: &str,
        detour: *const u8,
        orig_out: *mut *mut u8,
    ) -> Result<(), DetourError> {
        if !self.is_pending {
            return Err(DetourError::NotStarted);
        }
        self.pending_hooks.push(PendingHook::Iat {
            module: h_module,
            target_dll: target_dll.to_string(),
            target_func: target_func.to_string(),
            detour,
            orig_out,
        });
        Ok(())
    }

    pub fn commit(&mut self) -> Result<Vec<Detour>, DetourError> {
        if !self.is_pending {
            return Err(DetourError::NotStarted);
        }

        // Suspend threads
        for &h_thread in &self.threads {
            unsafe { SuspendThread(h_thread) };
        }

        let pending = std::mem::take(&mut self.pending_hooks);
        let mut installed: Vec<Detour> = Vec::new();

        // Apply hooks
        for hook in pending {
            match hook {
                PendingHook::Inline(data) => match self.apply_inline_hook(data) {
                    Ok(inst) => installed.push(Detour::Inline(inst)),
                    Err(e) => {
                        self.rollback(&mut installed);
                        self.cleanup_threads();
                        return Err(e);
                    }
                },
                PendingHook::Iat {
                    module,
                    target_dll,
                    target_func,
                    detour,
                    orig_out,
                } => {
                    unsafe {
                        if let Some(original) = crate::iat::IatHook::hook_import(
                            module,
                            &target_dll,
                            &target_func,
                            detour,
                        ) {
                            if !orig_out.is_null() {
                                *orig_out = original;
                            }
                            // We push the IAT detour to the installed list so it can be unhooked later if needed. The original pointer is stored in the IatDetour struct.
                            installed.push(Detour::Iat(IatDetour {
                                module,
                                dll_name: target_dll,
                                func_name: target_func,
                                original_ptr: original,
                            }));
                        } else {
                            self.rollback(&mut installed);
                            self.cleanup_threads();
                            return Err(DetourError::InvalidParameter);
                        }
                    }
                }
            }
        }

        // CPU Cache flush after all hooks installed
        unsafe {
            windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache(
                GetCurrentProcess(),
                std::ptr::null(),
                0,
            );
        }

        // resume threads
        self.cleanup_threads();
        self.is_pending = false;
        Ok(installed)
    }

    pub fn abort(&mut self) {
        if !self.is_pending {
            return;
        }
        self.pending_hooks.clear();
        self.cleanup_threads();
        self.is_pending = false;
    }

    /// Rollback function to undo all installed hooks in case of an error during commit. It takes a mutable reference to the list of installed hooks and unhooks each one.
    fn rollback(&self, installed: &mut Vec<Detour>) {
        for detour in installed.drain(..) {
            match detour {
                Detour::Inline(hook) => unsafe {
                    crate::mem::write_memory_atomic(
                        hook.target,
                        hook.orig_bytes.as_ptr(),
                        hook.stolen_len,
                    );
                },
                Detour::Iat(hook) => {
                    let _ = hook.unhook();
                }
            }
        }
    }

    fn cleanup_threads(&mut self) {
        for &h in &self.threads {
            unsafe {
                ResumeThread(h);
                CloseHandle(h);
            }
        }
        self.threads.clear();
    }

    // Apply an inline hook, returning an InstalledHook on success.
    fn apply_inline_hook(&mut self, data: HookData) -> Result<InstalledHook, DetourError> {
        unsafe {
            let target = data.target;
            let dest = data.detour;

            // We prepare the jump instruction in a buffer. For Relative5, it's 5 bytes: E9 + 4-byte offset. For Absolute14, it's 14 bytes: FF 25 00 00 00 00 + 8-byte absolute address.
            let mut patch_buffer = [0u8; 14];
            let patch_len: usize;

            match data.jump_type {
                JumpType::Relative5 => {
                    let offset = (dest as isize)
                        .wrapping_sub(target as isize)
                        .wrapping_sub(5);

                    debug_assert!(
                        (i32::MIN as isize..=i32::MAX as isize).contains(&offset),
                        "Offset for relative jump does not fit in 32 bits"
                    );

                    patch_buffer[0] = 0xE9;
                    // We write the offset as a little-endian 4-byte value starting at patch_buffer[1]
                    patch_buffer[1..5].copy_from_slice(&(offset as i32).to_le_bytes());
                    patch_len = 5;
                }
                JumpType::Absolute14 => {
                    #[cfg(target_arch = "x86_64")]
                    {
                        patch_buffer[0..6].copy_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
                        patch_buffer[6..14].copy_from_slice(&(dest as u64).to_le_bytes());
                        patch_len = 14;
                    }
                    #[cfg(target_arch = "x86")]
                    {
                        // Absolute jumps are not supported on x86, we should never reach this case because attach() should have returned an error if the target was too far away. We put this here just for completeness, but it should never be used.
                        return Err(DetourError::InvalidParameter);
                    }
                }
            };

            // we write atomic to ensure a thread-safe patching. If something fails we return an error
            if crate::mem::write_memory_atomic(target, patch_buffer.as_ptr(), patch_len).is_some() {
                Ok(InstalledHook {
                    target: data.target,
                    trampoline: data.trampoline,
                    stolen_len: data.stolen_len,
                    orig_bytes: data.orig_bytes,
                    jump_type: data.jump_type,
                })
            } else {
                // If the write fails, we return an error. The commit() function will catch this and call rollback() to undo any hooks that were already installed.
                Err(DetourError::RelocationFailed)
            }
        }
    }
}

impl Drop for DetourTransaction {
    fn drop(&mut self) {
        // If the transaction is still pending when the DetourTransaction struct is dropped, we call abort() to clean up any pending hook
        if self.is_pending {
            self.abort();
        }
    }
}
