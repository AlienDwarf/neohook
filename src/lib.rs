// This is a new rust library project.
// NeoHook is a modern hooking library for Windows, designed to be fast, safe, and easy to use.
// It provides a simple and efficient way to hook functions in Windows applications, allowing developers to modify behavior, intercept calls, and implement custom logic without modifying the original code.

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

pub mod alloc;
pub mod disasm;
pub mod iat;
pub mod mem;
pub mod module;
pub mod threads;
pub mod api;

/// Errors that can occur during the detouring process
/// - `NotStarted`: The transaction has not been started or has already been committed/aborted.
/// - `AllocationFailed`: Memory allocation for the trampoline failed.
/// - `RelocationFailed`: Relocating the original instructions to the trampoline failed.
/// - `InvalidParameter`: An invalid parameter was provided to a function, such as a null pointer or an invalid module handle.
#[derive(Debug)]
pub enum DetourError {
    NotStarted,
    AllocationFailed,
    RelocationFailed,
    InvalidParameter,
}

#[derive(Clone, Copy)]
pub enum JumpType {
    Relative5,
    Absolute14,
}

/// Struct to hold data for an inline hook, which includes the target function address,
/// the detour function address, the trampoline address,
/// the length of stolen bytes, and the type of jump to use.
pub struct HookData {
    pub target: *mut u8,
    pub detour: *const u8,
    pub trampoline: *mut u8,
    pub stolen_len: usize,
    pub jump_type: JumpType,
}

/// Enum, used internally in DetourTransaction, to represent either
/// an inline hook or an IAT hook that is pending to be committed.
enum PendingHook {
    Inline(HookData),
    Iat {
        module: HMODULE,
        target_dll: String,
        target_func: String,
        detour: *const u8,
        orig_out: *mut *mut u8,
    },
}

/// Main struct to manage a detour transaction, which can include multiple hooks
/// and thread updates.
pub struct DetourTransaction {
    threads: Vec<HANDLE>,
    pending_hooks: Vec<PendingHook>,
    is_pending: bool,
}

// TODO: Better commenting for the function. Cleaner code in general, maybe split into multiple chunks
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
        let threads = unsafe { crate::threads::ThreadEnumerator::enumerate_process_threads() };
        for h in threads {
            self.threads.push(h);
        }
    }

    pub fn attach(&mut self, target: *mut u8, detour: *const u8) -> Result<*mut u8, DetourError> {
        if !self.is_pending {
            return Err(DetourError::NotStarted);
        }

        let diff = (detour as isize).wrapping_sub(target as isize).abs();
        let (jump_type, required_space) = if diff < 0x7FFF_FFFF {
            (JumpType::Relative5, 5)
        } else {
            (JumpType::Absolute14, 14)
        };

        let stolen_len = unsafe {
            disasm::Disassembler::get_instruction_len(target, required_space)
                .map_err(|_| DetourError::InvalidParameter)
        }?;

        let trampoline = unsafe {
            alloc::TrampolineAlloc::alloc_nearby(target, 64).ok_or(DetourError::AllocationFailed)?
        };

        (unsafe {
            disasm::Disassembler::relocate(target, trampoline, stolen_len)
                .map_err(|_| DetourError::RelocationFailed)
        })?;

        let data = HookData {
            target,
            detour,
            trampoline,
            stolen_len,
            jump_type,
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

    pub fn commit(&mut self) -> Result<(), DetourError> {
        if !self.is_pending {
            return Err(DetourError::NotStarted);
        }

        // pause threads before applying hooks to avoid race conditions
        for &h_thread in &self.threads {
            unsafe { SuspendThread(h_thread) };
        }

        for hook in &self.pending_hooks {
            match hook {
                PendingHook::Inline(data) => unsafe {
                    match data.jump_type {
                        JumpType::Relative5 => self.write_relative_jump(data.target, data.detour),
                        JumpType::Absolute14 => self.write_absolute_jump(data.target, data.detour),
                    }
                },
                PendingHook::Iat {
                    module,
                    target_dll,
                    target_func,
                    detour,
                    orig_out,
                } => unsafe {
                    if let Some(original) =
                        iat::IatHook::hook_import(*module, target_dll, target_func, *detour)
                    {
                        if !orig_out.is_null() {
                            // Saves the original function pointer to the provided output location, so the caller can call the original function if needed.

                            *(*orig_out) = original;
                        } else {
                            return Err(DetourError::InvalidParameter);
                        }
                    }
                },
            }
        }

        for &h_thread in &self.threads {
            unsafe { ResumeThread(h_thread) };
        }

        self.is_pending = false;
        Ok(())
    }

    pub fn abort(&mut self) {
        self.pending_hooks.clear();
        self.threads.clear();
        self.is_pending = false;
    }

    unsafe fn write_absolute_jump(&self, target: *mut u8, destination: *const u8) {
        let mut patch = [0u8; 14];
        patch[0..6].copy_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
        patch[6..14].copy_from_slice(&(destination as u64).to_le_bytes());

        let mut old_protect = 0;
        unsafe {
            // We need to change the protection of the memory page containing the target address to allow writing, then write the patch, and restore the original protection. Finally, we flush the instruction cache to ensure that the CPU sees the updated instructions.
            mem::virtual_protect_same_execute(target, 14, PAGE_EXECUTE_READWRITE, &mut old_protect);
            std::ptr::copy_nonoverlapping(patch.as_ptr(), target, 14);
            VirtualProtect(target as _, 14, old_protect, &mut old_protect);
            FlushInstructionCache(GetCurrentProcess(), target as _, 14);
        }
    }

    unsafe fn write_relative_jump(&self, target: *mut u8, destination: *const u8) {
        let offset = (destination as isize)
            .wrapping_sub(target as isize)
            .wrapping_sub(5);

        let mut patch = [0u8; 5];
        patch[0] = 0xE9;
        patch[1..5].copy_from_slice(&(offset as i32).to_le_bytes());

        let mut old_protect = 0;
        unsafe {
            mem::virtual_protect_same_execute(target, 5, PAGE_EXECUTE_READWRITE, &mut old_protect);
            std::ptr::copy_nonoverlapping(patch.as_ptr(), target, 5);
            VirtualProtect(target as _, 5, old_protect, &mut old_protect);
            FlushInstructionCache(GetCurrentProcess(), target as _, 5);
        }
    }
}
