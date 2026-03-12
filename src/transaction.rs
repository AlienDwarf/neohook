// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::DetourError;
use crate::alloc::{Trampoline, TrampolineAlloc};
use crate::disasm;
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::{CONTEXT, GetThreadContext, SetThreadContext};
use windows_sys::Win32::System::Threading::*;

/// The number of usize slots to scan on the stack for return addresses.
/// Default: 512 (corresponds to 4KB / one memory page on x64).
const STACK_SCAN_DEPTH: usize = 512;

#[cfg(target_arch = "x86_64")]
const CONTEXT_FLAGS: u32 = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_ALL_AMD64;

#[cfg(target_arch = "x86")]
const CONTEXT_FLAGS: u32 = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_ALL_X86;

#[cfg(target_arch = "x86_64")]
const MANAGED_GATEWAY_LEN: usize = 14;

#[cfg(target_arch = "x86")]
const MANAGED_GATEWAY_LEN: usize = 5;

/// Main struct to manage a detour transaction, which can include multiple hooks
/// - `Relative5` is a 5-byte relative jump `E9 xx xx xx xx` that can be used when the detour target is within +/- 2GB of the hook site.
/// - `Absolute14` is a 14-byte absolute jump `FF 25 00 00 00 00 [8-byte address]` that can be used when the detour target is further than +/- 2GB away from the hook site __(x64 only)__.
#[derive(Clone, Copy, Debug)]
pub enum JumpType {
    Relative5,
    Absolute14,
}

/// Internal enum to differentiate between normal targets and managed gateways.
/// Managed gateways are special stubs that allow hooking of managed methods and chaining of hooks without the need for disassembly
/// - `Normal` function targets require disassembly to determine the length of stolen bytes and proper relocation, and are used for typical inline hooks
/// - `ManagedGateway` targets are pre-allocated stubs that can be directly overwritte
#[derive(Debug)]
enum TargetKind {
    Normal,
    ManagedGateway,
}

/// Struct to hold data for an inline hook, which includes the target function address,
/// the detour function address, the trampoline address,
/// the length of given bytes, the type of jump to use, and the original bytes that were overwritten.
pub struct InlineData {
    pub target: *mut u8,
    pub detour: *const u8,
    pub trampoline: Trampoline,
    pub redirect_base: *mut u8,
    pub stolen_len: usize,
    pub jump_type: JumpType,
    pub orig_bytes: Vec<u8>,
    target_kind: TargetKind,
}

/// Enum, used internally in DetourTransaction, to represent either
/// an inline hook or an IAT hook that is pending to be committed.
pub enum PendingHook {
    Inline(InlineData),
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
pub enum Hook {
    Inline(InlineHook),
    Iat(IatHook),
}

impl Hook {
    /// Returns the original function pointer for this detour, which can be used to call the original function.
    /// For an inline hook, this is the pointer to the trampoline. For an IAT hook, this is the original function pointer stored in the IAT.
    pub fn original_ptr(&self) -> *const u8 {
        match self {
            Hook::Inline(h) => h.original_ptr(),
            Hook::Iat(h) => h.original_ptr,
        }
    }

    /// Unhooks this detour restoring the original bytes or original ptr
    pub fn unhook(self) -> Result<(), DetourError> {
        match self {
            Hook::Inline(h) => h.unhook(),
            Hook::Iat(h) => h.unhook(),
        }
    }
}

/// Helper struct to manage the allocation of trampolines, which are used for inline hooks.
#[derive(Debug)]
pub struct InlineHook {
    pub target: *mut u8,
    pub trampoline: Trampoline,
    pub stolen_len: usize,
    pub orig_bytes: Vec<u8>,
    pub jump_type: JumpType,
    active: bool,
    target_kind: TargetKind,
}

impl InlineHook {
    /// Returns the original function pointer for this inline hook, which is the address of the trampoline.
    pub fn original_ptr(&self) -> *const u8 {
        // .ptr is  *mut u8, we cast to *const u8
        self.trampoline.ptr as *const u8
    }

    /// Unhooks this inline hook by restoring the original bytes at the target address.
    pub fn unhook(mut self) -> Result<(), DetourError> {
        self.perform_unhook()?;
        unregister_managed_gateway(self.trampoline.ptr);
        self.active = false;

        Ok(())
    }

    fn perform_unhook(&self) -> Result<(), DetourError> {
        // parameter validation
        if self.target.is_null() || self.orig_bytes.len() != self.stolen_len {
            return Err(DetourError::InvalidParameter);
        }

        unsafe {
            let mut old = 0u32;
            // Get current protection and add execute permissions
            let protect_ok = crate::mem::virtual_protect_same_execute(
                self.target,
                self.stolen_len,
                windows_sys::Win32::System::Memory::PAGE_READWRITE,
                &mut old,
            );
            if protect_ok == 0 {
                return Err(DetourError::RelocationFailed);
            }

            // copy the original bytes back to the target function
            std::ptr::copy_nonoverlapping(self.orig_bytes.as_ptr(), self.target, self.stolen_len);

            // If this hook had overwritten a managed gateway, restoring the original bytes
            // makes the target a managed gateway again
            if matches!(self.target_kind, TargetKind::ManagedGateway) {
                register_managed_gateway(self.target);
            }

            // CPU-Cache flush so CPU has to read from RAM not from L1 L2 L3 cache
            let flush_ok = windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache(
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                self.target as _,
                self.stolen_len,
            );

            // Restore original protection
            let restore_ok = windows_sys::Win32::System::Memory::VirtualProtect(
                self.target as _,
                self.stolen_len,
                old,
                &mut old,
            );

            // Wait til end even if an error occurs so we try to restore original protection always
            if flush_ok == 0 || restore_ok == 0 {
                return Err(DetourError::RelocationFailed);
            }
        }
        Ok(())
    }
}

impl Drop for InlineHook {
    fn drop(&mut self) {
        if self.active {
            // auto unhook when dropped, best effort, ignore errors
            let _ = self.perform_unhook();
        }
        unregister_managed_gateway(self.trampoline.ptr);
    }
}

#[derive(Debug)]
pub struct IatHook {
    pub module: HMODULE,
    pub dll_name: String,
    pub func_name: String,
    pub original_ptr: *mut u8,
    active: bool,
}

impl IatHook {
    pub fn unhook(mut self) -> Result<(), DetourError> {
        self.perform_unhook()?;
        self.active = false;

        Ok(())
    }

    fn perform_unhook(&self) -> Result<(), DetourError> {
        unsafe {
            crate::iat::IatHook::hook_import(
                self.module,
                &self.dll_name,
                &self.func_name,
                self.original_ptr,
            )?;
            Ok(())
        }
    }
}

impl Drop for IatHook {
    fn drop(&mut self) {
        if self.active {
            // auto unhook when dropped, best effort, ignore errors
            let _ = self.perform_unhook();
        }
    }
}

pub struct TransactionCore {
    threads: Vec<HANDLE>,
    pending_hooks: Vec<PendingHook>,
    is_pending: bool,
    redirected_threads: Vec<(HANDLE, u64)>, // for safety, we store the original RIP of redirected threads so we can restore it if needed
    redirected_stacks: Vec<(HANDLE, usize, usize)>, // for safety, we store the original stack pointer and size of redirected threads so we can restore it if needed
}

impl TransactionCore {
    pub fn begin() -> Self {
        Self {
            threads: Vec::new(),
            pending_hooks: Vec::new(),
            is_pending: true,
            redirected_threads: Vec::new(),
            redirected_stacks: Vec::new(),
        }
    }

    /// Suspends the given thread and adds it to the list of threads to be resumed later.
    pub fn update_thread(&mut self, h_thread: HANDLE) -> Result<(), DetourError> {
        if !self.is_pending {
            return Err(DetourError::NotStarted);
        }
        unsafe {
            // 1. Check: ignore current thread
            let tid = GetThreadId(h_thread);
            if tid == 0 || tid == GetCurrentThreadId() {
                // if tid = 0 then handle is invalid, ignore it
                if tid == 0 {
                    CloseHandle(h_thread);
                }
                return Ok(());
            }

            // 2. Suspend the thread
            if SuspendThread(h_thread) == u32::MAX {
                // If we cant suspend the thread, we ignore it and close the handle
                CloseHandle(h_thread);
                return Ok(());
            }
        }

        self.threads.push(h_thread);
        Ok(())
    }

    pub fn update_all_threads(&mut self) {
        let threads = crate::threads::ThreadEnumerator::enumerate_process_threads();
        for h in threads {
            // we ignore errors here
            // so a single system threads cant cause the entire transaction to fail
            let _ = self.update_thread(h);
        }
    }

    /// Creates a pending inline hook for this transaction. The hook will not be applied until `commit()` is called.
    /// # Parameters
    /// - `target`: The address of the function to hook.
    /// - `detour`: The address of the detour function that will be called instead of the original function.
    /// # Returns
    /// On success, returns a pointer to the trampoline that can be used to call the original function. On failure, returns a `DetourError`.
    pub fn attach(&mut self, target: *mut u8, detour: *const u8) -> Result<*mut u8, DetourError> {
        if !self.is_pending {
            return Err(DetourError::NotStarted);
        }

        if target.is_null() || detour.is_null() {
            return Err(DetourError::InvalidParameter);
        }

        // If the target function is a managed gateway, we use a special hooking method that does not require disassembly or stolen bytes, as the gateway is designed to be overwritten with a jump to the trampoline. This allows us to hook methods that would otherwise be difficult or impossible to hook.
        // The trampoline will contain a stub that jumps to the original target after executing the detour, allowing for proper chaining of hooks
        if is_managed_gateway(target) {
            let previous_target = unsafe {
                read_managed_gateway_target(target as *const u8)
                    .ok_or(DetourError::InvalidParameter)?
            };

            let jump_type = {
                #[cfg(target_arch = "x86_64")]
                {
                    let rel = (detour as i64) - (target as i64) - 5;
                    if (i32::MIN as i64..=i32::MAX as i64).contains(&rel) {
                        JumpType::Relative5
                    } else {
                        JumpType::Absolute14
                    }
                }
                #[cfg(target_arch = "x86")]
                {
                    JumpType::Relative5
                }
            };

            let trampoline_handle = unsafe {
                TrampolineAlloc::alloc_nearby_trampoline(target, MANAGED_GATEWAY_LEN.max(64))
                    .ok_or(DetourError::AllocationFailed)?
            };

            let gateway = trampoline_handle.ptr;

            unsafe {
                write_managed_gateway_stub(gateway, previous_target);
            }

            let _ = trampoline_handle.make_rx();

            let data = InlineData {
                target,
                detour,
                trampoline: trampoline_handle,
                stolen_len: MANAGED_GATEWAY_LEN,
                jump_type,
                orig_bytes: unsafe {
                    std::slice::from_raw_parts(target as *const u8, MANAGED_GATEWAY_LEN).to_vec()
                },
                redirect_base: gateway,
                target_kind: TargetKind::ManagedGateway,
            };

            self.pending_hooks.push(PendingHook::Inline(data));
            return Ok(gateway);
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

        // MANAGED GATEWAYS FOR HOOK CHAINING
        let tramp_capacity = 128 as usize;
        let trampoline_handle = unsafe {
            // Allocate memory. rwx is required for the trampoline, we switch to rx later
            TrampolineAlloc::alloc_nearby_trampoline(target, tramp_capacity)
                .ok_or(DetourError::AllocationFailed)?
        };

        let gateway = trampoline_handle.ptr;
        let body = unsafe { gateway.add(MANAGED_GATEWAY_LEN) };

        let body_len = unsafe {
            // Relocation
            disasm::Disassembler::relocate(target, body, stolen_len)
                .map_err(|_| DetourError::RelocationFailed)
        }?;

        if MANAGED_GATEWAY_LEN + body_len > tramp_capacity {
            return Err(DetourError::RelocationFailed);
        }

        unsafe {
            write_managed_gateway_stub(gateway, body as *const u8);
        }

        let _ = trampoline_handle.make_rx();

        let data = InlineData {
            target,
            detour,
            trampoline: trampoline_handle,
            stolen_len,
            jump_type,
            orig_bytes: unsafe {
                std::slice::from_raw_parts(target as *const u8, stolen_len).to_vec()
            },
            redirect_base: body,
            target_kind: TargetKind::Normal,
        };

        self.pending_hooks.push(PendingHook::Inline(data));
        Ok(gateway)
    }

    /// Creates a pending IAT hook for this transaction. The hook will not be applied until `commit()` is called.
    /// # Parameters
    /// - `h_module`: The handle to the module whose IAT should be hooked.
    /// - `target_dll`: The name of the target DLL that is imported by the module.
    /// - `target_func`: The name of the target function that is imported from the target DLL.
    /// - `detour`: The address of the detour function that will be called instead of the original function.
    /// - `orig_out`: A pointer to a variable that will receive the original function pointer from the IAT. This can be used to call the original function from the detour.
    /// # Returns
    /// On success, returns `Result<()>`. On failure, returns a `DetourError`.
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

        // Pointer validity checks
        unsafe {
            let mut mbi: windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION =
                std::mem::zeroed();
            let res = windows_sys::Win32::System::Memory::VirtualQuery(
                h_module as *const _,
                &mut mbi,
                std::mem::size_of::<windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION>(),
            );

            // If VirtualQuery fails, we return an error or if memory is not readable
            if res == 0
                || (mbi.Protect
                    & (windows_sys::Win32::System::Memory::PAGE_READONLY
                        | windows_sys::Win32::System::Memory::PAGE_READWRITE
                        | windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ
                        | windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE))
                    == 0
            {
                return Err(DetourError::InvalidParameter);
            }
        }

        // Check if we can find the import
        // if find_import_address returns None it means there is no such dll or function in the IAT, so we return an error

        unsafe {
            crate::iat::IatHook::find_import_address(h_module, target_dll, target_func)?;
        }

        // NOW WE CAN SAFELY PUSH THE HOOK TO THE PENDING LIST, THE COMMIT FUNCTION WILL TAKE CARE OF INSTALLING IT

        self.pending_hooks.push(PendingHook::Iat {
            module: h_module,
            target_dll: target_dll.to_string(),
            target_func: target_func.to_string(),
            detour,
            orig_out,
        });
        Ok(())
    }

    // Commits the current detour transaction and returns the installed hooks.
    ///
    /// Pending inline hooks are installed after tracked threads have been checked
    /// and, if necessary, redirected from the overwritten instruction range to the
    /// trampoline. Pending IAT hooks are then applied by replacing the matching
    /// import entry with the detour function.
    ///
    /// If any step fails, all hooks installed during this call are rolled back and
    /// tracked threads are resumed before returning the error.
    ///
    /// # Errors
    ///
    /// - `DetourError::NotStarted` if the transaction is no longer pending.
    /// - Any error produced while redirecting threads or applying hooks.
    ///
    /// On success, all tracked threads are resumed and the transaction is finalized.
    pub fn commit(&mut self) -> Result<Vec<Hook>, DetourError> {
        if !self.is_pending {
            return Err(DetourError::NotStarted);
        }

        #[cfg(debug_assertions)]
        println!(
            "[Commit] Starting transaction with {} Hooks and {} threads...",
            self.pending_hooks.len(),
            self.threads.len()
        );

        let pending = std::mem::take(&mut self.pending_hooks);
        let mut installed: Vec<Hook> = Vec::new();

        // Apply hooks
        for hook in pending {
            match hook {
                PendingHook::Inline(data) => {
                    // Borrow
                    let thread_handles = self.threads.clone();
                    // check if any thread is executing in the range of the original bytes, and if so, redirect them to the trampoline before we overwrite the code
                    for h_thread in thread_handles {
                        if let Err(e) = self.redirect_rip_relative_threads(h_thread, &data) {
                            self.rollback(&mut installed);
                            self.cleanup_threads();
                            return Err(e);
                        }
                    }

                    match self.apply_inline_hook(data) {
                        Ok(inst) => installed.push(Hook::Inline(inst)),
                        Err(e) => {
                            self.rollback(&mut installed);
                            self.cleanup_threads();
                            return Err(e);
                        }
                    }
                }
                PendingHook::Iat {
                    module,
                    target_dll,
                    target_func,
                    detour,
                    orig_out,
                } => unsafe {
                    match crate::iat::IatHook::hook_import(
                        module,
                        &target_dll,
                        &target_func,
                        detour,
                    ) {
                        Ok(original) => {
                            if !orig_out.is_null() {
                                *orig_out = original;
                            }

                            installed.push(Hook::Iat(IatHook {
                                module,
                                dll_name: target_dll,
                                func_name: target_func,
                                original_ptr: original,
                                active: true,
                            }));
                        }
                        Err(err) => {
                            self.rollback(&mut installed);
                            self.cleanup_threads();
                            return Err(err.into());
                        }
                    }
                },
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

        #[cfg(debug_assertions)]
        println!(
            "[Commit] transaction successfully committed with {} hooks installed.",
            installed.len()
        );

        // resume threads
        self.cleanup_threads();
        self.is_pending = false;
        Ok(installed)
    }

    /// This function inspects the thread's instruction pointer and a portion of its
    /// stack to detect addresses that still point into the overwritten instruction
    /// range of `data.target`.
    ///
    /// If the current instruction pointer lies within the stolen byte range, it is
    /// updated to point to the corresponding offset inside `data.trampoline`.
    ///
    /// The stack is also scanned for potential return addresses that still point
    /// into the stolen range. Matching addresses are rewritten so execution returns
    /// into the trampoline instead of the patched original code.
    ///
    /// Any successful instruction-pointer or stack redirection is recorded in
    /// `self.redirected_threads` or `self.redirected_stacks` so it can later be
    /// restored if needed.
    ///
    /// # Parameters
    ///
    /// - `h_thread`: A handle to the suspended thread whose context should be
    ///   inspected and adjusted.
    /// - `data`: Metadata describing the inline hook, including the target address,
    ///   trampoline address, and stolen instruction length.
    ///
    /// # Errors
    ///
    /// Returns `Err(DetourError::RelocationFailed)` if the thread context could be
    /// updated after modifying the instruction pointer.
    ///
    /// If the thread context cannot be read via `GetThreadContext`, the function
    /// does **not** fail and instead returns `Ok(())`, treating the thread as
    /// skipped.
    ///
    /// # Notes
    ///
    /// - Only a limited of the stack is scanned, as defined by
    ///   `STACK_SCAN_DEPTH`. Automatically detects when the stack frame ends to avoid invalid access
    /// - This function assumes the thread is already suspended before being passed
    ///   in.
    /// - On x86_64, the instruction pointer and stack pointer are taken from `Rip`
    ///   and `Rsp`; on x86, `Eip` and `Esp` are used instead.
    fn redirect_rip_relative_threads(
        &mut self,
        h_thread: HANDLE,
        data: &InlineData,
    ) -> Result<(), DetourError> {
        unsafe {
            #[repr(align(16))]
            struct AlignedContext(CONTEXT);
            let mut ctx_wrapper: AlignedContext = std::mem::zeroed();
            let context = &mut ctx_wrapper.0;
            context.ContextFlags = CONTEXT_FLAGS;

            // fill context struct with current thread
            if GetThreadContext(h_thread, context) == 0 {
                #[cfg(debug_assertions)]
                eprintln!("[Debug] Couldn't read context for thread {:?}", h_thread);
                // Skip if we can't get the context
                return Ok(());
            }

            #[cfg(debug_assertions)]
            let tid = windows_sys::Win32::System::Threading::GetThreadId(h_thread);

            #[cfg(target_arch = "x86_64")]
            let original_rip = context.Rip as usize;
            #[cfg(target_arch = "x86")]
            let original_rip = context.Eip as usize;

            let target_start = data.target as usize;
            let target_end = target_start + data.stolen_len;

            #[cfg(debug_assertions)]
            println!(
                "[Scan] Thread {} at RIP: 0x{:X} | Target: 0x{:X}-0x{:X}",
                tid, original_rip, target_start, target_end
            );

            // 1. RIP Redirection
            if original_rip >= target_start && original_rip < target_end {
                #[cfg(debug_assertions)]
                println!(
                    "[DEBUG] Thread {} Instruction Pointer has been redirected",
                    tid
                );

                self.redirected_threads
                    .push((h_thread, original_rip as u64));
                let offset = original_rip - target_start;

                #[cfg(target_arch = "x86_64")]
                {
                    #[cfg(debug_assertions)]
                    println!(
                        "RIP: 0x{:X} -> 0x{:X} (Trampoline + {})",
                        original_rip, data.trampoline.ptr as usize, offset
                    );
                    context.Rip = (data.redirect_base as u64) + (offset as u64);
                }
                #[cfg(target_arch = "x86")]
                {
                    #[cfg(debug_assertions)]
                    println!(
                        "EIP: 0x{:X} -> 0x{:X} (Trampoline + {})",
                        original_rip,
                        data.trampoline.ptr as u32,
                        (offset as u32)
                    );
                    context.Eip = (data.redirect_base as u32) + (offset as u32);
                }

                if SetThreadContext(h_thread, context) == 0 {
                    return Err(DetourError::RelocationFailed);
                }
            }

            // 2. STACK Redirection
            #[cfg(target_arch = "x86_64")]
            let stack_ptr = context.Rsp as usize;
            #[cfg(target_arch = "x86")]
            let stack_ptr = context.Esp as usize;

            let mut mbi: windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION =
                std::mem::zeroed();
            if windows_sys::Win32::System::Memory::VirtualQuery(
                stack_ptr as *const _,
                &mut mbi,
                std::mem::size_of::<windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION>(),
            ) != 0
            {
                let stack_segment_top = mbi.BaseAddress as usize + mbi.RegionSize;

                for i in 0..STACK_SCAN_DEPTH {
                    let current_stack_addr = stack_ptr + (i * std::mem::size_of::<usize>());
                    if current_stack_addr + std::mem::size_of::<usize>() > stack_segment_top {
                        break;
                    }

                    let mut stack_value: usize = 0;
                    std::ptr::copy_nonoverlapping(
                        current_stack_addr as *const usize,
                        &mut stack_value,
                        1,
                    );

                    if stack_value >= target_start && stack_value < target_end {
                        let offset = stack_value - target_start;
                        let new_return_addr = (data.redirect_base as usize) + offset;

                        #[cfg(debug_assertions)]
                        println!(
                            "[Stack] Thread {} return address found on stack at 0x{:X}:",
                            tid, current_stack_addr
                        );
                        #[cfg(debug_assertions)]
                        println!(
                            "        0x{:X} -> 0x{:X} (Trampoline + {})",
                            stack_value, new_return_addr, offset
                        );

                        self.redirected_stacks
                            .push((h_thread, current_stack_addr, stack_value));

                        std::ptr::copy_nonoverlapping(
                            &new_return_addr,
                            current_stack_addr as *mut usize,
                            1,
                        );
                    }
                }
            }
            Ok(())
        }
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
    fn rollback(&mut self, installed: &mut Vec<Hook>) {
        // restore threads first before unhook
        for (h_thread, original_rip) in self.redirected_threads.drain(..) {
            unsafe {
                #[repr(align(16))]
                struct AlignedContext(CONTEXT);
                let mut ctx_wrapper: AlignedContext = std::mem::zeroed();
                let context = &mut ctx_wrapper.0;
                context.ContextFlags = CONTEXT_FLAGS;

                // Get context, restore original RIP, set context
                if GetThreadContext(h_thread, context) != 0 {
                    #[cfg(target_arch = "x86_64")]
                    {
                        context.Rip = original_rip;
                    }
                    #[cfg(target_arch = "x86")]
                    {
                        context.Eip = original_rip as u32;
                    }

                    SetThreadContext(h_thread, context);

                    #[cfg(debug_assertions)]
                    println!(
                        "[Rollback] Thread restored to Original-IP 0x{:X}",
                        original_rip
                    );
                }
            }
        }

        for (_h_thread, stack_addr, original_value) in self.redirected_stacks.drain(..) {
            unsafe {
                std::ptr::copy_nonoverlapping(&original_value, stack_addr as *mut usize, 1);
            }
        }

        // Restore original bytes or IAT entries for each installed hook
        for detour in installed.drain(..) {
            match detour {
                Hook::Inline(hook) => {
                    let _ = hook.unhook();
                }
                Hook::Iat(hook) => {
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
    fn apply_inline_hook(&mut self, data: InlineData) -> Result<InlineHook, DetourError> {
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

            // stolen_len could be > patch_len, in that case we fill the rest with NOP 0x90 bytes
            let mut full_patch = vec![0x90u8; data.stolen_len];
            full_patch[..patch_len].copy_from_slice(&patch_buffer[..patch_len]); // E9 xx xx xx xx 90 90 90 90....

            // we write atomic to ensure a thread-safe patching. If something fails we return an error
            if crate::mem::write_memory_atomic(target, full_patch.as_ptr(), data.stolen_len)
                .is_some()
            {
                // If this hook is overwriting a managed gateway, we need to unregister it
                if matches!(data.target_kind, TargetKind::ManagedGateway) {
                    unregister_managed_gateway(data.target);
                }

                // Write was successful now we register the trampoline as a managed gateway so it can be hooked itself
                register_managed_gateway(data.trampoline.ptr);

                Ok(InlineHook {
                    target: data.target,
                    trampoline: data.trampoline,
                    stolen_len: data.stolen_len,
                    orig_bytes: data.orig_bytes,
                    jump_type: data.jump_type,
                    active: true,
                    target_kind: data.target_kind,
                })
            } else {
                // If the write fails, we return an error. The commit() function will catch this and call rollback() to undo any hooks that were already installed.
                Err(DetourError::RelocationFailed)
            }
        }
    }

    #[cfg(debug_assertions)]
    pub fn dump_state(&self) {
        println!("\n--- [DETOUR TRANSACTION DEBUG] ---");
        println!(
            "Status: {}",
            if self.is_pending {
                "PENDING"
            } else {
                "COMMITTED/ABORTED"
            }
        );

        println!("Threads ({}):", self.threads.len());
        for &h in &self.threads {
            let tid = unsafe { windows_sys::Win32::System::Threading::GetThreadId(h) };
            println!("  [Thread] TID: {} (Handle: {:?})", tid, h);
        }

        println!("Planned Hooks ({}):", self.pending_hooks.len());
        for (i, hook) in self.pending_hooks.iter().enumerate() {
            match hook {
                PendingHook::Inline(data) => {
                    println!(
                        "  [{}] INLINE: Target {:p} -> Detour {:p} (Type: {:?})",
                        i, data.target, data.detour, data.jump_type
                    );
                }
                PendingHook::Iat {
                    target_dll,
                    target_func,
                    ..
                } => {
                    println!("  [{}] IAT: {}!{}", i, target_dll, target_func);
                }
            }
        }

        if !self.redirected_threads.is_empty() {
            println!("RIP-Redirections: {}", self.redirected_threads.len());
        }

        if !self.redirected_stacks.is_empty() {
            println!("Stack-Redirections: {}", self.redirected_stacks.len());
        }

        println!("----------------------------------\n");
    }
}

impl Drop for TransactionCore {
    fn drop(&mut self) {
        // If the transaction is still pending when the DetourTransaction struct is dropped, we call abort() to clean up any pending hook
        if self.is_pending {
            self.abort();
        }
    }
}

fn managed_gateways() -> &'static Mutex<HashSet<usize>> {
    static GATEWAYS: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();
    GATEWAYS.get_or_init(|| Mutex::new(HashSet::new()))
}

fn register_managed_gateway(ptr: *mut u8) {
    let _ = managed_gateways().lock().map(|mut s| {
        s.insert(ptr as usize);
    });
}

fn unregister_managed_gateway(ptr: *mut u8) {
    let _ = managed_gateways().lock().map(|mut s| {
        s.remove(&(ptr as usize));
    });
}

fn is_managed_gateway(ptr: *mut u8) -> bool {
    managed_gateways()
        .lock()
        .map(|s| s.contains(&(ptr as usize)))
        .unwrap_or(false)
}

#[cfg(target_arch = "x86_64")]
unsafe fn write_managed_gateway_stub(src: *mut u8, dst: *const u8) {
    unsafe {
        // FF 25 00 00 00 00 [u64 addr]
        *src.add(0) = 0xFF;
        *src.add(1) = 0x25;
        *src.add(2) = 0x00;
        *src.add(3) = 0x00;
        *src.add(4) = 0x00;
        *src.add(5) = 0x00;
        std::ptr::copy_nonoverlapping(&(dst as u64).to_le_bytes()[0], src.add(6), 8);
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn read_managed_gateway_target(src: *const u8) -> Option<*const u8> {
    unsafe {
        if *src.add(0) != 0xFF
            || *src.add(1) != 0x25
            || *src.add(2) != 0x00
            || *src.add(3) != 0x00
            || *src.add(4) != 0x00
            || *src.add(5) != 0x00
        {
            return None;
        }

        let mut addr = [0u8; 8];
        std::ptr::copy_nonoverlapping(src.add(6), addr.as_mut_ptr(), 8);
        Some(u64::from_le_bytes(addr) as *const u8)
    }
}

#[cfg(target_arch = "x86")]
unsafe fn write_managed_gateway_stub(src: *mut u8, dst: *const u8) {
    let rel = (dst as isize).wrapping_sub(src as isize).wrapping_sub(5);
    *src.add(0) = 0xE9;
    std::ptr::copy_nonoverlapping(&(rel as i32).to_le_bytes()[0], src.add(1), 4);
}

#[cfg(target_arch = "x86")]
unsafe fn read_managed_gateway_target(src: *const u8) -> Option<*const u8> {
    if *src.add(0) != 0xE9 {
        return None;
    }

    let mut rel = [0u8; 4];
    std::ptr::copy_nonoverlapping(src.add(1), rel.as_mut_ptr(), 4);
    let rel = i32::from_le_bytes(rel) as isize;
    Some(src.offset(5 + rel) as *const u8)
}
