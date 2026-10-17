// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hook detection: is a function already hooked, and where does the hook lead?
//!
//! A hook - another library's, an anti-cheat's, an AppCompat shim's, or one of
//! neohook's own - leaves a trace that can be found from inside the process:
//!
//! * **Inline hooks** change the first bytes of a function. They are found by
//!   comparing the code in memory with the same bytes in the module's file on
//!   disk, with the file's base relocations applied for where the module was
//!   actually loaded. The changed instruction is classified (`jmp rel32`,
//!   `jmp [mem]`, `push imm; ret`, `mov rax, imm; jmp rax`, `int3`) and the jump
//!   is followed to its destination.
//! * **Hardware breakpoints** (VEH hooks) change no byte at all; they are
//!   found in the debug registers of the process's threads.
//! * **Import (IAT) hooks** rewrite a module's import slot; the slot no longer
//!   holds the address the exporting module resolves the import to.
//! * **Export (EAT) hooks** rewrite an export's RVA; it no longer matches the
//!   one in the file.
//!
//! For every finding the module owning the destination is reported, or `None`
//! when the destination lies in private memory, which is where trampolines and
//! injected code usually live.
//!
//! ```rust,ignore
//! if let Some(hook) = neohook::check_export("user32.dll", "MessageBoxW")? {
//!     println!("{:?} -> {:?} in {:?}", hook.kind, hook.destination, hook.destination_module);
//! }
//! for hook in neohook::scan_module_hooks("ntdll.dll")? {
//!     println!("{hook:?}");
//! }
//! ```
//!
//! ## Limits
//!
//! Only code inside a module image can be compared with a file. A function
//! whose module file cannot be read (deleted, or a manually mapped image) is
//! reported as [`DetectError::FileUnreadable`]. The comparison covers the
//! first instructions of a function (at least [`COMPARE_BYTES`] bytes, up to
//! the function's first `ret` or jump), which is where hooks are placed; a
//! patch deeper inside a function is not looked for. Some Windows versions
//! rewrite indirect import calls in code at load time (import call
//! optimization); a direct call where the file has an indirect one is
//! therefore not reported.

use std::fmt;

use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind};
use windows_sys::Win32::Foundation::{CloseHandle, HMODULE, MAX_PATH};
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, GetThreadContext, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT,
    IMAGE_SCN_MEM_EXECUTE,
};
use windows_sys::Win32::System::LibraryLoader::{
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    GetModuleFileNameW, GetModuleHandleExW, GetProcAddress,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentThread, OpenThread, ResumeThread, SuspendThread, THREAD_GET_CONTEXT,
    THREAD_SUSPEND_RESUME,
};

/// Minimum number of bytes compared at a function's start: enough for the
/// longest jump patch (`FF 25` + 8-byte address) plus a hot-patch prefix.
pub const COMPARE_BYTES: usize = 16;

/// What kind of hook was found.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DetectedHookKind {
    /// The function starts with a jump that the file does not have.
    InlineJump,
    /// The function starts with an `int3` (`0xCC`) that the file does not
    /// have, the mark of a software-breakpoint hook.
    Breakpoint,
    /// A thread has a hardware execution breakpoint on the function, the mark
    /// of a VEH hook. No byte is changed.
    HardwareBreakpoint,
    /// The function's first bytes differ from the file, but not as a
    /// recognised jump.
    ModifiedCode,
    /// An import slot holds a different address than the exporting module
    /// resolves the import to.
    ImportRedirect,
    /// An export's RVA differs from the one in the module's file.
    ExportRedirect,
}

/// One hook found by the detection functions.
#[derive(Clone, Debug, PartialEq)]
pub struct DetectedHook {
    /// What kind of hook it is.
    pub kind: DetectedHookKind,
    /// The modified location: the function's first changed byte, the import
    /// slot, or the export table entry.
    pub address: *const u8,
    /// The function concerned, if known: the export name, or `"DLL!Name"` for
    /// an import.
    pub function: Option<String>,
    /// Where the hook leads, if it can be told: the jump's final destination,
    /// the address in the import slot, or the redirected export.
    pub destination: Option<*const u8>,
    /// The file name of the module holding `destination`, or `None` if it lies
    /// in private memory (or is unknown).
    pub destination_module: Option<String>,
}

// SAFETY: the pointers are plain addresses reported to the caller; nothing is
// dereferenced through them.
unsafe impl Send for DetectedHook {}
unsafe impl Sync for DetectedHook {}

/// Errors produced by hook detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectError {
    /// A null pointer was supplied.
    NullPointer,
    /// The module or export could not be found.
    NotFound,
    /// The address does not lie inside a loaded module, so there is no file to
    /// compare it with.
    NotInModule,
    /// The module's file could not be read or is not a matching PE image.
    FileUnreadable,
}

impl fmt::Display for DetectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NullPointer => write!(f, "null pointer"),
            Self::NotFound => write!(f, "module or export not found"),
            Self::NotInModule => write!(f, "address is not inside a loaded module"),
            Self::FileUnreadable => write!(f, "module file could not be read"),
        }
    }
}

impl std::error::Error for DetectError {}

/// Checks whether the function at `func` is hooked.
///
/// Returns the hook found at its start - an inline jump, a breakpoint, other
/// modified bytes, or a hardware breakpoint on it - or `None` if it matches its
/// module's file. If `func` itself is unchanged and is a jump stub (an import
/// thunk, an incremental-linking stub), the function it leads to is checked
/// as well.
///
/// # Errors
///
/// [`DetectError::NullPointer`] for a null `func`,
/// [`DetectError::NotInModule`] if it is not inside a loaded module, and
/// [`DetectError::FileUnreadable`] if the module's file cannot be read.
///
/// # Safety
///
/// `func` must stay mapped for the duration of the call: its code is read,
/// and a module unloaded meanwhile could be unmapped under the read.
pub unsafe fn check_function(func: *const u8) -> Result<Option<DetectedHook>, DetectError> {
    if func.is_null() {
        return Err(DetectError::NullPointer);
    }
    let found = check_code(func)?;
    if found.is_some() {
        return Ok(found);
    }
    // An unchanged jump stub: check where it leads.
    let target = unsafe { crate::detour_code_from_pointer(func) } as *const u8;
    if target.is_null() || target == func {
        return Ok(None);
    }
    match check_code(target) {
        Ok(found) => Ok(found),
        // The stub leads into code that cannot be compared (e.g. private
        // memory): nothing more to tell.
        Err(DetectError::NotInModule | DetectError::FileUnreadable) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Checks whether the export `func` of `module` (loaded if it is not already
/// present) is hooked, inline or in the module's export table.
///
/// # Errors
///
/// [`DetectError::NotFound`] if the module cannot be loaded or has no such
/// export, otherwise as [`check_function`].
pub fn check_export(module: &str, func: &str) -> Result<Option<DetectedHook>, DetectError> {
    let address = crate::find_function(module, func).ok_or(DetectError::NotFound)?;
    let h_module = crate::get_module_handle(module).ok_or(DetectError::NotFound)?;
    let disk = DiskImage::load(h_module)?;

    // An export table hook: `GetProcAddress` already returns the redirected
    // address, so compare the table entry with the file first.
    if let Some(hook) = unsafe { export_redirect(h_module, &disk, func) } {
        return Ok(Some(hook));
    }
    let mut found = check_code(address)?;
    if let Some(hook) = &mut found {
        hook.function = Some(func.to_string());
    }
    Ok(found)
}

/// Scans the loaded module `module` for hooks: every exported function's
/// start, its export table, and its import table.
///
/// # Errors
///
/// [`DetectError::NotFound`] if the module is not loaded, and
/// [`DetectError::FileUnreadable`] if its file cannot be read.
pub fn scan_module_hooks(module: &str) -> Result<Vec<DetectedHook>, DetectError> {
    let h_module = crate::get_module_handle(module).ok_or(DetectError::NotFound)?;
    let disk = DiskImage::load(h_module)?;
    let base = h_module as usize;
    let mut found = Vec::new();

    let exports = unsafe { crate::enumerate_exports(h_module) }.unwrap_or_default();
    let breakpoints = HardwareBreakpoints::capture();
    for export in &exports {
        if export.forwarder.is_some() {
            continue;
        }
        let name = export
            .name
            .clone()
            .unwrap_or_else(|| format!("#{}", export.ordinal));
        if let Some(mut hook) = disk.export_redirect(base, export.ordinal, export.address) {
            hook.function = Some(name);
            found.push(hook);
            continue;
        }
        let rva = (export.address as usize).wrapping_sub(base);
        if !disk.is_executable(rva) {
            continue;
        }
        let hook = inline_hook(export.address, &disk, base)
            .or_else(|| breakpoints.hook_at(export.address));
        if let Some(mut hook) = hook {
            hook.function = Some(name);
            found.push(hook);
        }
    }

    found.extend(unsafe { import_redirects(h_module) });
    Ok(found)
}

/// Checks the code at `func` against its module's file, then the hardware
/// breakpoints.
fn check_code(func: *const u8) -> Result<Option<DetectedHook>, DetectError> {
    let h_module = module_of(func).ok_or(DetectError::NotInModule)?;
    let disk = DiskImage::load(h_module)?;
    if let Some(hook) = inline_hook(func, &disk, h_module as usize) {
        return Ok(Some(hook));
    }
    Ok(HardwareBreakpoints::capture().hook_at(func))
}

/// Compares the first instructions at `func` with the file and classifies a
/// difference.
fn inline_hook(func: *const u8, disk: &DiskImage, base: usize) -> Option<DetectedHook> {
    let rva = (func as usize).checked_sub(base)?;
    // Disk bytes for the comparison window, with a little slack so the last
    // instruction decodes whole.
    let disk_code = disk.read(rva, COMPARE_BYTES + 32, base)?;
    let readable = unsafe { crate::disasm::readable_bytes_from(func) };
    if readable == 0 {
        return None;
    }
    let live_len = disk_code.len().min(readable);
    let live_code = unsafe { std::slice::from_raw_parts(func, live_len) };

    // Walk the file's instructions: compare each one, and stop once the window
    // is covered or the function ends.
    let mut decoder = Decoder::with_ip(bitness(), &disk_code, func as u64, DecoderOptions::NONE);
    let mut offset = 0usize;
    while offset < COMPARE_BYTES && decoder.can_decode() {
        let disk_instr = decoder.decode();
        if disk_instr.is_invalid() {
            return None;
        }
        let len = disk_instr.len();
        if offset + len > live_code.len() {
            return None;
        }
        let live = &live_code[offset..offset + len];
        let file = &disk_code[offset..offset + len];
        if live != file {
            let at = unsafe { func.add(offset) };
            if is_import_call_rewrite(&disk_instr, at) {
                offset += len;
                continue;
            }
            let hook = classify(at, &live_code[offset..]);
            return (!is_self_patch(&hook)).then_some(hook);
        }
        offset += len;
        if matches!(
            disk_instr.flow_control(),
            FlowControl::Return | FlowControl::UnconditionalBranch | FlowControl::IndirectBranch
        ) {
            break;
        }
    }
    None
}

/// Whether the live instruction at `at` is the loader's rewrite of the file's
/// indirect import call or jump (`call [__imp_X]`) into a direct one.
fn is_import_call_rewrite(disk_instr: &Instruction, at: *const u8) -> bool {
    let indirect = matches!(
        disk_instr.flow_control(),
        FlowControl::IndirectCall | FlowControl::IndirectBranch
    ) && disk_instr.op0_kind() == OpKind::Memory;
    if !indirect {
        return false;
    }
    let Some(live) = decode_live(at) else {
        return false;
    };
    matches!(
        live.flow_control(),
        FlowControl::Call | FlowControl::UnconditionalBranch
    ) && live.near_branch_target() != 0
}

/// Classifies the changed bytes at `at` (the live code from there on).
fn classify(at: *const u8, live: &[u8]) -> DetectedHook {
    let mut hook = DetectedHook {
        kind: DetectedHookKind::ModifiedCode,
        address: at,
        function: None,
        destination: None,
        destination_module: None,
    };
    let Some(instr) = decode_live(at) else {
        return hook;
    };
    let mut destination = None;
    match instr.mnemonic() {
        Mnemonic::Int3 => hook.kind = DetectedHookKind::Breakpoint,
        Mnemonic::Jmp => {
            hook.kind = DetectedHookKind::InlineJump;
            // Follows the jump and any jump stubs after it (a hot-patch short
            // jump into the padding, a trampoline's absolute jump).
            destination = Some(unsafe { crate::detour_code_from_pointer(at) } as *const u8);
        }
        // push imm32; ret
        Mnemonic::Push if is_push_imm(&instr) => {
            if live.get(instr.len()) == Some(&0xC3) {
                hook.kind = DetectedHookKind::InlineJump;
                // Sign-extended to 64 bits on x64, as the CPU does.
                destination = Some(instr.immediate(0) as usize as *const u8);
            }
        }
        // mov rax/eax, imm; jmp rax/eax
        Mnemonic::Mov if is_immediate(instr.op1_kind()) && instr.op0_kind() == OpKind::Register => {
            let next = unsafe { at.add(instr.len()) };
            if let Some(jmp) = decode_live(next)
                && jmp.mnemonic() == Mnemonic::Jmp
                && jmp.op0_kind() == OpKind::Register
                && jmp.op0_register() == instr.op0_register()
            {
                hook.kind = DetectedHookKind::InlineJump;
                destination = Some(instr.immediate(1) as usize as *const u8);
            }
        }
        _ => {}
    }
    if let Some(destination) = destination.filter(|d| !d.is_null()) {
        let destination = unsafe { crate::detour_code_from_pointer(destination) } as *const u8;
        hook.destination = Some(destination);
        hook.destination_module = module_name_of(destination);
    }
    hook
}

/// Whether a jump patched into a system DLL stays inside that DLL. System
/// DLLs patch themselves at run time - `ucrtbase` and `ntdll` point their math
/// and memory routines at the variant for the CPU - while a hook leads into
/// another module or private memory.
fn is_self_patch(hook: &DetectedHook) -> bool {
    let Some(module) = module_of(hook.address) else {
        return false;
    };
    hook.kind == DetectedHookKind::InlineJump
        && hook
            .destination
            .is_some_and(|d| module_of(d) == Some(module))
        && is_system_module(module)
}

fn is_push_imm(instr: &Instruction) -> bool {
    matches!(
        instr.op0_kind(),
        OpKind::Immediate8to32 | OpKind::Immediate32 | OpKind::Immediate32to64
    )
}

fn is_immediate(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate32to64
    )
}

/// Decodes the live instruction at `at`.
fn decode_live(at: *const u8) -> Option<Instruction> {
    let readable = unsafe { crate::disasm::readable_bytes_from(at) };
    if readable == 0 {
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(at, readable.min(15)) };
    let mut decoder = Decoder::with_ip(bitness(), bytes, at as u64, DecoderOptions::NONE);
    let instr = decoder.decode();
    (!instr.is_invalid() && instr.code() != Code::INVALID).then_some(instr)
}

fn bitness() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        64
    }
    #[cfg(target_arch = "x86")]
    {
        32
    }
}

/// The module whose image contains `address`, if any.
fn module_of(address: *const u8) -> Option<HMODULE> {
    let mut module: HMODULE = std::ptr::null_mut();
    let ok = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            address as *const u16,
            &mut module,
        )
    };
    (ok != 0 && !module.is_null()).then_some(module)
}

/// Whether `address` is an export of a module loaded from the Windows
/// directory. Windows points some exports at another system DLL's export at
/// run time (32-bit `user32!DefWindowProcA` at an `ntdll` stub).
fn is_system_export(address: *const u8) -> bool {
    let Some(module) = module_of(address) else {
        return false;
    };
    is_system_module(module)
        && unsafe { crate::enumerate_exports(module) }
            .is_ok_and(|exports| exports.iter().any(|e| e.address == address))
}

/// Whether `module` was loaded from the Windows directory.
fn is_system_module(module: HMODULE) -> bool {
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    let mut buffer = [0u16; MAX_PATH as usize];
    let len =
        unsafe { GetSystemWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if len == 0 || len >= buffer.len() {
        return false;
    }
    let mut windows = String::from_utf16_lossy(&buffer[..len]).to_lowercase();
    if !windows.ends_with('\\') {
        windows.push('\\');
    }
    module_path(module).is_some_and(|path| path.to_lowercase().starts_with(&windows))
}

/// Full path of a loaded module's file.
fn module_path(module: HMODULE) -> Option<String> {
    let mut buffer = vec![0u16; MAX_PATH as usize];
    loop {
        let len = unsafe { GetModuleFileNameW(module, buffer.as_mut_ptr(), buffer.len() as u32) }
            as usize;
        if len == 0 {
            return None;
        }
        if len < buffer.len() {
            return Some(String::from_utf16_lossy(&buffer[..len]));
        }
        if buffer.len() >= 32 * 1024 {
            return None;
        }
        buffer.resize(buffer.len() * 2, 0);
    }
}

/// File name (without the directory) of the module containing `address`.
fn module_name_of(address: *const u8) -> Option<String> {
    let path = module_path(module_of(address)?)?;
    Some(path.rsplit(['\\', '/']).next().unwrap_or(&path).to_string())
}

/// An export whose table entry differs from the file.
unsafe fn export_redirect(h_module: HMODULE, disk: &DiskImage, func: &str) -> Option<DetectedHook> {
    let exports = unsafe { crate::enumerate_exports(h_module) }.ok()?;
    let export = exports
        .iter()
        .find(|e| e.name.as_deref() == Some(func) && e.forwarder.is_none())?;
    let mut hook = disk.export_redirect(h_module as usize, export.ordinal, export.address)?;
    hook.function = Some(func.to_string());
    Some(hook)
}

/// Import slots of `h_module` that do not hold what their exporting module
/// resolves the import to.
unsafe fn import_redirects(h_module: HMODULE) -> Vec<DetectedHook> {
    let Ok(imports) = (unsafe { crate::enumerate_imports(h_module) }) else {
        return Vec::new();
    };
    let Some(slots) = import_slots(h_module) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for (import, slot) in imports.iter().zip(slots) {
        let Some(name) = &import.name else {
            continue;
        };
        if import.address.is_null() {
            continue;
        }
        // The loader binds an import to wherever the exporting module, its API
        // set and its forwarders resolve it - which can differ from what the
        // named DLL resolves it to from here, and can carry another name
        // (`HeapAlloc` is `ntdll!RtlAllocateHeap`). A slot holding an export of
        // that name in the module it points into, or any export of a system
        // DLL, is bound by the loader; a hook points at a detour.
        let Ok(cname) = std::ffi::CString::new(name.as_str()) else {
            continue;
        };
        if let Some(target_module) = module_of(import.address)
            && unsafe { GetProcAddress(target_module, cname.as_ptr().cast()) }
                .is_some_and(|f| f as *const u8 == import.address)
        {
            continue;
        }
        if is_system_export(import.address) {
            continue;
        }
        found.push(DetectedHook {
            kind: DetectedHookKind::ImportRedirect,
            address: slot,
            function: Some(format!("{}!{}", import.dll, name)),
            destination: Some(import.address),
            destination_module: module_name_of(import.address),
        });
    }
    found
}

/// The addresses of a module's import slots, in the order
/// [`crate::enumerate_imports`] lists the imports.
fn import_slots(h_module: HMODULE) -> Option<Vec<*const u8>> {
    use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_IMPORT;
    use windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_DESCRIPTOR;
    let image = crate::pe::parse_module_image(h_module).ok()?;
    let mut slots = Vec::new();
    let mut desc_rva =
        crate::pe::data_directory_rva(&image, IMAGE_DIRECTORY_ENTRY_IMPORT as usize)?;
    let word = std::mem::size_of::<usize>();
    while let Some(desc) = crate::pe::rva_to_ptr::<IMAGE_IMPORT_DESCRIPTOR>(&image, desc_rva) {
        let desc = unsafe { *desc };
        if desc.Name == 0 {
            break;
        }
        crate::pe::read_c_string_from_rva(&image, desc.Name as usize)?;
        let original = unsafe { desc.Anonymous.OriginalFirstThunk } as usize;
        let lookup = if original != 0 {
            original
        } else {
            desc.FirstThunk as usize
        };
        let iat = desc.FirstThunk as usize;
        if lookup != 0 {
            let mut offset = 0;
            while let Some(entry) = crate::pe::rva_to_ptr::<usize>(&image, lookup + offset) {
                if unsafe { entry.read_unaligned() } == 0 {
                    break;
                }
                slots.push((image.base_address + iat + offset) as *const u8);
                offset += word;
            }
        }
        desc_rva += std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
    }
    Some(slots)
}

/// Hardware execution breakpoints armed in the process's threads.
struct HardwareBreakpoints {
    addresses: Vec<usize>,
}

impl HardwareBreakpoints {
    /// Reads the debug registers of every thread, this one included.
    fn capture() -> Self {
        #[cfg(target_arch = "x86_64")]
        const CONTEXT_DEBUG: u32 =
            windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_DEBUG_REGISTERS_AMD64;
        #[cfg(target_arch = "x86")]
        const CONTEXT_DEBUG: u32 =
            windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_DEBUG_REGISTERS_X86;

        #[repr(align(16))]
        struct AlignedContext(CONTEXT);

        // The execute breakpoints armed in a thread, 0 for an unused register.
        // Allocates nothing: it runs while the thread is suspended, and that
        // thread may hold the heap lock.
        let read = |h_thread| {
            let mut found = [0usize; 4];
            let mut ctx: AlignedContext = unsafe { std::mem::zeroed() };
            ctx.0.ContextFlags = CONTEXT_DEBUG;
            if unsafe { GetThreadContext(h_thread, &mut ctx.0) } == 0 {
                return found;
            }
            let ctx = ctx.0;
            for (slot, dr) in [ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3].into_iter().enumerate() {
                // Locally or globally enabled, with an execute condition (R/W = 00).
                let enabled = ctx.Dr7 & (0b11 << (slot * 2)) != 0;
                let execute = (ctx.Dr7 >> (16 + slot * 4)) & 0b11 == 0;
                if enabled && execute {
                    found[slot] = dr as usize;
                }
            }
            found
        };

        let mut addresses: Vec<usize> = read(unsafe { GetCurrentThread() }).to_vec();
        let _freeze = crate::threads::hold_freeze_lock();
        for tid in crate::threads::ThreadEnumerator::enumerate_process_threads() {
            let h = unsafe { OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, 0, tid) };
            if h.is_null() {
                continue;
            }
            if unsafe { SuspendThread(h) } != u32::MAX {
                let found = read(h);
                unsafe { ResumeThread(h) };
                addresses.extend(found);
            }
            unsafe { CloseHandle(h) };
        }
        addresses.retain(|&address| address != 0);
        addresses.sort_unstable();
        addresses.dedup();
        Self { addresses }
    }

    fn hook_at(&self, func: *const u8) -> Option<DetectedHook> {
        self.addresses
            .binary_search(&(func as usize))
            .ok()
            .map(|_| DetectedHook {
                kind: DetectedHookKind::HardwareBreakpoint,
                address: func,
                function: None,
                destination: None,
                destination_module: None,
            })
    }
}

/// A section of the module's file.
struct Section {
    virtual_address: usize,
    virtual_size: usize,
    raw_offset: usize,
    raw_size: usize,
    executable: bool,
}

/// The parts of a module's file needed to rebuild its original code: the
/// sections, the preferred base and the base relocations.
struct DiskImage {
    bytes: Vec<u8>,
    sections: Vec<Section>,
    image_base: u64,
    /// RVA and type of every base relocation, sorted by RVA.
    relocations: Vec<(usize, u16)>,
    /// RVA of the export directory's function table and its entry count.
    export_functions: Option<(usize, usize, u32)>,
}

const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
const IMAGE_REL_BASED_DIR64: u16 = 10;

impl DiskImage {
    /// Reads and parses the file of a loaded module.
    fn load(h_module: HMODULE) -> Result<Self, DetectError> {
        let path = module_path(h_module).ok_or(DetectError::FileUnreadable)?;
        let bytes = std::fs::read(&path).map_err(|_| DetectError::FileUnreadable)?;
        Self::parse(bytes).ok_or(DetectError::FileUnreadable)
    }

    fn parse(bytes: Vec<u8>) -> Option<Self> {
        let u16_at = |at: usize| -> Option<u16> {
            Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
        };
        let u32_at = |at: usize| -> Option<u32> {
            Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
        };
        let u64_at = |at: usize| -> Option<u64> {
            Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
        };

        if u16_at(0)? != 0x5A4D {
            return None;
        }
        let nt = u32_at(0x3C)? as usize;
        if u32_at(nt)? != 0x0000_4550 {
            return None;
        }
        let file_header = nt + 4;
        let section_count = u16_at(file_header + 2)? as usize;
        let optional_size = u16_at(file_header + 16)? as usize;
        let optional = file_header + 20;
        let magic = u16_at(optional)?;
        #[cfg(target_arch = "x86_64")]
        let (image_base, directories) = {
            if magic != 0x20B {
                return None;
            }
            (u64_at(optional + 24)?, optional + 112)
        };
        #[cfg(target_arch = "x86")]
        let (image_base, directories) = {
            if magic != 0x10B {
                return None;
            }
            let _ = u64_at;
            (u32_at(optional + 28)? as u64, optional + 96)
        };
        let directory = |index: u32| -> Option<(usize, usize)> {
            let at = directories + index as usize * 8;
            let rva = u32_at(at)? as usize;
            let size = u32_at(at + 4)? as usize;
            (rva != 0 && size != 0).then_some((rva, size))
        };

        let mut sections = Vec::with_capacity(section_count);
        let table = optional + optional_size;
        for i in 0..section_count {
            let at = table + i * 40;
            let characteristics = u32_at(at + 36)?;
            sections.push(Section {
                virtual_size: u32_at(at + 8)? as usize,
                virtual_address: u32_at(at + 12)? as usize,
                raw_size: u32_at(at + 16)? as usize,
                raw_offset: u32_at(at + 20)? as usize,
                executable: characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
            });
        }

        let reloc_directory = directory(IMAGE_DIRECTORY_ENTRY_BASERELOC as u32);
        let export_directory = directory(IMAGE_DIRECTORY_ENTRY_EXPORT as u32);

        let mut image = Self {
            bytes,
            sections,
            image_base,
            relocations: Vec::new(),
            export_functions: None,
        };

        if let Some((rva, size)) = reloc_directory {
            let blocks = image.raw(rva, size)?;
            let mut at = 0;
            while at + 8 <= blocks.len() {
                let page = u32::from_le_bytes(blocks[at..at + 4].try_into().ok()?) as usize;
                let block_size =
                    u32::from_le_bytes(blocks[at + 4..at + 8].try_into().ok()?) as usize;
                if block_size < 8 || at + block_size > blocks.len() {
                    break;
                }
                for entry in blocks[at + 8..at + block_size].as_chunks::<2>().0 {
                    let entry = u16::from_le_bytes(*entry);
                    let kind = entry >> 12;
                    if kind == IMAGE_REL_BASED_HIGHLOW || kind == IMAGE_REL_BASED_DIR64 {
                        image
                            .relocations
                            .push((page + (entry & 0xFFF) as usize, kind));
                    }
                }
                at += block_size;
            }
            image.relocations.sort_unstable();
        }

        if let Some((rva, _)) = export_directory {
            let header = image.raw(rva, 40)?;
            let base = u32::from_le_bytes(header[16..20].try_into().ok()?);
            let count = u32::from_le_bytes(header[20..24].try_into().ok()?) as usize;
            let functions = u32::from_le_bytes(header[28..32].try_into().ok()?) as usize;
            image.export_functions = Some((functions, count, base));
        }

        Some(image)
    }

    /// The file bytes backing `[rva, rva + len)`, without relocations.
    fn raw(&self, rva: usize, len: usize) -> Option<Vec<u8>> {
        let section = self.sections.iter().find(|s| {
            rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size.max(s.raw_size)
        })?;
        let within = rva - section.virtual_address;
        let available = section
            .virtual_size
            .max(section.raw_size)
            .saturating_sub(within);
        let len = len.min(available);
        let mut out = vec![0u8; len];
        // Bytes past the section's raw data are zero-filled in memory.
        if within < section.raw_size {
            let from = section.raw_offset + within;
            let copy = len.min(section.raw_size - within);
            out[..copy].copy_from_slice(self.bytes.get(from..from + copy)?);
        }
        Some(out)
    }

    /// The original bytes at `[rva, rva + len)` as the loader maps them at
    /// `base`: the file bytes with the base relocations applied.
    fn read(&self, rva: usize, len: usize, base: usize) -> Option<Vec<u8>> {
        let mut out = self.raw(rva, len)?;
        let end = rva + out.len();
        let delta = (base as u64).wrapping_sub(self.image_base);
        if delta == 0 {
            return Some(out);
        }
        // Relocations that start up to 7 bytes before the window still reach
        // into it.
        let first = self.relocations.partition_point(|&(r, _)| r + 8 <= rva);
        for &(reloc, kind) in &self.relocations[first..] {
            if reloc >= end {
                break;
            }
            let width = if kind == IMAGE_REL_BASED_DIR64 { 8 } else { 4 };
            let Some(original) = self.raw(reloc, width) else {
                continue;
            };
            if original.len() < width {
                continue;
            }
            let patched: Vec<u8> = if width == 8 {
                u64::from_le_bytes(original[..8].try_into().ok()?)
                    .wrapping_add(delta)
                    .to_le_bytes()
                    .to_vec()
            } else {
                u32::from_le_bytes(original[..4].try_into().ok()?)
                    .wrapping_add(delta as u32)
                    .to_le_bytes()
                    .to_vec()
            };
            for (i, byte) in patched.iter().enumerate() {
                let at = reloc + i;
                if at >= rva && at < end {
                    out[at - rva] = *byte;
                }
            }
        }
        Some(out)
    }

    fn is_executable(&self, rva: usize) -> bool {
        self.sections.iter().any(|s| {
            s.executable && rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size
        })
    }

    /// An export (by biased `ordinal`) whose live address differs from the
    /// file's export table.
    fn export_redirect(&self, base: usize, ordinal: u32, live: *const u8) -> Option<DetectedHook> {
        let (functions, count, ordinal_base) = self.export_functions?;
        let index = ordinal.checked_sub(ordinal_base)? as usize;
        if index >= count {
            return None;
        }
        let entry = self.raw(functions + index * 4, 4)?;
        let file_rva = u32::from_le_bytes(entry[..4].try_into().ok()?) as usize;
        let live_rva = (live as usize).wrapping_sub(base);
        if file_rva == live_rva || is_system_export(live) {
            return None;
        }
        Some(DetectedHook {
            kind: DetectedHookKind::ExportRedirect,
            address: (base + functions + index * 4) as *const u8,
            function: None,
            destination: Some(live),
            destination_module: module_name_of(live),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify_bytes(code: &[u8]) -> DetectedHook {
        classify(code.as_ptr(), code)
    }

    #[test]
    fn classifies_patch_patterns() {
        assert_eq!(
            classify_bytes(&[0xCC, 0x90, 0x90]).kind,
            DetectedHookKind::Breakpoint
        );
        assert_eq!(
            classify_bytes(&[0x90, 0x90, 0x90]).kind,
            DetectedHookKind::ModifiedCode
        );

        // jmp rel32 to the byte after it: a jump whose destination is known.
        let jmp = classify_bytes(&[0xE9, 0x00, 0x00, 0x00, 0x00, 0xC3]);
        assert_eq!(jmp.kind, DetectedHookKind::InlineJump);
        assert!(jmp.destination.is_some());

        // push imm32; ret
        let push_ret = classify_bytes(&[0x68, 0x78, 0x56, 0x34, 0x12, 0xC3]);
        assert_eq!(push_ret.kind, DetectedHookKind::InlineJump);
        assert_eq!(push_ret.destination, Some(0x1234_5678 as *const u8));

        // push imm32 not followed by ret is not a jump.
        assert_eq!(
            classify_bytes(&[0x68, 0x78, 0x56, 0x34, 0x12, 0x90]).kind,
            DetectedHookKind::ModifiedCode
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn classifies_register_jumps() {
        // mov rax, imm64; jmp rax
        let hook = classify_bytes(&[
            0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xFF, 0xE0,
        ]);
        assert_eq!(hook.kind, DetectedHookKind::InlineJump);
        assert_eq!(hook.destination, Some(0x1122_3344_5566_7788 as *const u8));

        // mov rax, imm64; jmp rcx: a different register is no jump through it.
        let hook = classify_bytes(&[
            0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xFF, 0xE1,
        ]);
        assert_eq!(hook.kind, DetectedHookKind::ModifiedCode);
    }

    #[cfg(target_arch = "x86")]
    #[test]
    fn classifies_register_jumps() {
        // mov eax, imm32; jmp eax
        let hook = classify_bytes(&[0xB8, 0x78, 0x56, 0x34, 0x12, 0xFF, 0xE0]);
        assert_eq!(hook.kind, DetectedHookKind::InlineJump);
        assert_eq!(hook.destination, Some(0x1234_5678 as *const u8));
    }

    /// An image with one section at RVA 0x1000 holding `code`, its file data at
    /// offset 0x200, preferred base 0x10000, and the given relocations.
    fn synthetic(code: &[u8], relocations: Vec<(usize, u16)>) -> DiskImage {
        let mut bytes = vec![0u8; 0x200];
        bytes.extend_from_slice(code);
        DiskImage {
            bytes,
            sections: vec![Section {
                virtual_address: 0x1000,
                virtual_size: 0x1000,
                raw_offset: 0x200,
                raw_size: code.len(),
                executable: true,
            }],
            image_base: 0x10000,
            relocations,
            export_functions: None,
        }
    }

    #[test]
    fn read_applies_relocations_for_the_load_base() {
        // mov eax, [0x00012345] with its address relocated (HIGHLOW at +1).
        let image = synthetic(
            &[0xA1, 0x45, 0x23, 0x01, 0x00, 0xC3],
            vec![(0x1001, IMAGE_REL_BASED_HIGHLOW)],
        );
        assert_eq!(
            image.read(0x1000, 6, 0x10000).unwrap(),
            [0xA1, 0x45, 0x23, 0x01, 0x00, 0xC3],
            "at the preferred base nothing moves"
        );
        assert_eq!(
            image.read(0x1000, 6, 0x30000).unwrap(),
            [0xA1, 0x45, 0x23, 0x03, 0x00, 0xC3],
            "loaded 0x20000 higher"
        );
        // A window that starts inside the relocated value.
        assert_eq!(image.read(0x1003, 3, 0x30000).unwrap(), [0x03, 0x00, 0xC3]);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn read_applies_dir64_relocations() {
        let image = synthetic(
            &[0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00],
            vec![(0x1000, IMAGE_REL_BASED_DIR64)],
        );
        let moved = image.read(0x1000, 8, 0x7FF0_0000_0000).unwrap();
        assert_eq!(
            u64::from_le_bytes(moved.try_into().unwrap()),
            0x11000u64.wrapping_add(0x7FF0_0000_0000 - 0x10000)
        );
    }

    #[test]
    fn read_zero_fills_past_the_raw_data() {
        let image = synthetic(&[0xC3], vec![]);
        assert_eq!(image.read(0x1000, 4, 0x10000).unwrap(), [0xC3, 0, 0, 0]);
        assert!(
            image.read(0x5000, 4, 0x10000).is_none(),
            "outside every section"
        );
    }

    #[test]
    fn parse_rejects_non_images() {
        assert!(DiskImage::parse(Vec::new()).is_none());
        assert!(DiskImage::parse(vec![0x4D, 0x5A, 0, 0]).is_none());
        let mut bytes = vec![0u8; 0x100];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3C] = 0x40;
        assert!(DiskImage::parse(bytes).is_none(), "no PE signature");
    }

    #[test]
    fn parses_the_file_of_a_loaded_module() {
        let kernel32 = crate::get_module_handle("kernel32.dll").unwrap();
        let image = DiskImage::load(kernel32).expect("kernel32 file");
        assert!(image.sections.iter().any(|s| s.executable));
        assert!(image.export_functions.is_some());
        let entry = crate::find_function("kernel32.dll", "GetTickCount").unwrap();
        assert!(image.is_executable(entry as usize - kernel32 as usize));
    }
}
