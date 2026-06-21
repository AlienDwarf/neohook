// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Symbol-based target resolution via the Debug Help library (`dbghelp`).
//!
//! [`crate::find_function`] resolves a target through the export table, and
//! [`crate::scan`] resolves one through a byte signature. Both fail on a
//! function that is **not exported** - an internal routine, a `static` helper,
//! a stripped-but-symbol-bearing build. When a PDB is available (next to the
//! binary, or via a symbol server / `_NT_SYMBOL_PATH`), `dbghelp` can map such a
//! name straight to an address.
//!
//! [`resolve_symbol`] takes a module and a symbol name and returns the absolute
//! address, e.g.
//!
//! ```rust,ignore
//! // Hook a private ntdll routine by name (requires ntdll symbols).
//! if let Some(addr) = neohook::resolve_symbol("ntdll.dll", "LdrpInitializeProcess") {
//!     // feed `addr` straight into DetourTransaction::attach
//! }
//! ```
//!
//! Even **without** a PDB, `dbghelp` synthesizes symbols from a module's export
//! table, so `resolve_symbol("kernel32.dll", "GetProcAddress")` resolves the
//! same address [`crate::find_function`] would - this module simply also reaches
//! the names a PDB adds on top.
//!
//! `dbghelp` is single-threaded by contract, so every call here is serialized
//! through one process-wide lock.

use std::sync::{Mutex, MutexGuard};
use windows_sys::Win32::Foundation::{HANDLE, HMODULE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    SYMBOL_INFOW, SYMOPT_DEFERRED_LOADS, SYMOPT_FAIL_CRITICAL_ERRORS, SYMOPT_UNDNAME, SymFromNameW,
    SymInitializeW, SymLoadModuleExW, SymSetOptions,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleFileNameW, GetModuleHandleW, LoadLibraryW,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use crate::module::get_module_size;

/// Upper bound on a decorated symbol name, per the `dbghelp` convention.
const MAX_SYM_NAME: usize = 2000;
/// Buffer length for `GetModuleFileNameW`.
const MAX_PATH_LEN: usize = 260;

/// Process-wide `dbghelp` state, guarded by a single lock because the library is
/// not thread-safe.
struct DbgHelp {
    /// Whether `SymInitializeW` has run successfully.
    initialized: bool,
    /// Base addresses already handed to `SymLoadModuleExW`, so each module's
    /// symbol table is loaded at most once.
    loaded: Vec<usize>,
}

static STATE: Mutex<DbgHelp> = Mutex::new(DbgHelp {
    initialized: false,
    loaded: Vec::new(),
});

/// Recovers the lock even if a previous holder panicked; the guarded state
/// carries no invariant a panic could corrupt.
fn lock() -> MutexGuard<'static, DbgHelp> {
    STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Resolves `symbol` within `module` to its absolute address using `dbghelp`.
///
/// The module is loaded into the process if necessary (mirroring
/// [`crate::find_function`]), and its symbol table is loaded into `dbghelp` on
/// first use. Resolution finds both PDB symbols (when symbols are available) and
/// export-table names.
///
/// Returns `None` if `dbghelp` cannot initialize, the module cannot be found or
/// loaded, or the symbol is unknown.
///
/// # Parameters
/// - `module`: module file name (e.g. `"ntdll.dll"`) or full path.
/// - `symbol`: undecorated symbol name (e.g. `"RtlAllocateHeap"`).
pub fn resolve_symbol(module: &str, symbol: &str) -> Option<*const u8> {
    if module.is_empty() || symbol.is_empty() {
        return None;
    }

    let mut state = lock();
    let process = unsafe { GetCurrentProcess() };

    if !state.initialized {
        unsafe {
            SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_FAIL_CRITICAL_ERRORS);
            // fInvadeProcess = FALSE: load each module explicitly below so the
            // base/size always match the in-process image.
            if SymInitializeW(process, std::ptr::null(), 0) == 0 {
                return None;
            }
        }
        state.initialized = true;
    }

    let h_module = load_process_module(module)?;
    ensure_sym_module(&mut state, process, h_module, module);

    // `dbghelp` keys names by the module's base name without extension.
    let base_name = module_basename_no_ext(module);
    let query = format!("{base_name}!{symbol}");
    sym_from_name(process, &query)
}

/// Returns a handle to `module`, loading it if it is not already mapped.
fn load_process_module(module: &str) -> Option<HMODULE> {
    let wide: Vec<u16> = module.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let mut h = GetModuleHandleW(wide.as_ptr());
        if h.is_null() {
            h = LoadLibraryW(wide.as_ptr());
        }
        if h.is_null() { None } else { Some(h) }
    }
}

/// Registers a module's symbol table with `dbghelp` exactly once per base.
fn ensure_sym_module(state: &mut DbgHelp, process: HANDLE, h_module: HMODULE, module: &str) {
    let base = h_module as usize;
    if state.loaded.contains(&base) {
        return;
    }

    let size = get_module_size(h_module);

    // Prefer the on-disk path as the image name so `dbghelp` can locate a PDB;
    // fall back to the supplied module string if the path cannot be read.
    let mut path_buf = [0u16; MAX_PATH_LEN];
    let n = unsafe { GetModuleFileNameW(h_module, path_buf.as_mut_ptr(), path_buf.len() as u32) };
    let image_name: Vec<u16> = if n == 0 || n as usize >= path_buf.len() {
        module.encode_utf16().chain(std::iter::once(0)).collect()
    } else {
        path_buf[..=n as usize].to_vec()
    };

    unsafe {
        // Returns the module base on success, or 0 if already loaded / failed -
        // either way there is nothing to roll back, and we record the attempt.
        SymLoadModuleExW(
            process,
            std::ptr::null_mut(),
            image_name.as_ptr(),
            std::ptr::null(),
            base as u64,
            size,
            std::ptr::null(),
            0,
        );
    }

    state.loaded.push(base);
}

/// Looks up a `module!symbol` query through `SymFromNameW`.
fn sym_from_name(process: HANDLE, query: &str) -> Option<*const u8> {
    // SYMBOL_INFOW is followed by a variable-length name buffer; over-allocate
    // as `u64` so the struct's 8-byte-aligned fields are correctly aligned.
    let bytes = std::mem::size_of::<SYMBOL_INFOW>() + MAX_SYM_NAME * 2;
    let mut buf = vec![0u64; bytes.div_ceil(std::mem::size_of::<u64>())];
    let info = buf.as_mut_ptr() as *mut SYMBOL_INFOW;
    unsafe {
        (*info).SizeOfStruct = std::mem::size_of::<SYMBOL_INFOW>() as u32;
        (*info).MaxNameLen = MAX_SYM_NAME as u32;
    }

    let wide: Vec<u16> = query.encode_utf16().chain(std::iter::once(0)).collect();
    let ok = unsafe { SymFromNameW(process, wide.as_ptr(), info) };
    if ok == 0 {
        return None;
    }

    let address = unsafe { (*info).Address };
    if address == 0 {
        None
    } else {
        Some(address as *const u8)
    }
}

/// Strips any directory and file extension, yielding the name `dbghelp` uses to
/// key symbols (e.g. `"C:\\win\\ntdll.dll"` -> `"ntdll"`).
fn module_basename_no_ext(module: &str) -> String {
    let name = module.rsplit(['\\', '/']).next().unwrap_or(module);
    match name.rfind('.') {
        Some(dot) => name[..dot].to_string(),
        None => name.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_an_exported_symbol_to_the_export_address() {
        // Even without a PDB, dbghelp synthesizes symbols from the export table,
        // so this must agree with the GetProcAddress-based resolver.
        let via_sym = resolve_symbol("kernel32.dll", "GetProcAddress")
            .expect("dbghelp should resolve a well-known kernel32 export");
        let via_export = crate::module::find_function("kernel32.dll", "GetProcAddress")
            .expect("GetProcAddress must exist");
        assert_eq!(via_sym, via_export, "symbol address must match the export");
    }

    #[test]
    fn unknown_symbol_returns_none() {
        assert!(
            resolve_symbol("kernel32.dll", "DefinitelyNotASymbol_zzz_123").is_none(),
            "an unknown symbol must resolve to None"
        );
    }

    #[test]
    fn missing_module_returns_none() {
        assert!(
            resolve_symbol("fantasy_dll_999.dll", "Whatever").is_none(),
            "a missing module must resolve to None"
        );
    }

    #[test]
    fn empty_inputs_return_none() {
        assert!(resolve_symbol("", "GetProcAddress").is_none());
        assert!(resolve_symbol("kernel32.dll", "").is_none());
    }

    #[test]
    fn basename_strips_path_and_extension() {
        assert_eq!(module_basename_no_ext("kernel32.dll"), "kernel32");
        assert_eq!(
            module_basename_no_ext("C:\\Windows\\System32\\ntdll.dll"),
            "ntdll"
        );
        assert_eq!(module_basename_no_ext("no_extension"), "no_extension");
    }
}
