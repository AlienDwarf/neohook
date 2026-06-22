// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pattern (signature) scanning and signature-based hook resolution.
//!
//! Direct pointers and module/export names only get you so far: many hook
//! targets are *unexported, statically-linked, or stripped* functions whose
//! address changes between builds. The reliable way to find them at runtime is
//! a byte **signature** - a short run of opcode bytes with wildcards covering
//! the parts that move (relative offsets, absolute addresses, register
//! encodings).
//!
//! This module makes that a first-class operation:
//!
//! - [`Pattern`] parses both common signature dialects:
//!   - **IDA / x64dbg style**: a string like `"48 8B 05 ?? ?? ?? ?? E8"` where
//!     `?` / `??` are wildcard bytes.
//!   - **Code + mask style**: a byte
//!     array paired with a mask string such as `(b"\x48\x8B\x00", "xx?")`.
//! - [`scan`] / [`scan_all`] match a pattern against any in-memory byte slice.
//! - [`scan_module`] / [`scan_module_by_name`] resolve a signature inside a
//!   loaded module, walking only committed, executable regions through
//!   [`VirtualQuery`] so a guard page or a hole in the image can never drive a
//!   faulting read.
//!
//! The resolved address can be fed straight into
//! [`crate::DetourTransaction::attach`] - or you can let
//! [`crate::DetourTransaction::attach_pattern`] do both steps in one call.

use crate::pe;
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, LoadLibraryW};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, VirtualQuery,
};

/// All page protections that permit instruction execution.
const EXECUTABLE_FLAGS: u32 =
    PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

/// Errors produced while parsing a byte signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternError {
    /// The signature contained no bytes at all.
    Empty,
    /// A token in an IDA-style signature was neither a wildcard nor a valid
    /// 1-2 digit hexadecimal byte. Carries the offending token.
    InvalidToken(String),
    /// A code-style mask used a character other than a match (`x`/`X`) or a
    /// wildcard (`?`). Carries the offending character.
    InvalidMaskChar(char),
    /// The code-style mask length did not match the byte-array length.
    MaskLengthMismatch {
        /// Number of pattern bytes supplied.
        bytes: usize,
        /// Number of mask characters supplied.
        mask: usize,
    },
}

impl std::fmt::Display for PatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "signature is empty"),
            Self::InvalidToken(tok) => {
                write!(
                    f,
                    "invalid signature token '{tok}' (expected a hex byte or '?')"
                )
            }
            Self::InvalidMaskChar(c) => {
                write!(f, "invalid mask character '{c}' (expected 'x' or '?')")
            }
            Self::MaskLengthMismatch { bytes, mask } => write!(
                f,
                "mask length ({mask}) does not match pattern length ({bytes})"
            ),
        }
    }
}

impl std::error::Error for PatternError {}

/// A parsed byte signature: a sequence of bytes, each either a fixed value that
/// must match exactly or a wildcard that matches any byte.
///
/// Construct one with [`Pattern::parse`] (IDA / x64dbg string syntax) or
/// [`Pattern::from_code_style`] (byte array + mask string).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pattern {
    /// Literal byte values. The value at a wildcard position is unused.
    bytes: Vec<u8>,
    /// Per-byte match flags: `true` means the corresponding `bytes` entry must
    /// match exactly, `false` marks a wildcard.
    mask: Vec<bool>,
}

impl Pattern {
    /// Parses an IDA / x64dbg-style signature string.
    ///
    /// Tokens are separated by whitespace. Each token is either a hexadecimal
    /// byte (`4F`, `8b`, or a single nibble like `8`) or a wildcard (`?` or
    /// `??`). For example:
    ///
    /// ```rust,ignore
    /// let pat = Pattern::parse("48 8B 05 ?? ?? ?? ?? 48 89")?;
    /// ```
    ///
    /// # Errors
    /// Returns [`PatternError::Empty`] for a blank signature, or
    /// [`PatternError::InvalidToken`] for a token that is neither a wildcard nor
    /// a valid hex byte.
    pub fn parse(signature: &str) -> Result<Self, PatternError> {
        let mut bytes = Vec::new();
        let mut mask = Vec::new();

        for token in signature.split_whitespace() {
            if token.bytes().all(|b| b == b'?') {
                // "?" or "??" - a wildcard byte.
                bytes.push(0);
                mask.push(false);
                continue;
            }

            // A fixed hex byte (1 or 2 nibbles).
            if token.len() > 2 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(PatternError::InvalidToken(token.to_string()));
            }
            match u8::from_str_radix(token, 16) {
                Ok(value) => {
                    bytes.push(value);
                    mask.push(true);
                }
                Err(_) => return Err(PatternError::InvalidToken(token.to_string())),
            }
        }

        if bytes.is_empty() {
            return Err(PatternError::Empty);
        }

        Ok(Self { bytes, mask })
    }

    /// Builds a pattern from a raw byte array and a mask string.
    ///
    /// Each character of `mask` corresponds to one byte of `pattern`: `'x'` (or
    /// `'X'`) means the byte must match exactly, `'?'` marks a wildcard. This is
    /// the classic "FindPattern" convention, e.g.
    /// `from_code_style(b"\x48\x8B\x00\x00", "xx??")`.
    ///
    /// # Errors
    /// Returns [`PatternError::Empty`] when `pattern` is empty,
    /// [`PatternError::MaskLengthMismatch`] when the lengths differ, or
    /// [`PatternError::InvalidMaskChar`] for a mask character other than
    /// `x`/`X`/`?`.
    pub fn from_code_style(pattern: &[u8], mask: &str) -> Result<Self, PatternError> {
        if pattern.is_empty() {
            return Err(PatternError::Empty);
        }
        if pattern.len() != mask.chars().count() {
            return Err(PatternError::MaskLengthMismatch {
                bytes: pattern.len(),
                mask: mask.chars().count(),
            });
        }

        let mut mask_flags = Vec::with_capacity(pattern.len());
        for c in mask.chars() {
            match c {
                'x' | 'X' => mask_flags.push(true),
                '?' => mask_flags.push(false),
                other => return Err(PatternError::InvalidMaskChar(other)),
            }
        }

        Ok(Self {
            bytes: pattern.to_vec(),
            mask: mask_flags,
        })
    }

    /// Returns the number of bytes (fixed and wildcard) in the signature.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the signature has no bytes. A successfully parsed
    /// [`Pattern`] is never empty, so this is effectively always `false`.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Tests whether the signature matches `haystack` starting at `offset`.
    #[inline]
    fn matches_at(&self, haystack: &[u8], offset: usize) -> bool {
        // The caller guarantees offset + len <= haystack.len().
        for (j, (&want, &fixed)) in self.bytes.iter().zip(self.mask.iter()).enumerate() {
            if fixed && haystack[offset + j] != want {
                return false;
            }
        }
        true
    }
}

/// Returns the offset of the first occurrence of `pattern` in `haystack`, or
/// `None` if it does not appear.
pub fn scan(haystack: &[u8], pattern: &Pattern) -> Option<usize> {
    let plen = pattern.len();
    if plen == 0 || haystack.len() < plen {
        return None;
    }
    (0..=haystack.len() - plen).find(|&i| pattern.matches_at(haystack, i))
}

/// Returns the offsets of every (possibly overlapping) occurrence of `pattern`
/// in `haystack`.
pub fn scan_all(haystack: &[u8], pattern: &Pattern) -> Vec<usize> {
    let plen = pattern.len();
    if plen == 0 || haystack.len() < plen {
        return Vec::new();
    }
    (0..=haystack.len() - plen)
        .filter(|&i| pattern.matches_at(haystack, i))
        .collect()
}

/// Scans the committed regions inside `[start, start + len)` for `pattern`.
///
/// Only regions that are committed and not `PAGE_NOACCESS` / `PAGE_GUARD` are
/// read; when `executable_only` is set, the region must additionally be
/// executable. Region boundaries are probed with [`VirtualQuery`] so a hole or
/// guard page in the range can never trigger a faulting read. Matches are not
/// detected across a region boundary.
///
/// # Safety
/// `start` must be a value obtained from this process's address space. The
/// scanned bytes may change underneath the scan if other threads are running.
unsafe fn scan_committed(
    start: usize,
    len: usize,
    pattern: &Pattern,
    executable_only: bool,
    first_only: bool,
) -> Vec<*const u8> {
    let mut results: Vec<*const u8> = Vec::new();
    let plen = pattern.len();
    if plen == 0 || len < plen {
        return results;
    }
    let Some(range_end) = start.checked_add(len) else {
        return results;
    };

    let mut cursor = start;
    while cursor < range_end {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let queried = unsafe {
            VirtualQuery(
                cursor as _,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if queried == 0 {
            break;
        }

        let region_base = mbi.BaseAddress as usize;
        let Some(region_end) = region_base.checked_add(mbi.RegionSize) else {
            break;
        };

        let committed = mbi.State == MEM_COMMIT;
        let blocked = (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0;
        let exec_ok = !executable_only || (mbi.Protect & EXECUTABLE_FLAGS) != 0;

        if committed && !blocked && exec_ok {
            // Clamp the scan window to the intersection of this region and the
            // requested range.
            let scan_start = cursor.max(region_base);
            let scan_end = region_end.min(range_end);
            if scan_end > scan_start && scan_end - scan_start >= plen {
                let slice = unsafe {
                    std::slice::from_raw_parts(scan_start as *const u8, scan_end - scan_start)
                };
                if first_only {
                    if let Some(off) = scan(slice, pattern) {
                        results.push((scan_start + off) as *const u8);
                        return results;
                    }
                } else {
                    for off in scan_all(slice, pattern) {
                        results.push((scan_start + off) as *const u8);
                    }
                }
            }
        }

        // Advance past this region; guard against a non-progressing query.
        if region_end <= cursor {
            break;
        }
        cursor = region_end;
    }

    results
}

/// Scans `len` bytes starting at `start` for the first occurrence of `pattern`,
/// limited to committed, readable regions.
///
/// Returns the absolute address of the first match, or `None`.
///
/// # Safety
/// `start` must point into this process's address space (it need not all be
/// committed - holes are skipped). Concurrent writers may change the bytes
/// during the scan.
pub unsafe fn scan_range(start: *const u8, len: usize, pattern: &Pattern) -> Option<*const u8> {
    if start.is_null() {
        return None;
    }
    unsafe { scan_committed(start as usize, len, pattern, false, true) }
        .into_iter()
        .next()
}

/// Scans `len` bytes starting at `start` for every occurrence of `pattern`,
/// limited to committed, readable regions.
///
/// # Safety
/// See [`scan_range`].
pub unsafe fn scan_range_all(start: *const u8, len: usize, pattern: &Pattern) -> Vec<*const u8> {
    if start.is_null() {
        return Vec::new();
    }
    unsafe { scan_committed(start as usize, len, pattern, false, false) }
}

/// Resolves a signature inside a loaded module, returning the address of the
/// first match in the module's executable regions.
///
/// The module headers are validated through [`crate::pe`], and only committed,
/// executable regions within the image are scanned - the natural home of the
/// code a signature describes. Returns `None` if the module is invalid or the
/// signature does not appear.
///
/// # Safety
/// `h_module` must be the base address of a PE image currently mapped in this
/// process and must stay loaded for the duration of the call.
pub unsafe fn scan_module(h_module: HMODULE, pattern: &Pattern) -> Option<*const u8> {
    let image = pe::parse_module_image(h_module).ok()?;
    unsafe { scan_committed(image.base_address, image.size, pattern, true, true) }
        .into_iter()
        .next()
}

/// Resolves a signature inside a loaded module, returning every match in the
/// module's executable regions.
///
/// # Safety
/// See [`scan_module`].
pub unsafe fn scan_module_all(h_module: HMODULE, pattern: &Pattern) -> Vec<*const u8> {
    let Ok(image) = pe::parse_module_image(h_module) else {
        return Vec::new();
    };
    unsafe { scan_committed(image.base_address, image.size, pattern, true, false) }
}

/// Resolves a signature inside a module identified by name, loading the module
/// if it is not already present (mirroring [`crate::find_function`]).
///
/// Returns the address of the first match in the module's executable regions,
/// or `None` if the module cannot be found/loaded or the signature does not
/// appear.
pub fn scan_module_by_name(module_name: &str, pattern: &Pattern) -> Option<*const u8> {
    let module_name_wide: Vec<u16> = module_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let h_module = unsafe {
        let mut h = GetModuleHandleW(module_name_wide.as_ptr());
        if h.is_null() {
            h = LoadLibraryW(module_name_wide.as_ptr());
        }
        h
    };

    if h_module.is_null() {
        return None;
    }

    unsafe { scan_module(h_module, pattern) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ida_style_with_wildcards() {
        let pat = Pattern::parse("48 8B ?? ?? E8").expect("valid signature");
        assert_eq!(pat.len(), 5);
        assert_eq!(pat.bytes, vec![0x48, 0x8B, 0, 0, 0xE8]);
        assert_eq!(pat.mask, vec![true, true, false, false, true]);
    }

    #[test]
    fn parse_accepts_single_nibble_and_lowercase() {
        let pat = Pattern::parse("8 ab CD").expect("valid signature");
        assert_eq!(pat.bytes, vec![0x08, 0xAB, 0xCD]);
        assert!(pat.mask.iter().all(|&m| m));
    }

    #[test]
    fn parse_rejects_empty_and_garbage() {
        assert_eq!(Pattern::parse("   "), Err(PatternError::Empty));
        assert!(matches!(
            Pattern::parse("48 ZZ"),
            Err(PatternError::InvalidToken(_))
        ));
        assert!(matches!(
            Pattern::parse("48 8BB"),
            Err(PatternError::InvalidToken(_))
        ));
    }

    #[test]
    fn from_code_style_matches_ida_equivalent() {
        let code = Pattern::from_code_style(b"\x48\x8B\x00\x00\xE8", "xx??x").unwrap();
        let ida = Pattern::parse("48 8B ?? ?? E8").unwrap();
        assert_eq!(code, ida);
    }

    #[test]
    fn from_code_style_validates_inputs() {
        assert_eq!(
            Pattern::from_code_style(b"", "").unwrap_err(),
            PatternError::Empty
        );
        assert!(matches!(
            Pattern::from_code_style(b"\x48", "xx"),
            Err(PatternError::MaskLengthMismatch { bytes: 1, mask: 2 })
        ));
        assert!(matches!(
            Pattern::from_code_style(b"\x48", "y"),
            Err(PatternError::InvalidMaskChar('y'))
        ));
    }

    #[test]
    fn scan_finds_first_and_all_with_wildcards() {
        let haystack = [0x90u8, 0x48, 0x8B, 0xC1, 0xE8, 0x48, 0x8B, 0xD2, 0xE8];
        let pat = Pattern::parse("48 8B ?? E8").unwrap();

        assert_eq!(scan(&haystack, &pat), Some(1));
        assert_eq!(scan_all(&haystack, &pat), vec![1, 5]);
    }

    #[test]
    fn scan_returns_none_when_absent_or_too_short() {
        let haystack = [0x00u8, 0x11, 0x22];
        let pat = Pattern::parse("48 8B").unwrap();
        assert_eq!(scan(&haystack, &pat), None);

        let short = [0x48u8];
        assert_eq!(scan(&short, &pat), None);
    }

    #[test]
    fn scan_module_resolves_known_kernel32_prologue() {
        // Build a signature from the actual first bytes of an exported
        // function, then confirm the module scan finds that very address.
        let target = crate::module::find_function("kernel32.dll", "GetProcAddress")
            .expect("GetProcAddress should resolve");

        let prologue = unsafe { std::slice::from_raw_parts(target, 12) };
        let pat = Pattern {
            bytes: prologue.to_vec(),
            mask: vec![true; prologue.len()],
        };

        let h = crate::module::get_module_handle("kernel32.dll").expect("kernel32 handle");
        let found = unsafe { scan_module(h, &pat) }.expect("signature should be found");

        assert_eq!(found, target);
    }

    #[test]
    fn scan_module_by_name_returns_none_for_absent_signature() {
        // A signature this long is overwhelmingly unlikely to occur by chance.
        let pat = Pattern::parse("DE AD BE EF DE AD BE EF DE AD BE EF DE AD BE EF").unwrap();
        assert!(scan_module_by_name("kernel32.dll", &pat).is_none());
    }

    #[test]
    fn scan_module_by_name_handles_missing_module() {
        let pat = Pattern::parse("90").unwrap();
        assert!(scan_module_by_name("fantasy_dll_999.dll", &pat).is_none());
    }
}
