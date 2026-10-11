// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! x64 unwind data for neohook's executable stubs.
//!
//! x64 Windows unwinds a stack - for an exception, a debugger's call stack,
//! `RtlCaptureStackBackTrace`, a profiler - through table-based unwind data:
//! every frame's instruction pointer must lie in a function with a
//! `RUNTIME_FUNCTION` entry describing what its prologue did to the stack. A
//! trampoline or gateway runs a relocated copy of the target's prologue in
//! memory neohook allocated, which has no such entry. While a call made by
//! those stolen instructions is running, its return address points into the
//! stub; the unwinder then treats the stub as a leaf, reads the wrong return
//! address and the walk ends there - or an exception cannot be dispatched past
//! it.
//!
//! Each stub therefore gets an entry derived from the target's own unwind
//! data. The prologue's unwind codes are kept for the instructions the stub
//! runs, with their offsets translated through the relocation map, since a
//! relocated instruction can change length. Codes for prologue instructions
//! the stub does not run (they execute in the original body after the jump
//! back) are dropped. The entry and its unwind info live in a reserved area at
//! the end of the stub's allocation and are registered with
//! `RtlAddFunctionTable`; [`crate::reclaim`] deletes the table before the
//! allocation is released.
//!
//! x86 unwinds through frame-pointer chains and exception registration
//! records, not tables, so there everything here is a no-op.

/// Bytes reserved at the end of a stub allocation for its unwind data.
#[cfg(target_arch = "x86_64")]
pub(crate) const UNWIND_AREA: usize = 128;
#[cfg(target_arch = "x86")]
pub(crate) const UNWIND_AREA: usize = 0;

#[cfg(target_arch = "x86_64")]
pub(crate) use imp::*;

#[cfg(target_arch = "x86")]
mod imp_x86 {
    use crate::disasm::RelocationMapping;

    /// No table-based unwinding on x86.
    pub(crate) unsafe fn register_relocated(
        _target: *const u8,
        _region: *mut u8,
        _area_offset: usize,
        _code_offset: usize,
        _mapping: &RelocationMapping,
        _stolen_len: usize,
    ) {
    }

    pub(crate) fn suspend(_bases: &[usize]) {}

    pub(crate) fn settle(_bases: &[usize], _still_busy: &[usize]) {}
}

#[cfg(target_arch = "x86")]
pub(crate) use imp_x86::*;

#[cfg(target_arch = "x86_64")]
mod imp {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use windows_sys::Win32::System::Diagnostics::Debug::{
        IMAGE_RUNTIME_FUNCTION_ENTRY, RtlAddFunctionTable, RtlDeleteFunctionTable,
        RtlLookupFunctionEntry,
    };

    use super::UNWIND_AREA;
    use crate::disasm::RelocationMapping;

    const UNW_FLAG_CHAININFO: u8 = 0x4;

    const UWOP_PUSH_NONVOL: u8 = 0;
    const UWOP_ALLOC_LARGE: u8 = 1;
    const UWOP_ALLOC_SMALL: u8 = 2;
    const UWOP_SET_FPREG: u8 = 3;
    const UWOP_SAVE_NONVOL: u8 = 4;
    const UWOP_SAVE_NONVOL_FAR: u8 = 5;
    /// `UWOP_EPILOG` in version 2 unwind info, `UWOP_SAVE_XMM` in version 1.
    const UWOP_EPILOG_OR_SAVE_XMM: u8 = 6;
    /// `UWOP_SPARE_CODE` in version 2, `UWOP_SAVE_XMM_FAR` in version 1.
    const UWOP_SPARE_OR_SAVE_XMM_FAR: u8 = 7;
    const UWOP_SAVE_XMM128: u8 = 8;
    const UWOP_SAVE_XMM128_FAR: u8 = 9;
    const UWOP_PUSH_MACHFRAME: u8 = 10;

    /// A stub's table entry and whether it is currently registered.
    struct Table {
        entry: usize,
        registered: bool,
    }

    /// Registered stub tables by allocation base.
    static TABLES: Mutex<Option<HashMap<usize, Table>>> = Mutex::new(None);

    fn with_tables<R>(f: impl FnOnce(&mut HashMap<usize, Table>) -> R) -> R {
        let mut guard = TABLES.lock().unwrap_or_else(|p| p.into_inner());
        f(guard.get_or_insert_with(HashMap::new))
    }

    /// Writes and registers the unwind data of a stub holding the relocated
    /// prologue of `target`.
    ///
    /// `region` is the stub allocation; the relocated code starts at
    /// `region + code_offset` and was produced by `mapping` from `stolen_len`
    /// bytes at `target`. The unwind data is written at `region + area_offset`,
    /// where [`UNWIND_AREA`] bytes must be writable. Nothing is registered if
    /// the target has no unwind data, or data this cannot translate (a chained
    /// entry, more codes than fit).
    ///
    /// # Safety
    ///
    /// `region` must be a live stub allocation, writable for
    /// `area_offset + UNWIND_AREA` bytes, and `target` the code `mapping` was
    /// built from.
    pub(crate) unsafe fn register_relocated(
        target: *const u8,
        region: *mut u8,
        area_offset: usize,
        code_offset: usize,
        mapping: &RelocationMapping,
        stolen_len: usize,
    ) {
        let Some(codes) = (unsafe { translate(target, mapping, stolen_len) }) else {
            return;
        };
        let info_offset = area_offset + std::mem::size_of::<IMAGE_RUNTIME_FUNCTION_ENTRY>();
        let info_len = 4 + codes.slots.len().next_multiple_of(2) * 2;
        if info_offset - area_offset + info_len > UNWIND_AREA {
            return;
        }

        unsafe {
            let info = region.add(info_offset);
            // Version 1, no flags: handlers and epilogue descriptions belong to
            // the original function, not to the stub.
            info.write(1);
            info.add(1).write(codes.prolog_size);
            info.add(2).write(codes.slots.len() as u8);
            info.add(3).write(codes.frame);
            let slots = info.add(4) as *mut u16;
            for (i, slot) in codes.slots.iter().enumerate() {
                slots.add(i).write_unaligned(*slot);
            }
            if codes.slots.len() % 2 == 1 {
                slots.add(codes.slots.len()).write_unaligned(0);
            }

            let entry = region.add(area_offset) as *mut IMAGE_RUNTIME_FUNCTION_ENTRY;
            entry.write(std::mem::zeroed());
            (*entry).BeginAddress = code_offset as u32;
            (*entry).EndAddress = (code_offset + mapping.written_len) as u32;
            (*entry).Anonymous.UnwindData = info_offset as u32;

            if RtlAddFunctionTable(entry, 1, region as u64) {
                with_tables(|tables| {
                    tables.insert(
                        region as usize,
                        Table {
                            entry: entry as usize,
                            registered: true,
                        },
                    )
                });
            }
        }
    }

    /// Unwind codes translated for a stub.
    struct Translated {
        slots: Vec<u16>,
        prolog_size: u8,
        /// `FrameRegister | FrameOffset << 4`.
        frame: u8,
    }

    /// Translates the unwind codes of the function containing `target` to the
    /// stub `mapping` describes.
    unsafe fn translate(
        target: *const u8,
        mapping: &RelocationMapping,
        stolen_len: usize,
    ) -> Option<Translated> {
        let mut image_base = 0u64;
        let function =
            unsafe { RtlLookupFunctionEntry(target as u64, &mut image_base, std::ptr::null_mut()) };
        if function.is_null() {
            // A leaf function: no frame, nothing to describe.
            return None;
        }
        let function = unsafe { &*function };
        let info = (image_base + unsafe { function.Anonymous.UnwindData } as u64) as *const u8;
        let header = unsafe { std::slice::from_raw_parts(info, 4) };
        let version = header[0] & 0x7;
        let flags = header[0] >> 3;
        if flags & UNW_FLAG_CHAININFO != 0 || !(1..=2).contains(&version) {
            return None;
        }
        let count = header[2] as usize;
        let mut frame = header[3];
        let source = unsafe { std::slice::from_raw_parts(info.add(4) as *const u16, count) };

        // Where the stub starts within its function.
        let delta = (target as u64).checked_sub(image_base + function.BeginAddress as u64)?;

        let mut slots = Vec::new();
        let mut prolog_size = 0u8;
        let mut i = 0;
        while i < count {
            let code = source[i];
            let offset = (code & 0xFF) as u64;
            let op = ((code >> 8) & 0xF) as u8;
            let op_info = (code >> 12) as u8;
            let len = match op {
                UWOP_PUSH_NONVOL | UWOP_ALLOC_SMALL | UWOP_SET_FPREG | UWOP_PUSH_MACHFRAME => 1,
                UWOP_ALLOC_LARGE if op_info == 0 => 2,
                UWOP_ALLOC_LARGE => 3,
                UWOP_SAVE_NONVOL | UWOP_SAVE_XMM128 => 2,
                UWOP_SAVE_NONVOL_FAR | UWOP_SAVE_XMM128_FAR => 3,
                UWOP_EPILOG_OR_SAVE_XMM if version == 2 => 1,
                UWOP_EPILOG_OR_SAVE_XMM => 2,
                UWOP_SPARE_OR_SAVE_XMM_FAR if version == 2 => 2,
                UWOP_SPARE_OR_SAVE_XMM_FAR => 3,
                _ => return None,
            };
            if i + len > count {
                return None;
            }
            // Epilogue descriptions do not apply to the stub.
            if version == 2 && matches!(op, UWOP_EPILOG_OR_SAVE_XMM | UWOP_SPARE_OR_SAVE_XMM_FAR) {
                i += len;
                continue;
            }

            let new_offset = if offset <= delta {
                // Done before the stub's first instruction: always in effect.
                Some(0)
            } else {
                let relative = (offset - delta) as u32;
                if relative as usize > stolen_len {
                    // Runs in the original body, after the stub.
                    None
                } else if relative as usize == stolen_len {
                    Some(mapping.jmp_back_offset)
                } else {
                    let index = mapping
                        .old_instruction_offsets
                        .iter()
                        .position(|&o| o == relative)?;
                    Some(mapping.new_instruction_offsets[index])
                }
            };
            match new_offset {
                Some(new_offset) => {
                    let new_offset = u8::try_from(new_offset).ok()?;
                    prolog_size = prolog_size.max(new_offset);
                    slots.push((code & 0xFF00) | new_offset as u16);
                    slots.extend_from_slice(&source[i + 1..i + len]);
                }
                None if op == UWOP_SET_FPREG => {
                    // The frame pointer is not set up yet anywhere in the stub.
                    frame = 0;
                }
                None => {}
            }
            i += len;
        }

        Some(Translated {
            slots,
            prolog_size,
            frame,
        })
    }

    /// Deletes the tables of the stub allocations at `bases` before they may be
    /// released. Runs before any thread is suspended: the function table lock
    /// could be held by a frozen thread.
    pub(crate) fn suspend(bases: &[usize]) {
        with_tables(|tables| {
            for base in bases {
                if let Some(table) = tables.get_mut(base)
                    && table.registered
                {
                    unsafe {
                        RtlDeleteFunctionTable(table.entry as *const IMAGE_RUNTIME_FUNCTION_ENTRY)
                    };
                    table.registered = false;
                }
            }
        });
    }

    /// After a release pass: forgets the tables of the allocations that were
    /// released and registers the others (`still_busy`) again.
    pub(crate) fn settle(bases: &[usize], still_busy: &[usize]) {
        with_tables(|tables| {
            for base in bases {
                if still_busy.contains(base) {
                    if let Some(table) = tables.get_mut(base)
                        && !table.registered
                    {
                        table.registered = unsafe {
                            RtlAddFunctionTable(
                                table.entry as *const IMAGE_RUNTIME_FUNCTION_ENTRY,
                                1,
                                *base as u64,
                            )
                        };
                    }
                } else {
                    tables.remove(base);
                }
            }
        });
    }
}
