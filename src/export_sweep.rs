// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Real-world relocation sweep.
//!
//! Walk the exports of the major
//! system DLLs and runs each prologue through the exact path an inline hook
//! takes - [`Disassembler::get_instruction_len`] followed by
//! [`Disassembler::relocate`] into a *nearby* trampoline
//!
//! It is deliberately read-only: it never installs a jump into a live OS
//! function (that would redirect callers inside the test process and crash it)
//! and never executes the relocated bytes. The end-to-end "execute the
//! trampoline + verify exact byte restore" guarantee is covered separately by
//! the curated `tests/export_roundtrip.rs` integration test against functions
//! that are safe to call.
//!
//! ## Failure policy
//!
//! The relocator must never *panic* or *overflow its buffer* on a real
//! prologue - those are crashes, and they hard-fail the test. A graceful
//! `Err` (e.g. iced refusing a short-only branch that is out of range, or an
//! address that turned out not to be code) is *reported* but tolerated: those
//! vary with the OS and are intentional `RelocationFailed` outcomes, not bugs.
//! A catastrophic relocator regression is still caught by a coverage floor:
//! the vast majority of executable prologues must relocate cleanly.

use crate::code::detour_code_from_pointer;
use crate::disasm::Disassembler;
use crate::introspect::enumerate_exports;
use crate::module::get_module_handle;

use std::panic::{AssertUnwindSafe, catch_unwind};

use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, VirtualQuery,
};

use crate::alloc::TrampolineAlloc;

/// Modules whose entire export table we sweep. These are the most important dlls with around >10k exports intotal
const SWEEP_MODULES: &[&str] = &[
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "user32.dll",
    "gdi32.dll",
    "advapi32.dll",
    "ole32.dll",
    "oleaut32.dll",
    "shell32.dll",
    "shlwapi.dll",
    "ws2_32.dll",
    "msvcrt.dll",
];

/// Minimum prologue size an inline hook needs for the common near-jump path
/// (`JMP rel32`). This mirrors `required_space` in `transaction.rs` for the
/// `Relative5` case, which is the dominant real-world path.
const REQUIRED_SPACE: usize = 5;

/// Trampoline page allocated near each module; large enough that no single
/// relocated prologue can overrun it.
const TRAMPOLINE_CAP: usize = 4096;

/// neohook's real per-hook trampoline body budget (see `tramp_capacity` minus
/// the managed-gateway stub in `transaction.rs`). Relocations larger than this
/// would be rejected by the real hook path, so we track them separately.
const REAL_BUDGET: usize = 128 - 16;

#[derive(Default)]
struct Stats {
    swept: usize,
    relocated: usize,
    skipped_not_code: usize,
    skipped_undecodable: usize,
    refused: usize,
    exceeds_real_budget: usize,
    /// Hard failures: panics or buffer-budget violations. Each entry is a
    /// human-readable diagnostic. The test fails if this is non-empty.
    crashes: Vec<String>,
    /// A few sampled graceful refusals, purely for the human-readable report.
    refusal_samples: Vec<String>,
}

/// Returns true when `addr` points into committed, executable memory i.e. it
/// is code, not an exported data symbol sitting in `.rdata`.
unsafe fn is_executable(addr: *const u8) -> bool {
    const EXEC: u32 =
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let written = unsafe {
        VirtualQuery(
            addr.cast(),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if written == 0 {
        return false;
    }
    mbi.State == MEM_COMMIT && (mbi.Protect & EXEC) != 0
}

/// Loads `name` (idempotent if already mapped) and returns its base handle.
fn ensure_loaded(name: &str) -> Option<windows_sys::Win32::Foundation::HMODULE> {
    if let Some(h) = get_module_handle(name) {
        return Some(h);
    }
    let c_name = std::ffi::CString::new(name).ok()?;
    // LoadLibraryA bumps the refcount; we intentionally leak it for the
    // lifetime of the test process.
    let handle = unsafe { LoadLibraryA(c_name.as_ptr().cast()) };
    if handle.is_null() {
        return None;
    }
    get_module_handle(name)
}

fn first_bytes(code: *const u8, len: usize) -> Vec<u8> {
    let n = len.min(16);
    unsafe { std::slice::from_raw_parts(code, n).to_vec() }
}

fn sweep_module(name: &str, tramp: *mut u8, stats: &mut Stats) {
    let Some(handle) = ensure_loaded(name) else {
        eprintln!("  [skip] {name}: not present / could not be loaded");
        return;
    };

    let exports = match unsafe { enumerate_exports(handle) } {
        Ok(exports) => exports,
        Err(err) => {
            eprintln!("  [skip] {name}: enumerate_exports failed: {err:?}");
            return;
        }
    };

    for export in exports {
        // Forwarded exports ("DLL.Func") have no local code to relocate.
        if export.forwarder.is_some() {
            continue;
        }
        if export.address.is_null() {
            continue;
        }

        // Follow import/incremental-link thunks to the real entry, exactly as
        // the hook path does.
        let code = unsafe { detour_code_from_pointer(export.address) };
        if code.is_null() {
            continue;
        }
        if !unsafe { is_executable(code) } {
            stats.skipped_not_code += 1;
            continue;
        }

        let label = || match &export.name {
            Some(n) => format!("{name}!{n}"),
            None => format!("{name}!#{}", export.ordinal),
        };

        // Stage 1: how many whole instructions cover the patch site? An Err
        // here means the bytes are not decodable as code (data mislabelled as
        // an export, a function shorter than the patch site at a region edge,
        // etc.) - not a relocator bug.
        let stolen_len = match catch_unwind(|| unsafe {
            Disassembler::get_instruction_len(code, REQUIRED_SPACE)
        }) {
            Ok(Ok(len)) => len,
            Ok(Err(_)) => {
                stats.skipped_undecodable += 1;
                continue;
            }
            Err(_) => {
                stats.crashes.push(format!(
                    "{}: get_instruction_len PANICKED at {:p} bytes={:02X?}",
                    label(),
                    code,
                    first_bytes(code, REQUIRED_SPACE + 15)
                ));
                continue;
            }
        };

        stats.swept += 1;

        // Stage 2: relocate the stolen prologue into the nearby trampoline,
        // the same call the real inline hook makes.
        let outcome = catch_unwind(AssertUnwindSafe(|| unsafe {
            Disassembler::relocate(code, tramp, stolen_len)
        }));

        match outcome {
            Ok(Ok(mapping)) => {
                if mapping.written_len == 0 || mapping.written_len > TRAMPOLINE_CAP {
                    stats.crashes.push(format!(
                        "{}: relocate reported written_len={} (cap {}) stolen={} at {:p}",
                        label(),
                        mapping.written_len,
                        TRAMPOLINE_CAP,
                        stolen_len,
                        code
                    ));
                    continue;
                }
                if mapping.written_len > REAL_BUDGET {
                    stats.exceeds_real_budget += 1;
                }
                stats.relocated += 1;
            }
            Ok(Err(err)) => {
                // "Internal relocation error: ..." signals a broken offset map
                // or encoder invariant - a real bug, not an environmental
                // limitation like a too-far RIP operand or an unencodable
                // short-only branch. Treat it as a hard failure.
                if err.contains("Internal relocation error") {
                    stats.crashes.push(format!(
                        "{}: internal relocator invariant violated: {} (stolen={}, bytes={:02X?})",
                        label(),
                        err,
                        stolen_len,
                        first_bytes(code, stolen_len)
                    ));
                    continue;
                }
                stats.refused += 1;
                if stats.refusal_samples.len() < 20 {
                    stats.refusal_samples.push(format!(
                        "{}: {} (stolen={}, bytes={:02X?})",
                        label(),
                        err,
                        stolen_len,
                        first_bytes(code, stolen_len)
                    ));
                }
            }
            Err(_) => {
                stats.crashes.push(format!(
                    "{}: relocate PANICKED at {:p} stolen={} bytes={:02X?}",
                    label(),
                    code,
                    stolen_len,
                    first_bytes(code, stolen_len)
                ));
            }
        }
    }
}

#[test]
fn relocation_sweep_over_system_exports() {
    let mut stats = Stats::default();

    for &name in SWEEP_MODULES {
        let Some(handle) = ensure_loaded(name) else {
            eprintln!("  [skip] {name}: not present / could not be loaded");
            continue;
        };

        // One trampoline page near the module's base. Every export lives within
        // a few MB of the base, well inside the +/-2GB window, so relocating
        // RIP-relative and relative-branch operands against this address is
        // representable exactly as it would be for a real nearby trampoline.
        let Some(trampoline) = (unsafe {
            TrampolineAlloc::alloc_nearby_trampoline(handle as *const u8, TRAMPOLINE_CAP)
        }) else {
            eprintln!("  [skip] {name}: could not allocate a nearby trampoline");
            continue;
        };

        sweep_module(name, trampoline.as_ptr(), &mut stats);
        // `trampoline` drops here, retiring the page.
    }

    eprintln!(
        "\nexport relocation sweep:\n  \
         swept (decodable executable prologues): {}\n  \
         relocated cleanly: {}\n  \
         gracefully refused: {}\n  \
         relocations exceeding real {REAL_BUDGET}B budget: {}\n  \
         skipped (not code / data export): {}\n  \
         skipped (not decodable as code): {}\n  \
         hard failures (panic / overrun): {}",
        stats.swept,
        stats.relocated,
        stats.refused,
        stats.exceeds_real_budget,
        stats.skipped_not_code,
        stats.skipped_undecodable,
        stats.crashes.len(),
    );
    if !stats.refusal_samples.is_empty() {
        eprintln!("  sample refusals:");
        for sample in &stats.refusal_samples {
            eprintln!("    - {sample}");
        }
    }

    // Hard gate 1: the relocator must never panic or overrun its buffer on a
    // real prologue.
    assert!(
        stats.crashes.is_empty(),
        "relocator crashed on real-world prologues:\n{}",
        stats.crashes.join("\n")
    );

    // Sanity: the sweep actually ran against a substantial corpus. If this
    // trips, the module list failed to load rather than the relocator being
    // fine - fail loudly instead of silently passing on nothing.
    assert!(
        stats.swept >= 2000,
        "expected to sweep thousands of real exports, only saw {} - did the system DLLs load?",
        stats.swept
    );

    // Hard gate 2: coverage floor. A correct relocator handles the overwhelming
    // majority of real prologues; graceful refusals are a small minority. A
    // regression that broke relocation broadly would crater this ratio.
    let ratio = stats.relocated as f64 / stats.swept as f64;
    assert!(
        ratio >= 0.80,
        "relocation success ratio {:.3} below floor 0.80 ({} / {} prologues) - \
         relocator may have regressed",
        ratio,
        stats.relocated,
        stats.swept,
    );
}
