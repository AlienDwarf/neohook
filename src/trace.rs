// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Built-in tracing / logging detour generation.
//!
//! Writing a detour whose only job is to log "this function was called with
//! these arguments and returned this" is pure boilerplate - and easy to get
//! subtly wrong (forgetting to forward to the original, formatting the wrong
//! value). [`crate::detour_trace!`] generates that detour for you: give it a
//! target and its signature and it installs an inline hook that formats every
//! call's arguments and return value (via [`std::fmt::Debug`]) and forwards to
//! the original.
//!
//! Where the formatted line *goes* is decided by a process-wide **sink**. By
//! default records are written to standard error; install your own sink with
//! [`set_sink`] to route them into a real logging framework, a ring buffer, or a
//! file.
//!
//! ```rust,ignore
//! use neohook::{detour_trace, trace};
//!
//! // Route trace records into your logger instead of stderr.
//! trace::set_sink(|r| log::debug!("{}({}) -> {}", r.function, r.args, r.ret));
//!
//! #[inline(never)]
//! extern "system" fn add(a: i32, b: i32) -> i32 { a + b }
//!
//! let _hooks = detour_trace!(add, "system" fn(a: i32, b: i32) -> i32)?;
//! add(2, 3); // logs: add(2, 3) -> 5
//! ```
//!
//! This is a Rust-side ergonomic layer built on the closure-detour engine
//! ([`crate::detour_closure!`]); there is no C ABI, because formatting arbitrary
//! argument types is a Rust-language feature.

use std::sync::atomic::{AtomicUsize, Ordering};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;

use crate::HookContext;

/// A single traced call, handed to the active [`TraceSink`].
///
/// All string fields borrow from the tracing detour's stack frame and are only
/// valid for the duration of the sink call; copy anything you need to keep.
#[derive(Debug, Clone, Copy)]
pub struct TraceRecord<'a> {
    /// The traced function's name, as written at the [`crate::detour_trace!`]
    /// call site (`stringify!` of the target expression).
    pub function: &'a str,
    /// The call's arguments, comma-separated and `Debug`-formatted.
    pub args: &'a str,
    /// The return value, `Debug`-formatted (empty for a `()` return).
    pub ret: &'a str,
    /// The OS thread id the call ran on.
    pub thread_id: u32,
}

/// A function that consumes [`TraceRecord`]s produced by tracing detours.
pub type TraceSink = fn(&TraceRecord);

/// The active sink, stored as a function-pointer-sized integer so it can be read
/// without a lock on the hot path. `0` means "no sink installed", i.e. use the
/// default stderr writer.
static SINK: AtomicUsize = AtomicUsize::new(0);

/// Installs `sink` as the destination for every subsequent trace record,
/// replacing any previously installed sink.
pub fn set_sink(sink: TraceSink) {
    SINK.store(sink as usize, Ordering::Release);
}

/// Removes any custom sink, reverting to the default stderr writer.
pub fn clear_sink() {
    SINK.store(0, Ordering::Release);
}

/// The default sink: writes a single line per call to standard error.
fn default_sink(record: &TraceRecord) {
    eprintln!(
        "[neohook::trace] (tid {}) {}({}) -> {}",
        record.thread_id, record.function, record.args, record.ret
    );
}

/// Dispatches `record` to the active sink, or the default writer if none is set.
///
/// Called by the detour [`crate::detour_trace!`] generates; you normally do not
/// call this directly.
pub fn emit(record: &TraceRecord) {
    let raw = SINK.load(Ordering::Acquire);
    if raw == 0 {
        default_sink(record);
    } else {
        // SAFETY: `raw` was produced by `set_sink` from a valid `TraceSink`
        // function pointer and is only ever cleared to `0` (handled above).
        let sink: TraceSink = unsafe { std::mem::transmute::<usize, TraceSink>(raw) };
        sink(record);
    }
}

/// Builds a [`TraceRecord`] from the pieces a tracing detour has on hand
/// (stamping the current thread id) and dispatches it through [`emit`].
///
/// This is the entry point [`crate::detour_trace!`] expands to; it is `pub` so
/// the macro can call it from any crate, but is not meant for direct use.
#[doc(hidden)]
pub fn record(function: &str, args: &str, ret: &str) {
    let thread_id = unsafe { GetCurrentThreadId() };
    emit(&TraceRecord {
        function,
        args,
        ret,
        thread_id,
    });
}

/// Reads the first `n` "interesting" integer register values from a
/// [`HookContext`] captured at a function entry.
///
/// On **x86_64** these are exactly the Win64 integer argument registers
/// (`rcx`, `rdx`, `r8`, `r9`), so the values *are* the call's first four integer
/// arguments (`n` is capped at 4).
///
/// On **x86** the calling conventions pass integer arguments on the **stack**,
/// not in registers, and a mid-hook context exposes the stub's stack frame
/// rather than the caller's argument frame - so the arguments are not reachable
/// here. Instead the general-purpose registers (`eax`, `ecx`, `edx`, `ebx`,
/// `esi`, `edi`) are dumped as a register snapshot. These are **not** the call
/// arguments; use [`crate::detour_trace!`] with a signature for typed x86
/// arguments.
#[cfg(target_arch = "x86_64")]
fn raw_arg_values(ctx: &HookContext, n: usize) -> Vec<u64> {
    let regs = [ctx.rcx, ctx.rdx, ctx.r8, ctx.r9];
    regs[..n.min(regs.len())].to_vec()
}

#[cfg(target_arch = "x86")]
fn raw_arg_values(ctx: &HookContext, n: usize) -> Vec<u64> {
    let regs = [ctx.eax, ctx.ecx, ctx.edx, ctx.ebx, ctx.esi, ctx.edi];
    regs[..n.min(regs.len())]
        .iter()
        .map(|&v| v as u64)
        .collect()
}

/// Builds a trace record from a register snapshot and dispatches it.
///
/// This is the entry point [`crate::trace_raw!`] expands to: it formats the
/// first `args` integer register values from `ctx` as hex (the call's integer
/// arguments on x86_64; the general-purpose registers on x86 - see
/// [`raw_arg_values`]) and emits a record whose return field is the literal
/// `<entry>` (an entry-time snapshot has no return value to capture). `pub` so
/// the macro can reach it; not for direct use.
#[doc(hidden)]
pub fn record_raw(function: &str, ctx: &HookContext, args: usize) {
    let values = raw_arg_values(ctx, args);
    let formatted: Vec<String> = values.iter().map(|v| format!("{v:#x}")).collect();
    let thread_id = unsafe { GetCurrentThreadId() };
    emit(&TraceRecord {
        function,
        args: &formatted.join(", "),
        ret: "<entry>",
        thread_id,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Captures records from the sink under test. A global because `TraceSink` is
    // a bare `fn` and cannot capture environment.
    static CAPTURED: Mutex<Vec<String>> = Mutex::new(Vec::new());

    fn capturing_sink(record: &TraceRecord) {
        CAPTURED.lock().unwrap().push(format!(
            "{}({}) -> {}",
            record.function, record.args, record.ret
        ));
    }

    #[test]
    fn emit_routes_to_the_installed_sink() {
        CAPTURED.lock().unwrap().clear();
        set_sink(capturing_sink);

        record("add", "2, 3", "5");
        record("noop", "", "()");

        clear_sink();

        let lines = CAPTURED.lock().unwrap().clone();
        assert_eq!(lines, vec!["add(2, 3) -> 5", "noop() -> ()"]);
    }

    #[test]
    fn emit_uses_the_default_sink_when_cleared() {
        // No panic / no capture when no sink is installed: emit must fall back to
        // the default writer rather than dereferencing a null sink.
        clear_sink();
        record("lonely", "1", "1");
    }
}
