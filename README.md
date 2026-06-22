# NeoHook 🪝🦀

[![Crates.io](https://img.shields.io/crates/v/neohook.svg)](https://crates.io/crates/neohook)
[![License: MIT / Apache-2.0](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-blue.svg)](#license)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows)](https://www.microsoft.com/windows)
[![Arch: x86 / x86_64](https://img.shields.io/badge/arch-x86%20%7C%20x86__64-lightgrey)](https://en.wikipedia.org/wiki/X86)
[![CI](https://github.com/aliendwarf/neohook/actions/workflows/ci.yml/badge.svg)](https://github.com/aliendwarf/neohook/actions/workflows/ci.yml)

<img align="right" width="320px" height="320px" src="logo.png">

Hook any function in one line - transactional, and thread-safe. Leave pointer-to-pointer chaos behind.

NeoHook makes runtime function hooking simple and reliable: Win32 APIs, game engine functions, third-party DLL exports, anything with a code pointer. It brings the precision of low-level binary patching together with Rust's memory safety, type system, and RAII ownership model.

> [!IMPORTANT]
> NeoHook is a systems toolkit for debugging, profiling, instrumentation, interoperability, security research, and modding software you own or have permission to modify. You are responsible for complying with the licences, terms, and laws that govern any software you use it with. The authors do not endorse using it to circumvent security or licensing controls, to violate terms of service, or to cause harm.

---

## Why NeoHook?

Function hooking is deceptively difficult to get right. Writing a `JMP` patch is only a few lines of assembly - but doing it safely in a live, multi-threaded process requires solving multiple problems at once:

| Problem                                            |          Naive approach          |                 NeoHook                  |
| :------------------------------------------------- | :------------------------------: | :--------------------------------------: |
| Another thread executes the bytes you are patching |         Access Violation         |    ✅ Threads suspended during patch     |
| Instruction pointer on overwritten bytes           |              Crash               |             ✅ IP redirected             |
| Return address on stack points to patched region   |         Crash on return          |           ✅ Stack redirected            |
| JMP/CALL instructions break after relocation       |           Wrong target           | ✅ Instruction relocation via `iced-x86` |
| One hook in a batch fails                          |             Unstable             |   ✅ Atomic rollback - all or nothing    |
| Hook leaks after your code exits scope             | Permanent patch, crash on unload |   ✅ RAII: automatic unhook on `Drop`    |

---

## Features

- **Atomic Transactions** - Queue multiple hooks and commit them in one step. If any hook fails, every previously applied change in the same transaction is rolled back automatically, leaving the process in a known-good state.

- **Full Thread Safety** - Enumerates and suspends every thread in the process before applying patches.

- **RIP / EIP Redirection** - If a thread's instruction pointer falls within the bytes being overwritten, it is relocated.

- **Stack Scanning** - Scans the top 512 stack slots per thread for return addresses pointing into the patch area and rewrites them to the trampoline equivalent.

- **Instruction Relocation** - Uses [`iced-x86`](https://github.com/icedland/iced) to accurately decode, relocate, and re-encode.

- **Smart Trampoline Allocation** - On x64, allocates trampoline memory within ±2 GB of the target so that a compact 5-byte relative jump suffices. Falls back to a 14-byte absolute jump `(FF 25)`.

- **IAT Hooking** - Rewrites Import Address Table entries to redirect calls to entire DLL exports without touching function preambles.

- **EAT Hooking** - Rewrites a module's Export Address Table so every consumer that resolves the export afterwards (e.g. via `GetProcAddress`) is redirected, without patching the function body. On x64 an out-of-range detour is reached through an automatically managed jump stub.

- **VEH Hooking** - Redirects a function using a CPU hardware breakpoint and a vectored exception handler, **without modifying a single byte** of the target. Ideal for read-only or shared code that must not be patched. Up to four targets at a time (this is a hardware limitation not caused by NeoHook).

- **INT3 Software-Breakpoint Hooking** - Redirects a function by patching a single `0xCC` byte and routing the resulting breakpoint through a vectored exception handler. Unlike VEH hooks there is **no four-hook limit** (up to 256 targets), and threads created *after* the install still trap. The single-byte write is atomic, so no thread suspension is needed.

- **Call-the-Original Gateway (VEH / INT3)** - Breakpoint-style hooks normally *replace* the target with no way back to it. `install_with_original` builds a small gateway holding the relocated prologue plus a jump into the body, so the detour can forward to the original (use its return value, conditionally fall through) without re-triggering the breakpoint or recursing.

- **Symbol-Based Resolution** - Resolve a target by name through the Debug Help library (`dbghelp`): `resolve_symbol("ntdll.dll", "LdrpInitializeProcess")`. With a PDB available (next to the binary or via a symbol server / `_NT_SYMBOL_PATH`) this reaches **non-exported** internal routines that export-table and signature lookups cannot; without a PDB it still resolves export names.

- **Anti-Tamper / Re-Hook Watchdog** - A background `Watchdog` snapshots a hook's patched bytes and, on tamper, either **re-applies** them (`WatchMode::Restore`) or just **reports** the event (`WatchMode::DetectOnly`) via an `on_tamper` callback - keeping a hook in place across, or surfacing, periodic self-integrity checks that restore the original prologue. Works at the byte level, so it guards inline jumps, the INT3 `0xCC`, or any patch.

- **Control Flow Guard (CFG) Awareness** - On a process that enforces CFG, neohook registers the entry points it generates (inline trampolines, VEH/INT3 gateways, EAT jump stubs) and the IAT/EAT/VTable detours as valid indirect-call targets via `SetProcessValidCallTargets` - the same mechanism Microsoft Detours uses. Auto-detected and a no-op when CFG is off, so it is safe to leave on; it keeps hooks holding up under **strict CFG** and **export suppression**, where the default permit for private executable memory no longer applies. `cfg::register_valid_target` is public for your own runtime-generated code.

- **Tracing Detours** - Two generators, no hand-written boilerplate: `detour_trace!` takes a signature and `Debug`-formats every call's arguments **and return value**; `trace_raw!` needs **no signature** and dumps the integer argument registers at entry via the `MidHook`/`HookContext` bridge. Both emit to a process-wide sink (stderr by default, or your own logger).

- **Pattern / Signature Scanning** - Resolve unexported, statically-linked, or stripped functions by a byte signature (IDA / x64dbg `48 8B ?? E8` syntax, or code+mask). Scans only committed, executable regions of a module - safely skipping guard pages and holes - and feeds the match straight into a hook via `attach_pattern`.

- **Hook-by-Export-Name** - `attach_export("user32.dll", "MessageBoxW", detour)` resolves a named export (loading the module if needed) and queues an inline hook on the function body in a single call - no manual `GetModuleHandle` / `GetProcAddress` dance.

- **Relative-Reference Resolving** - After a signature scan lands on a `call rel32` or a `lea/mov [rip + disp32]`, `resolve_call_target` / `resolve_rip_relative` decode the instruction and return the absolute address it points to (or `resolve_relative` from a known encoding). Turns "the signature near the function" into "the function".

- **Closure Detours** - `detour_closure!` installs an inline hook whose body is a **Rust closure that captures environment** (counters, channels, config) - something a bare-`fn`-pointer C/C++ library cannot express. The closure receives the original function as its first argument so it can forward to it.

- **Delay / On-Load Hooks** - Register a hook for a function in a module that is **not loaded yet**; NeoHook inline-hooks `ntdll!LdrLoadDll` once and installs the real hook the moment the module appears (`DelayHook::register`).

- **Named Hook Registry** - Park hooks in a process-wide store and refer to them by name: `registry::register`, `enable` / `disable`, `unhook`, and `unhook_all` for a single teardown point (e.g. `DLL_PROCESS_DETACH`).

- **Mid-Function / Arbitrary-Address Detours** - Hook *any* instruction boundary, not just a function entry. NeoHook snapshots all general-purpose registers, flags, the XMM registers and `MXCSR` into a `HookContext`, calls your handler with a pointer to it, restores the (possibly modified) state, then resumes the original instructions. Rewrite integer or floating-point/SIMD arguments, results, or loop state in flight at a spot found by a signature scan - all on the thread-safe inline engine (thread suspension, IP/stack redirection, relocation, atomic rollback).

- **VTable Hooking** - Rewrites a selected VTable slot to detour virtual calls and restores the original slot on unhook.

- **Per-Instance VTable Hooking** - Clones an object's VTable, patches the clone, and redirects only that instance.

- **Hook Chaining** - Detour the trampoline of an already-installed hook to layer multiple interceptors in a defined order.

- **Enable / Disable** - Toggle an installed hook on or off (`Hook::enable` / `Hook::disable`) without unhooking, keeping the trampoline and cloned tables in place.

- **Reentrancy Guard** - The `reentrancy_guard!` macro lets a detour detect that it is already running on the current thread and forward to the original instead of recursing.

- **Serialized Transactions** - A process-wide lock applies one transaction at a time, so concurrent installs on different threads cannot suspend each other or patch overlapping code.

- **Failure Diagnostics** - A failed `commit()` reports which queued hook failed (`DetourError::CommitFailed { index, kind, source }`) after rolling back.

- **RAII Ownership** - The `Vec<Hook>` returned by `commit()` unhooks and restores original memory automatically when dropped.

- **Quiescence-Checked Teardown** - Freeing a trampoline the instant a hook drops would be unsound if another thread were still executing inside it. Instead a dropped stub is *retired* and released only once a thread scan (instruction pointers plus stack return addresses) shows no thread is inside it - otherwise it stays quarantined for a later pass. Reclamation runs automatically at the start of every transaction (a no-op when nothing is pending) and is also exposed as `neohook::reclaim()` for unhook-only workloads.

- **Zero-Boilerplate Macros** - `detour_inline!` and `detour_helper!` install a complete hook with a single expression.

- **C FFI** - Exposes a C ABI with auto-generated headers (`cbindgen`), usable from C, C++, Python (`ctypes`), or any FFI-capable language.

---

## Comparison

How NeoHook relates to the other established Windows hooking libraries. This is a
factual feature-presence matrix, not a benchmark - each project has different
goals, and Detours and MinHook in particular have a far longer production track
record (see the note below the table).

Legend: ✅ built in · ◐ partial / via a different mechanism · ❌ not provided.
Accurate as of June 2026; corrections welcome via an issue.

| Capability | NeoHook | MS Detours | PolyHook2 | MinHook |
| :--------- | :-----: | :--------: | :-------: | :-----: |
| Inline hook + instruction relocation | ✅ | ✅ | ✅ | ✅ |
| Atomic transaction + rollback | ✅ | ✅ | ❌ | ◐ |
| Thread suspend + IP redirect | ✅ | ◐ | ◐ | ✅ |
| Stack return-address rewrite | ✅ | ❌ | ❌ | ❌ |
| IAT hooking | ✅ | ◐ | ✅ | ❌ |
| EAT hooking | ✅ | ❌ | ✅ | ❌ |
| VTable hook (+ per-instance) | ✅ | ❌ | ✅ | ❌ |
| VEH (hardware-breakpoint) hook | ✅ | ❌ | ✅ | ❌ |
| INT3 software-breakpoint hook | ✅ | ❌ | ❌ | ❌ |
| Mid-function / register-context detour | ✅ | ❌ | ◐ | ❌ |
| Pattern / signature scanning | ✅ | ❌ | ❌ | ❌ |
| Symbol resolution (dbghelp / PDB) | ✅ | ❌ | ❌ | ❌ |
| Closure detours (capturing) | ✅ | ❌ | ◐ | ❌ |
| Tracing / logging detour generators | ✅ | ❌ | ❌ | ❌ |
| Anti-tamper / re-hook watchdog | ✅ | ❌ | ❌ | ❌ |
| Delay / on-load hooks | ✅ | ❌ | ❌ | ❌ |
| Control Flow Guard awareness | ✅ | ✅ | ❌ | ❌ |
| RAII / memory-safe ownership | ✅ | ❌ | ❌ | ❌ |
| C ABI | ✅ | ✅ | ❌ | ✅ |
| ARM64 inline hooking | ❌ | ✅ | ❌ | ❌ |
| Cross-process / remote patching | ❌ | ✅ | ◐ | ❌ |
| Process-launch DLL injection | ❌ | ✅ | ❌ | ❌ |
| On-disk PE import editing | ❌ | ✅ | ❌ | ❌ |

NeoHook is the broadest in-process engine on x86/x64 here; the areas Detours
still owns are out-of-process / launch-time injection, on-disk binary editing,
and ARM64. Detours and MinHook are also more battle-tested at scale, so treat
this as a feature comparison rather than a maturity one.

---

## Roadmap

| Version |     Status | Features                                               |
| ------- | ---------: | ------------------------------------------------------ |
| v0.1.0  |    ✅ Done | Initial release                                        |
| v0.1.0  |    ✅ Done | Inline hooking                                         |
| v0.1.0  |    ✅ Done | IAT hooking                                            |
| v0.1.0  |    ✅ Done | Transaction API (`begin`, `attach`, `commit`, `abort`) |
| v0.1.0  |    ✅ Done | Thread updates (`update_thread`, `update_all_threads`) |
| v0.1.0  |    ✅ Done | Trampoline allocation + relocation                     |
| v0.1.0  |    ✅ Done | Managed gateways / hook chaining                       |
| v0.1.0  |    ✅ Done | Rollback on failed commit                              |
| v0.1.0  |    ✅ Done | RAII unhook on drop                                    |
| v0.1.0  |    ✅ Done | C FFI transaction entry points                         |
| v0.2.0  |    ✅ Done | VTable hooking                                         |
| v0.2.0  |    ✅ Done | Per-instance VTable hooks                              |
| v0.2.0  |    ✅ Done | Shared VTable patching                                 |
| v0.2.0  |    ✅ Done | VTable hook support in C FFI                           |
| v0.2.0  |    ✅ Done | Additional tests and examples for C++ / COM targets    |
| v0.3.0  |    ✅ Done | Enable / disable hooks without full unhook             |
| v0.3.0  |    ✅ Done | Recursion / reentrancy guards                          |
| v0.3.0  |    ✅ Done | Improved diagnostics / debug output                    |
| v0.3.0  |    ✅ Done | Module / PE introspection (modules, exports, imports)  |
| v0.4.0  |    ✅ Done | Export / EAT hooking                                   |
| v0.5.0  |    ✅ Done | VEH hooking                                            |
| v0.6.0  |    ✅ Done | Pattern / signature scanning                           |
| v0.6.0  |    ✅ Done | Signature-based hook resolution (`attach_pattern`)     |
| v0.7.0  |    ✅ Done | Mid-function / arbitrary-address detours (`MidHook`)   |
| v0.7.0  |    ✅ Done | Register-context capture / modification (`HookContext`)|
| v0.8.0  |    ✅ Done | INT3 software-breakpoint hooking (`Int3Hook`)          |
| v0.8.0  |    ✅ Done | Hook-by-export-name (`attach_export`)                   |
| v0.8.0  |    ✅ Done | Relative-reference resolving (`resolve_call_target`)   |
| v0.8.0  |    ✅ Done | Closure detours (`detour_closure!`)                    |
| v0.8.0  |    ✅ Done | Delay / on-load hooks (`DelayHook`)                    |
| v0.8.0  |    ✅ Done | Named hook registry (`registry`)                       |
| v0.9.0  |    ✅ Done | XMM / MXCSR context capture in `MidHook`               |
| v0.9.0  |    ✅ Done | Control-flow redirect from a `MidHook` handler         |
| v0.10.0 |    ✅ Done | Call-the-original gateway for VEH / INT3 hooks          |
| v0.10.0 |    ✅ Done | Symbol-based resolution via `dbghelp` (`resolve_symbol`)|
| v0.10.0 |    ✅ Done | Anti-tamper / re-hook watchdog (`Watchdog`)            |
| v0.10.0 |    ✅ Done | Tracing / logging detour generator (`detour_trace!`)   |
| v0.10.0 |    ✅ Done | Control Flow Guard (CFG) awareness (`cfg`)             |
| v0.11.0 |    Planned | ARM64 inline hooking                                   |

--

## Installation

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
neohook = "0.10.0"
```

---

## Quick Start

### One-liner hook - `detour_inline!`

Use this when you want to completely replace a function and do not need to call the original.

```rust
use neohook::detour_inline;

#[inline(never)]
fn target(x: i32) -> i32 { std::hint::black_box(x) * 2 } // returns x * 2
fn detour(x: i32) -> i32 { x + 100 }

fn main() {
    let _hook = detour_inline!(target, detour).expect("hook failed"); // One line: suspend threads, patch, resume.
    assert_eq!(target(5), 105); // intercepted
    // _hook drops here => original bytes restored automatically
}
```

---

## Usage Examples

### Call the original - `detour_helper!`

`detour_helper!` stores the trampoline pointer in a `OnceLock` so you can forward calls to the original function from within your detour.

```rust
use std::sync::OnceLock;
use neohook::detour_helper;

type AddFn = fn(i32, i32) -> i32;

// Storage for the original function pointer (generated by the macro)
static ORG_ADD: OnceLock<AddFn> = OnceLock::new();

#[inline(never)]
fn add(a: i32, b: i32) -> i32 { a + b }

fn detour_add(a: i32, b: i32) -> i32 {
    // Call the original, then multiply the result
    let original = ORG_ADD.get().expect("original not set");
    original(a, b) * 10
}

fn main() {
    // Args: (static name, target, detour, function type)
    let _hook = detour_helper!(ORG_ADD, add, detour_add, AddFn)
        .expect("hook failed");

    assert_eq!(add(2, 3), 50); // (2 + 3) * 10
}
```

---

### Full Control - Transaction API

Use the `DetourTransaction` API directly when you need to install several hooks atomically or when you require fine-grained control.

```rust
use neohook::DetourTransaction;

fn main() {
    let mut session = DetourTransaction::begin();

    // Suspend all threads in the process before the commit
    session.update_all_threads();

    // Queue hooks - none are applied yet
    session.attach(fn_a as *mut u8, detour_a as *const u8).unwrap();
    session.attach(fn_b as *mut u8, detour_b as *const u8).unwrap();

    // Atomically apply all queued hooks.
    // If fn_b fails, fn_a is automatically rolled back.
    let hooks = session.commit().expect("transaction failed");
}
```

---

### IAT Hooking

Redirect calls to an imported function across an entire module by rewriting the Import Address Table entry instead of patching the function preamble. This is useful when you want to intercept only calls from a specific module.

```rust
use neohook::DetourTransaction;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

type SleepFn = unsafe extern "system" fn(u32);
static ORIG_SLEEP: OnceLock<SleepFn> = OnceLock::new();

unsafe extern "system" fn hooked_sleep(ms: u32) {
    if let Some(orig) = ORIG_SLEEP.get() {
        orig(ms / 2);
    }
}

fn main() {
    unsafe {
        let h_module = GetModuleHandleW(std::ptr::null()); // current module

        let mut orig_ptr: *mut u8 = std::ptr::null_mut();
        let mut session = DetourTransaction::begin();
        session.update_all_threads();

        session
            .attach_iat(
                h_module,
                "KERNEL32.dll",
                "Sleep",
                hooked_sleep as *const u8,
            )
            .expect("IAT hook failed");

        let hooks = session.commit().expect("transaction failed");
        let original_ptr = hooks[0].original_ptr();
        let original: SleepFn = std::mem::transmute(original_ptr);
        let _ = ORIG_SLEEP.set(original);

        // Sleep is now intercepted for this module
        windows_sys::Win32::System::Threading::Sleep(1000); // returns immediately
    }
}
```

---

### EAT Hooking

Redirect a function at its source by rewriting the exporting module's Export
Address Table. Unlike an IAT hook - which only affects one caller module - an
EAT hook redirects **every** consumer that resolves the export *after* the hook
is installed (for example through `GetProcAddress`). Code that already cached
the resolved address is unaffected, because only the lookup table changes, not
the function body.

```rust
use neohook::DetourTransaction;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;

unsafe extern "system" fn get_tick_count_detour() -> u32 {
    0xDEAD_BEEF
}

fn main() {
    let module = unsafe { GetModuleHandleA(c"kernel32.dll".as_ptr() as *const u8) };

    let mut tx = DetourTransaction::begin();
    tx.attach_eat(module, "GetTickCount", get_tick_count_detour as *const u8)
        .expect("EAT hook failed");
    let hooks = tx.commit().expect("transaction failed");

    // Any GetProcAddress(module, "GetTickCount") now resolves to the detour,
    // while `hooks[0].original_ptr()` still reaches the real function.
}
```

On x86_64 the export slot stores a 32-bit RVA. When the detour lies more than
4 GB from the module base, NeoHook allocates a small jump stub within range and
points the slot at it; the stub is released automatically when the hook is
dropped or unhooked. See [`examples/eat_hook.rs`](examples/eat_hook.rs).

The C ABI exposes this as
`detours_transaction_attach_eat(tx, h_module, target_func, detour)`.

---

### Pattern / Signature Scanning

Direct pointers and export names cover functions the loader knows about. For
**unexported, statically-linked, or stripped** functions - the usual situation
when hooking a game engine or a stripped third-party DLL - the reliable handle
is a byte **signature**: a short run of opcode bytes with wildcards over the
parts that move between builds (relative offsets, absolute addresses).

`Pattern` parses both common dialects, and `scan_module` resolves a signature
inside a loaded module, scanning only its committed, executable regions.

```rust
use neohook::{Pattern, scan_module, get_module_handle};

// IDA / x64dbg syntax: `?` / `??` are wildcard bytes.
let pat = Pattern::parse("48 8B 05 ?? ?? ?? ?? 48 89").unwrap();

// code + mask is also supported:
// let pat = Pattern::from_code_style(b"\x48\x8B\x05\x00\x00\x00\x00", "xxx????").unwrap();

let h = get_module_handle("game.dll").unwrap();
if let Some(addr) = unsafe { scan_module(h, &pat) } {
    println!("resolved target at {addr:p}");
}
```

The matched address can be fed straight into `DetourTransaction::attach`, or you
can let `attach_pattern` resolve the signature and queue the inline hook in one
step:

```rust
use neohook::DetourTransaction;

let mut tx = DetourTransaction::begin();
tx.update_all_threads();

// Resolve "game.dll!?" by signature and hook it inline. Returns the trampoline.
let _trampoline = tx
    .attach_pattern("game.dll", "48 89 5C 24 ?? 57 48 83 EC 20", my_detour as *const u8)
    .expect("signature not found");

let _hooks = tx.commit().expect("transaction failed");
```

The C ABI exposes `detours_scan_module`, `detours_scan_module_by_name`,
`detours_scan_range`, and `detours_transaction_attach_pattern`. The C++ wrapper
provides `neohook::scan_module(...)`, `neohook::scan_range(...)`, and
`Transaction::attach_pattern(...)`. See [`examples/pattern_scan.rs`](examples/pattern_scan.rs).

---

### Mid-Function / Arbitrary-Address Detours

Every other hook is anchored to a function entry or a table slot. A
**mid-function detour** lets you intercept *any* instruction boundary - the
exact spot inside a routine where a register holds the value you care about,
typically located with a [signature scan](#pattern--signature-scanning).

Because such a site is reached with arbitrary registers live, a normal detour
would clobber them. Instead NeoHook installs a context bridge: it snapshots all
general-purpose registers, flags, every XMM register and `MXCSR` into a
[`HookContext`], calls your handler with a pointer to it, restores the
(possibly modified) state, then runs the original instructions and resumes the
function. The patch runs on the full inline engine - threads suspended,
instruction pointers/return addresses redirected, stolen bytes relocated,
atomic rollback on failure.

```rust
use neohook::{HookContext, MidHook};

#[inline(never)]
extern "system" fn price_for(quantity: u64) -> u64 {
    std::hint::black_box(quantity) * 100
}

// Reached with the live CPU state; Win64 holds the first argument in RCX.
unsafe extern "system" fn handler(ctx: *mut HookContext) {
    let ctx = &mut *ctx;
    ctx.rcx = ctx.rcx.wrapping_add(5); // rewrite the argument in flight
}

fn main() {
    let hook = unsafe { MidHook::install(price_for as *const u8, handler) }
        .expect("mid-function hook failed");

    assert_eq!(price_for(2), 700); // (2 + 5) * 100 - the edit took effect

    hook.unhook().unwrap(); // original bytes restored
    assert_eq!(price_for(2), 200);
}
```

A handler may read any field of `HookContext` to observe a live register, or
write one to change it before execution continues - including the floating-point
/ SIMD argument registers via `ctx.xmm[..]` (e.g.
`f64::from_bits(ctx.xmm[0].low)` for a scalar `double`). General-purpose
registers, flags, all XMM registers and `MXCSR` are captured; the legacy x87
stack registers are not. `target` must sit on a real instruction boundary.

By default the detour *continues* the original function. A handler can instead
**redirect control flow** by setting `ctx.redirect_rip` (`redirect_eip` on x86)
to a code address: the stub restores the (possibly modified) state and jumps
there, skipping the stolen instructions. Use it to replace a routine wholesale
(redirect a hooked entry to a same-ABI drop-in that returns to the caller) or to
skip the patched region via `hook.resume_address()` (`= target + stolen_len`).
The redirect is an indirect `jmp`, not a `ret`, so it leaves the CET shadow
stack intact.

The C ABI exposes `detours_midhook_install(target, handler)` and
`detours_midhook_unhook(hook)`; the C++ wrapper provides an RAII `neohook::MidHook`.
See [`examples/midhook.rs`](examples/midhook.rs).

---

### VEH Hooking (hardware breakpoints)

Redirect a function **without patching its bytes**. NeoHook arms a CPU hardware
execution breakpoint (debug registers `DR0`-`DR3`) on the target and installs a
vectored exception handler that rewrites the instruction pointer to the detour
when the breakpoint fires. Because the code is never modified, this works on
read-only or shared pages that must stay byte-for-byte intact.

```rust
use neohook::VehHook;

#[inline(never)]
extern "system" fn secret() -> u32 { 1234 }
extern "system" fn secret_detour() -> u32 { 9999 }

fn main() {
    let hook = unsafe {
        VehHook::install(
            secret as *const () as *const u8,
            secret_detour as *const () as *const u8,
        )
    }
    .expect("VEH hook failed");

    assert_eq!(secret(), 9999); // intercepted via the exception handler
    hook.unhook().unwrap();     // breakpoint cleared on every thread
}
```

VEH hooking has inherent limits worth knowing:

- **Four hooks at a time** - one per hardware debug register.
- **Per-thread arming** - debug registers are per-thread. NeoHook arms every
  thread that exists when the hook is installed; threads created afterwards call
  the original.
- **Full replacement** - like `detour_inline!`, the detour replaces the target;
  there is no trampoline to call the original through.

To **call the original** anyway, install with `VehHook::install_with_original`:
it builds a small gateway holding the relocated prologue, retrievable with
`hook.original_ptr()`, that runs the original without re-triggering the
breakpoint. (The plain `install` stays a pure full replacement.)

See [`examples/veh_hook.rs`](examples/veh_hook.rs). The C ABI exposes
`detours_veh_install(target, detour)`,
`detours_veh_install_with_original(target, detour)`, `detours_veh_original(hook)`,
and `detours_veh_unhook(hook)`.

---

### INT3 Software-Breakpoint Hooking

Like a VEH hook, an INT3 hook redirects a function through a vectored exception
handler rather than overwriting its prologue with a jump - but it arms the trap
by patching a **single `0xCC` byte** at the target instead of using a hardware
debug register. That removes VEH's four-hook ceiling (up to 256 targets), and
threads created *after* the install still trap. The one-byte write is atomic, so
no threads are suspended.

```rust
use neohook::Int3Hook;

#[inline(never)]
extern "system" fn secret() -> u32 { 1234 }
extern "system" fn secret_detour() -> u32 { 9999 }

fn main() {
    let hook = unsafe {
        Int3Hook::install(
            secret as *const () as *const u8,
            secret_detour as *const () as *const u8,
        )
    }
    .expect("INT3 hook failed");

    assert_eq!(secret(), 9999); // intercepted via the breakpoint handler
    hook.unhook().unwrap();     // original byte restored
}
```

Trade-offs versus a VEH hook:

- **One byte is modified.** The target is not byte-for-byte intact, so this is
  unsuitable for read-only pages that reject the write or code guarded by an
  integrity check. (Use a VEH hook there.)
- **No four-hook limit.** Up to `INT3_MAX_HOOKS` (256) targets at once.
- **Covers future threads.** Arming is not per-thread.
- **Full replacement.** Like VEH, the detour replaces the target; there is no
  trampoline to call the original through - unless you install with
  `Int3Hook::install_with_original`, which builds a gateway (retrievable via
  `hook.original_ptr()`) so the detour can forward to the original without
  re-triggering the breakpoint.

See [`examples/int3_hook.rs`](examples/int3_hook.rs) (which installs six hooks at
once to show the limit is gone). The C ABI exposes
`detours_int3_install(target, detour)`,
`detours_int3_install_with_original(target, detour)`, `detours_int3_original(hook)`,
and `detours_int3_unhook(hook)`; the C++ wrapper provides an RAII
`neohook::Int3Hook`.

---

### Hooking a Named Export - `attach_export`

When the target is a named export, you do not need to resolve its address
yourself. `attach_export` loads the module if necessary, resolves the export, and
queues an inline hook on the function body in one call - intercepting **every**
caller in the process (unlike an IAT hook, which only affects one module).

```rust
use neohook::DetourTransaction;

unsafe extern "system" fn my_message_box_w(
    hwnd: *mut core::ffi::c_void,
    _text: *const u16,
    caption: *const u16,
    utype: u32,
) -> i32 {
    // Replace the body text, then forward through the trampoline if desired.
    0
}

fn main() {
    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();

    // One call: resolve user32!MessageBoxW by name and queue the inline hook.
    let _trampoline = tx
        .attach_export("user32.dll", "MessageBoxW", my_message_box_w as *const u8)
        .expect("export not found");

    let _hooks = tx.commit().expect("transaction failed");
}
```

The C ABI exposes `detours_transaction_attach_export(tx, module, func, detour)`;
the C++ wrapper provides `Transaction::attach_export(...)`. See
[`examples/attach_export.rs`](examples/attach_export.rs).

---

### Resolving Relative References After a Scan

A [signature scan](#pattern--signature-scanning) usually lands on an instruction
that *references* the address you want rather than being it - a `call rel32` into
the function, or a `lea/mov [rip + disp32]` loading a global. On x86_64 these
encodings are position-dependent, so the bytes you matched do not contain the
absolute target; you must add the displacement to the address *past* the
instruction. These helpers do that for you.

```rust
use neohook::{Pattern, scan_module_by_name, resolve_call_target, resolve_rip_relative};

// Signature lands on `call InitWorld` inside the caller.
let pat = Pattern::parse("E8 ?? ?? ?? ??").unwrap();
let call_site = scan_module_by_name("game.dll", &pat).unwrap();

// Follow the relative call to the real function entry, then hook that.
let init_world = unsafe { resolve_call_target(call_site) }.unwrap();

// Or, for `mov rax, [rip+disp32]` loading a global pointer:
// let global = unsafe { resolve_rip_relative(load_site) }.unwrap();
```

`resolve_relative(addr, disp_offset, instr_len)` is the decode-free variant when
you already know the exact encoding. The C ABI exposes `detours_resolve_call_target`,
`detours_resolve_rip_relative`, and `detours_resolve_relative`; the C++ wrapper
mirrors them as `neohook::resolve_*`. See
[`examples/resolve_relative.rs`](examples/resolve_relative.rs).

---

### Closure Detours - `detour_closure!`

Every detour shown so far is a bare `fn` pointer. `detour_closure!` lets the
detour be a **Rust closure that captures environment** - a counter, a channel, a
config value - which no C/C++ hooking library can express. The closure receives
the original function as its first argument, so it can still forward to it.

```rust
use neohook::detour_closure;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

#[inline(never)]
extern "system" fn add(a: i32, b: i32) -> i32 { a + b }

fn main() {
    let calls = Arc::new(AtomicU32::new(0));
    let calls_in = Arc::clone(&calls);

    let _hooks = detour_closure!(
        add,                                    // target
        "system" fn(a: i32, b: i32) -> i32,     // ABI + arg names/types + return
        move |orig, a, b| {                     // first param is the original
            calls_in.fetch_add(1, Ordering::Relaxed); // captured state!
            orig(a, b) * 10
        },
    )
    .expect("hook failed");

    assert_eq!(add(2, 3), 50);               // (2 + 3) * 10
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}
```

The argument names in the signature are reused for the closure parameters.
Returns `Result<Vec<Hook>, DetourError>` like `detour_inline!`; keep the value
alive to keep the hook installed. The closure is heap-allocated and leaked for
the process lifetime, and - like any detour - may run concurrently, so guard any
mutable captured state yourself. See
[`examples/closure_detour.rs`](examples/closure_detour.rs).

---

### Delay / On-Load Hooks

Sometimes the target lives in a module that is not loaded yet - a plugin, a
lazily-loaded codec, a graphics backend chosen at runtime. A `DelayHook`
registers the module + export name up front and installs the hook the moment
that module appears. NeoHook inline-hooks `ntdll!LdrLoadDll` (the chokepoint
every `LoadLibrary*` funnels through) once, and on each load re-checks the
pending list.

```rust
use neohook::DelayHook;

unsafe extern "system" fn my_present(/* ... */) -> i32 { 0 }

fn main() {
    // d3d11.dll may not be loaded yet - register anyway.
    let hook = unsafe {
        DelayHook::register("d3d11.dll", "D3D11CreateDeviceAndSwapChain", my_present as *const u8)
    }
    .expect("register failed");

    // ... later, when the game loads d3d11.dll, the hook installs itself.
    assert!(hook.is_active() || !hook.is_active()); // query install state
}
```

The redirect uses an INT3 hook (single byte, no thread suspension) so the install
is safe under the loader lock. Like INT3/VEH hooks it is full-replacement (no
trampoline to the original). The C ABI exposes `detours_delay_register`,
`detours_delay_is_active`, and `detours_delay_unhook`; the C++ wrapper provides
an RAII `neohook::DelayHook`. See [`examples/delay_hook.rs`](examples/delay_hook.rs).

---

### Named Hook Registry

By default a hook is owned by the `Vec<Hook>` you hold and is unhooked when that
value drops. In a long-lived injected DLL it is often handier to park hooks in
one place and refer to them by name - toggling, removing, or tearing them all
down without threading a guard through your code.

```rust
use neohook::{registry, DetourTransaction};

fn install(target: *mut u8, detour: *const u8) {
    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();
    tx.attach(target, detour).unwrap();
    let mut hooks = tx.commit().unwrap();

    registry::register("sleep", hooks.remove(0));
}

fn shutdown() {
    registry::disable("sleep").ok();   // temporarily off
    registry::enable("sleep").ok();    // back on
    registry::unhook_all();            // tear everything down (e.g. DLL_PROCESS_DETACH)
}
```

`register`, `take`, `enable`, `disable`, `is_enabled`, `unhook`, `unhook_all`,
`names`, and `count` operate on the shared store. This is a Rust-side ergonomic
layer (no C ABI).

---

### VTable Hooking

Redirect a specific virtual slot by queueing a VTable hook in the same transaction API.

```rust
use neohook::DetourTransaction;

type SlotFn = extern "system" fn() -> i32;

extern "system" fn original_method() -> i32 { 1 }
extern "system" fn detour_method() -> i32 { 2 }

fn main() {
    // Demonstration with a synthetic VTable array.
    // In real usage, this is usually an object's vtable pointer.
    let mut vtable = [original_method as *mut u8];

    let mut tx = DetourTransaction::begin();
    let original_ptr = tx
        .attach_vtable(vtable.as_mut_ptr(), 0, detour_method as *const u8)
        .expect("VTable attach failed");

    let _hooks = tx.commit().expect("transaction failed");

    let original: SlotFn = unsafe { std::mem::transmute(original_ptr) };
    let current: SlotFn = unsafe { std::mem::transmute(vtable[0]) };

    assert_eq!(current(), 2);
    assert_eq!(original(), 1);
}
```

For an object-scoped variant, see [`examples/vtable_instance_hook.rs`](examples/vtable_instance_hook.rs).
For hooking a COM-style interface (the `IUnknown` `QueryInterface`/`AddRef`/`Release` layout),
see [`examples/com_vtable_hook.rs`](examples/com_vtable_hook.rs).
For an end-to-end input hook (intercepting `user32!GetMessageW` so every keystroke
in a window becomes `'a'`), see [`examples/force_keystroke_to_a.rs`](examples/force_keystroke_to_a.rs).

---

### Graphics API Hooking (DirectX / OpenGL)

The flagship use case for VTable and inline hooks is intercepting a graphics
API's frame-present call - the anchor point for overlays, ESPs, and frame
counters. NeoHook ships three **self-contained, runnable** examples that set up
their own rendering context (no game required) and confirm the hook fires. They
use the software rasterizer / software GL, so they run **without a GPU** (and in
CI):

| Example | Target | Technique |
| :------ | :----- | :-------- |
| [`examples/d3d11_present.rs`](examples/d3d11_present.rs) | `IDXGISwapChain::Present` (vtable slot 8) | VTable hook on a WARP swapchain |
| [`examples/d3d9_endscene.rs`](examples/d3d9_endscene.rs) | `IDirect3DDevice9::EndScene` (vtable slot 42) | VTable hook on a NULLREF device |
| [`examples/opengl_swapbuffers.rs`](examples/opengl_swapbuffers.rs) | `opengl32!wglSwapBuffers` | Inline hook via `attach_export` |

The hard part of hooking DirectX is just *getting* the vtable: create a throwaway
device/swapchain and read the vtable pointer from the COM object. Each example
shows that, then hooks the present/end-scene slot and forwards to the original.
In an injected DLL the hook logic is identical - only the delivery differs (you
install it from `DllMain` instead of creating your own context). Run them with
e.g. `cargo run --example d3d11_present`.

---

### Keeping hooks alive (DLL injection / DllMain)

In Rust, values are dropped (and hooks uninstalled) when they leave scope. Inside a DLL that is injected into a running process, your initialization thread will eventually finish - taking your hooks with it unless you explicitly extend their lifetime.

The correct pattern is to move the hook guard into a `OnceLock<Vec<Hook>>` global:

```rust
use std::sync::OnceLock;
use neohook::{DetourTransaction, Hook};

static ACTIVE_HOOKS: OnceLock<Vec<Hook>> = OnceLock::new();

unsafe extern "system" fn target_present(/* ... */) { /* ... */ }
unsafe extern "system" fn hooked_present(/* ... */) { /* ... */ }

fn install_hooks() {
    let mut session = DetourTransaction::begin();
    session.update_all_threads();
    session
        .attach(target_present as *mut u8, hooked_present as *const u8)
        .unwrap();

    let guards = session.commit().expect("hook install failed");

    // Transfer ownership into the global - hooks stay alive for the process lifetime
    if ACTIVE_HOOKS.set(guards).is_err() {
        // Already initialised (e.g. called twice) - new guards drop and unhook safely
    }
}
```

> **Alternative for fire-and-forget hooks:** use `std::mem::forget(guards)` to intentionally leak the guard and prevent the `Drop` from ever running. The hooks will remain active until the process terminates.

---

### C / C++ FFI

NeoHook exposes a C ABI. Generate the header with:

```bash
cargo build --features generate-headers
```

The header is written to `include` directory.

**Notes on FFI ownership:**

- `detours_transaction_commit` takes ownership of the transaction pointer and frees it.
- The returned handle keeps hooks alive until you call `detours_handle_unhook_and_free`.
- All thread safety guarantees (suspension, RIP redirection, stack scanning) apply equally when called from C/C++.

**VTable FFI API:**

- `detours_transaction_attach_vtable(tx, vtable, index, detour)` returns the previous slot pointer on success.

---

### Module / PE Introspection

Discover hook targets at runtime: enumerate loaded modules, a module's entry point,
its exports (EAT) and imports, and resolve exports by name or ordinal.

```rust
use neohook::{enumerate_modules, enumerate_exports, get_module_handle, find_function_by_ordinal};

// List loaded modules.
for m in enumerate_modules() {
    println!("{} @ {:p} ({} bytes)", m.name, m.base, m.size);
}

// Walk a module's exports.
let h = get_module_handle("kernel32.dll").unwrap();
for e in unsafe { enumerate_exports(h) }.unwrap() {
    if let Some(name) = &e.name {
        println!("#{} {} -> {:p}", e.ordinal, name, e.address);
    }
}

// Resolve an export the linker only exposes by ordinal.
let func = find_function_by_ordinal("ws2_32.dll", 1);
```

The C ABI mirrors this with the opaque-handle pattern
(`detours_enumerate_modules` / `detours_enumerate_exports` / `detours_enumerate_imports`,
each paired with `_len` / per-field getters / `_free`), plus `detours_get_entry_point`
and `detours_find_function` / `detours_find_function_by_ordinal`. The C++ wrapper
(`neohook::enumerate_modules()`, etc.) returns owning `std::vector`s. See
[`examples/introspect.rs`](examples/introspect.rs).

---

### Symbol-Based Resolution (`dbghelp`)

Direct pointers, export names, and [signatures](#pattern--signature-scanning)
all fail on a function that is **not exported** - an internal routine, a `static`
helper, a private `ntdll` chokepoint. When a PDB is available (next to the
binary, or via a symbol server / `_NT_SYMBOL_PATH`), the Debug Help library can
map such a name straight to an address. `resolve_symbol` wraps that lookup.

```rust
use neohook::resolve_symbol;

// With ntdll symbols available, resolve a private, unexported routine by name.
if let Some(addr) = resolve_symbol("ntdll.dll", "LdrpInitializeProcess") {
    // feed `addr` straight into DetourTransaction::attach
    println!("resolved at {addr:p}");
}

// Even without a PDB, dbghelp synthesizes symbols from the export table, so a
// well-known export resolves to the same address find_function would return.
let get_proc = resolve_symbol("kernel32.dll", "GetProcAddress").unwrap();
```

The module is loaded if necessary, and `dbghelp` (which is single-threaded by
contract) is serialized through one process-wide lock. The C ABI exposes
`detours_resolve_symbol(module, symbol)`.

---

### Anti-Tamper / Re-Hook Watchdog

Some code verifies its own integrity: a periodic self-check scans the bytes it
shipped with and **restores the original bytes**, silently removing a hook some
time after it was installed. A `Watchdog` keeps a hook stable across such a check -
it snapshots the bytes a hook left at the target and watches a background thread
for tampering. What it does next is **your choice**: re-apply the patch
(`WatchMode::Restore`, the default) or just report it (`WatchMode::DetectOnly`).
An optional `on_tamper` callback fires once per tamper episode either way.

```rust
use neohook::{DetourTransaction, Hook, Watchdog, WatchMode};
use std::time::Duration;

let mut tx = DetourTransaction::begin();
tx.update_all_threads();
tx.attach(target as *mut u8, detour as *const u8).unwrap();
let hooks = tx.commit().unwrap();

// Snapshot the patched prologue and guard it.
let (addr, len) = match &hooks[0] {
    Hook::Inline(h) => (h.target as *const u8, h.orig_bytes.len()),
    _ => unreachable!(),
};
let wd = Watchdog::with_interval(Duration::from_millis(50));

// Get notified on tamper (runs on the watchdog thread).
wd.on_tamper(|e| eprintln!("tamper at {:p}, restored={}", e.target, e.restored));

// Default re-applies the patch; switch to "detect, do not re-patch" with:
// wd.set_mode(WatchMode::DetectOnly);

let id = unsafe { wd.guard(addr, len) }.unwrap();
// wd.restorations() counts how many times Restore mode stepped in.

wd.unguard(id); // stop guarding *before* you unhook
```

It works at the byte level, so it is agnostic to *how* the patch was made: it
guards inline-hook jumps, the single `0xCC` of an INT3 hook, or any run of bytes
you point it at. In `Restore` mode, guard a region **after** the hook is
installed and **unguard it before** you unhook - otherwise the watchdog would
faithfully re-install the very patch you are trying to remove. The C ABI exposes
`detours_watchdog_create`, `detours_watchdog_guard`, `detours_watchdog_unguard`,
`detours_watchdog_set_mode`, `detours_watchdog_set_on_tamper`,
`detours_watchdog_restorations`, and `detours_watchdog_destroy`. See
[`examples/watchdog.rs`](examples/watchdog.rs).

---

### Tracing Detours - `detour_trace!`

Writing a detour whose only job is to log "this function was called with these
arguments and returned this" is pure boilerplate. `detour_trace!` generates it:
give it a target and its signature and it installs an inline hook that
`Debug`-formats every call's arguments and return value, emits a record, and
forwards to the original unchanged.

```rust
use neohook::{detour_trace, trace};

#[inline(never)]
extern "system" fn add(a: i32, b: i32) -> i32 { a + b }

fn main() {
    // Optional: route records into your logger instead of the default stderr.
    trace::set_sink(|r| println!("[trace] {}({}) => {}", r.function, r.args, r.ret));

    let _hooks = detour_trace!(add, "system" fn(a: i32, b: i32) -> i32)
        .expect("trace hook failed");

    assert_eq!(add(2, 3), 5); // logs: add(2, 3) => 5, returns the real result
}
```

Every argument type and the return type must implement `Debug` (integers,
pointers, and most FFI types already do). Where records go is decided by a
process-wide sink: the default writes one line per call to standard error;
`trace::set_sink` overrides it and `trace::clear_sink` restores the default.

When you do **not** want to spell out a signature, `trace_raw!` builds the tracer
on the `MidHook` / `HookContext` register-context bridge instead. It needs only
the target, hooks the entry, and dumps the integer argument registers as hex:

```rust
use neohook::trace_raw;

// No ABI, no argument types - just the function. Dumps the first 2 integer args.
let _hook = trace_raw!(some_function, args = 2).expect("raw trace failed");
// emits e.g.:  some_function(0x10, 0x20) -> <entry>
```

The trade-off mirrors the two foundations: `detour_trace!` (closure engine) gives
**typed arguments and the return value** but needs the signature; `trace_raw!`
(`HookContext`) needs **no signature** but only sees raw integer registers at
entry and has no return value to report, so its record's return field is the
literal `<entry>`. On **x86_64** those registers *are* the first four integer
arguments (`rcx`/`rdx`/`r8`/`r9`); on **x86**, where arguments are stack-passed
and not reachable from a mid-hook context, it dumps the general-purpose registers
as a snapshot instead (use `detour_trace!` for typed x86 arguments).

Like the [named registry](#named-hook-registry), tracing is a Rust-side ergonomic
layer (no C ABI), because formatting arbitrary argument types is a Rust-language
feature. See [`examples/trace_detour.rs`](examples/trace_detour.rs).

---

### Control Flow Guard (CFG) Awareness

[Control Flow Guard](https://learn.microsoft.com/en-us/windows/win32/secbp/control-flow-guard)
validates every **indirect** call (through a function pointer, a vtable slot, or
an import thunk) against a per-process bitmap of legal targets. A rejected target
ends the process with a non-catchable `RtlFailFast`.

Most hooking survives default CFG untouched, because the default configuration is
permissive in two ways that happen to cover the common cases: private executable
memory (where trampolines live) is allowed, and modules without a Guard CF table
are allowed wholesale. The stricter configurations a process can opt into are
where registration becomes load-bearing:

- **Strict mode** removes the private-memory exemption - trampolines, gateways,
  and export stubs must be registered.
- **Export suppression** drops exports from the valid set unless re-validated.
- A detour that points *inside* a CFG image at a non-entry address is rejected in
  any mode.

neohook registers its generated entry points and its IAT/EAT/VTable detours
through `SetProcessValidCallTargets` automatically. The layer auto-detects the
process's CFG mitigation policy and does nothing when CFG is not enforced, so it
costs nothing in the common case and hardens the strict ones.

```rust
use neohook::cfg;

// Usually nothing to do - registration is automatic inside the hook engines.
// Query or override the behaviour if you need to:
if cfg::is_enforced() {
    // Mark your own runtime-generated (e.g. JIT-emitted) code as callable
    // through a guarded indirect call.
    cfg::register_valid_target(my_generated_code_ptr);
}

// Force the handling on/off (e.g. for deterministic tests); None = auto-detect.
cfg::set_enforcement(None);
```

`GetProcessMitigationPolicy` / `SetProcessValidCallTargets` are resolved from
kernel32 at runtime, so neohook adds no static import on these APIs and still
loads on systems that predate them.

The C ABI exposes `detours_cfg_is_enforced`, `detours_cfg_set_enforcement`, and
`detours_cfg_register_valid_target`; the C++ wrapper mirrors them under
`neohook::cfg`.

---

## How It Works - Under the Hood

### The Problem with Naive Patching

Writing a `JMP` takes multiple bytes. On a live system, another CPU core may be executing those exact bytes as you overwrite them - causing an immediate crash. Even if you get lucky and avoid the race, a relative jump instruction (`E9 xx xx xx xx`) encodes a _distance from its own address_. Copy it verbatim to a new location and it jumps to the wrong place.

### The NeoHook Commit Sequence

For every inline hook, NeoHook builds a trampoline near the target function.

That trampoline contains two parts:

1. a managed gateway
2. a relocated body
   The managed gateway is a small NeoHook-owned jump stub that acts as a stable original_ptr() and can itself be hooked again later.

```
Original target
    │
    ├── patched to detour
    │
    └── trampoline
         ├── managed gateway
         └── relocated original instructions + jump back
```

Conceptually, the trampoline looks like this:

```
trampoline:
+-------------------------------+
| managed gateway               |  -> jumps to relocated body
+-------------------------------+
| relocated stolen instructions |
| jump back to target+stolen    |
+-------------------------------+
```

```
DetourTransaction::commit()
│
├─ 1. FREEZE  ──── SuspendThread() on every tracked process thread
│                   (except the calling thread)
│
├─ 2. SCAN    ──── For each suspended thread:
│                   a. Read thread context with GetThreadContext()
│                   b. If RIP/EIP points into the bytes that will be overwritten:
│                        redirect it to trampoline/body + offset
│                   c. Scan the top part of the stack for stale return addresses
│                      that still point into the soon-to-be-patched range
│                   d. Rewrite those return addresses to the relocated body
│
├─ 3. PATCH   ──── For each queued hook:
│                   a. If needed, build or prepare the trampoline
│                   b. Write the detour jump into the original target
│                   c. Register the trampoline gateway as the new managed gateway
│                   d. If the patched target was itself a managed gateway:
│                        remove the old gateway from the registry
│                   If any step fails:
│                        rollback applied hooks and restore redirected threads
│
└─ 4. THAW    ──── ResumeThread() on every suspended thread
```

### Instruction Relocation

The bytes overwritten at the hook site are copied to a trampoline buffer. Because these instructions often contain position-dependent encodings (RIP-relative loads, short branches, `CALL` targets), they cannot simply be copied verbatim. `iced-x86` decodes each stolen instruction, recomputes all relative offsets relative to the new trampoline address, and re-encodes the result.

A back-jump is appended at the end of the trampoline to return execution to the first un-stolen instruction in the original function. Calling through the trampoline is therefore equivalent to calling the original function.

### Smart Trampoline Allocation

On x86_64, a 5-byte `E9 rel32` jump can only reach ±2 GB. `TrampolineAlloc::alloc_nearby` scans free memory regions outward from the target using `VirtualQuery` and allocates within that window. If no suitable region exists within ±2 GB, the engine upgrades to a 14-byte indirect absolute jump (`FF 25 00000000 <abs64>`).

### Hook chaining

A managed gateway can itself be used as the target of another inline hook. This is how hook chaining works.

Suppose we hook target with detour_A.

```
Before:
target
  |
  v
[ original function ]
```

After the first hook:

```
target -----------------------> detour_A

gateway_A --------------------> trampoline_body_A
                                  |
                                  v
                         relocated stolen bytes
                                  |
                                  v
                            target + stolen_len
```

Now suppose `target` is hooked again with `detour_B`. That means the new target is no longer the real function entry. The new target is `gateway_A`. NeoHook reads the destination of gateway_A, then creates a new gateway:

```
gateway_B --------------------> previous target of gateway_A
                              = trampoline_body_A
```

---

## Architecture Overview

```
neohook/
├── src/
│   ├── lib.rs          - Public API surface, macros (detour_inline!, detour_helper!)
│   ├── api.rs          - DetourTransaction: high-level Rust API + C FFI entry points
│   ├── transaction.rs  - TransactionCore: commit/rollback engine
│   ├── alloc.rs        - TrampolineAlloc: near-memory allocation (x86 + x86_64)
│   ├── disasm.rs       - Disassembler: instruction length, relocation via iced-x86
│   ├── iat.rs          - IatHook: IAT parsing and pointer rewriting
│   ├── eat.rs          - EatHook: EAT parsing and export RVA rewriting (+ near stub)
│   ├── veh.rs          - VehHook: hardware-breakpoint hooking via a vectored handler
│   ├── int3.rs         - Int3Hook: INT3 software-breakpoint hooking via a vectored handler
│   ├── gateway.rs      - Call-original gateway builder for VEH / INT3 hooks
│   ├── midhook.rs      - MidHook: mid-function detours + register-context bridge
│   ├── pe.rs           - Shared bounds-checked PE parsing primitives
│   ├── scan.rs         - Pattern: signature parsing + memory/module scanning
│   ├── resolve.rs      - Resolve relative refs (call/jmp/rip) into absolute addresses
│   ├── symbols.rs      - Symbol-based resolution via dbghelp (resolve_symbol)
│   ├── delay.rs        - DelayHook: on-load hooks via an ntdll!LdrLoadDll detour
│   ├── registry.rs     - Process-wide named hook registry (+ unhook_all)
│   ├── watchdog.rs     - Watchdog: anti-tamper / re-hook byte-region guard
│   ├── trace.rs        - Tracing detour sink for detour_trace!
│   ├── introspect.rs   - Module / PE introspection (modules, exports, imports)
│   ├── mem.rs          - Memory helpers: VirtualProtect wrapper, atomic write
│   ├── module.rs       - Module utilities: find_function, get_module_handle
│   └── threads.rs      - ThreadEnumerator: toolhelp32 snapshot, open/suspend threads
└── include/
    ├── neohook.h    - Auto-generated C header (cbindgen)
    └── neohook.hpp  - C++ header
```

---

## Error Handling

All fallible operations return `Result<T, DetourError>`:

| Variant                         | When it occurs                                                                                           |
| :------------------------------ | :------------------------------------------------------------------------------------------------------- |
| `DetourError::NotStarted`       | Method called on a transaction that was already committed or aborted                                     |
| `DetourError::AllocationFailed` | No suitable free memory region found near the target address                                             |
| `DetourError::RelocationFailed` | `iced-x86` could not relocate the stolen instructions (e.g., RIP-relative target > 2 GB from trampoline) |
| `DetourError::InvalidParameter` | Null pointer passed, or the requested IAT import was not found in the module                             |
| `DetourError::Pattern`          | A byte signature passed to `attach_pattern` could not be parsed                                          |
| `DetourError::PatternNotFound`  | A valid signature did not match anywhere in the target module                                            |

`DetourError` implements `std::error::Error` and `Display`, so it works with `?`, `anyhow`, `thiserror`, etc.

---

## Development

### Running tests

```bash
cargo test -- --test-threads=1
```

You have to make sure that you use one thread or you risk race conditions.

### Fuzzing the relocator

Instruction relocation is the most safety-critical component (it re-encodes
build-controlled prologue bytes), so it has a dedicated fuzz harness. A fast,
deterministic invariant pass runs as part of the normal suite; the deep,
mutation-based fuzzer is `#[ignore]`d so it can be run on demand or on a
schedule:

```bash
# millions of corpus-seeded mutations; reproducible via the seed
NEOHOOK_FUZZ_ITERS=5000000 cargo test --release fuzz_relocate_deep -- --ignored --nocapture
```

It asserts the relocator never panics, never writes past the trampoline budget
(canary-guarded), keeps the old→new instruction-offset map consistent, and
preserves absolute branch / RIP-relative targets. Set `NEOHOOK_FUZZ_SEED` to
reproduce a specific run.

---

## License

Licensed under either of:

- **MIT License** ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)

at your option.
