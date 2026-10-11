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

## What's New in 0.16.0

- **Signature inference** - estimate a function's arguments, return type and calling convention from its machine code ([`infer_signature`](#more-features)).
- **Hook detection** - find inline, INT3, VEH, IAT and EAT hooks and where they lead ([`check_function`, `scan_module_hooks`](#more-features)).
- **x64 unwind data** for trampolines, gateways and mid-hook stubs, so exceptions and stack walks pass through them.
- Many fixes: handlers are removed with the last hook (DLLs using NeoHook unload cleanly), no deadlock between `unhook_all` in `DllMain` and an open transaction, whole-stack return-address redirection, hardened PE parsing.

The full list is in the [`v0.16.0` tag](https://github.com/aliendwarf/neohook/releases/tag/v0.16.0).

---

## Why NeoHook?

Writing a `JMP` patch is a few lines of assembly - doing it safely in a live, multi-threaded process is not:

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

**Hooking methods**

- **Inline hooks** with instruction relocation ([`iced-x86`](https://github.com/icedland/iced)) and a trampoline to call the original.
- **IAT / EAT hooks** - rewrite an import slot (one module's calls) or an export entry (every later `GetProcAddress`).
- **VTable hooks** - shared slot or per-instance cloned table.
- **VEH hooks** - hardware breakpoints, no byte modified (four at a time).
- **INT3 hooks** - one `0xCC` byte, up to 256 targets, covers threads created later.
- **Mid-function hooks** - at any instruction, with all registers, flags, XMM and `MXCSR` readable and writable.
- **Closure detours**, **delay hooks** for modules not loaded yet, **hook chaining**, **enable / disable**.

**Safety**

- Atomic transactions with rollback; one transaction at a time process-wide.
- Threads suspended while patching; instruction pointers and return addresses (whole stack) redirected.
- Trampolines within ±2 GB on x64 (5-byte jump), 14-byte absolute jump otherwise.
- RAII unhook on `Drop`; retired stubs freed only once no thread references them.
- Control Flow Guard aware; x64 unwind data for every stub.

**Finding targets**

- Export name (`attach_export`), byte signature (`attach_pattern`), PDB symbol (`resolve_symbol`), module / export / import enumeration.
- Relative-reference resolving after a scan, signature inference, hook detection.

**Tooling**

- One-line macros (`detour_inline!`, `detour_helper!`), tracing detours (`detour_trace!`, `trace_raw!`), named hook registry, reentrancy guard, anti-tamper watchdog.
- C ABI (`cbindgen` header) and an RAII C++ wrapper.

---

## Installation

```toml
[dependencies]
neohook = "0.16.0"
```

---

## Quick Start

Replace a function completely:

```rust
use neohook::detour_inline;

#[inline(never)]
fn target(x: i32) -> i32 { std::hint::black_box(x) * 2 }
fn detour(x: i32) -> i32 { x + 100 }

fn main() {
    let _hook = detour_inline!(target, detour).expect("hook failed");
    assert_eq!(target(5), 105); // intercepted
    // _hook drops here => original bytes restored
}
```

---

## Usage

### Call the original - `detour_helper!`

```rust
use std::sync::OnceLock;
use neohook::detour_helper;

type AddFn = fn(i32, i32) -> i32;
static ORG_ADD: OnceLock<AddFn> = OnceLock::new();

#[inline(never)]
fn add(a: i32, b: i32) -> i32 { a + b }

fn detour_add(a: i32, b: i32) -> i32 {
    ORG_ADD.get().expect("original not set")(a, b) * 10
}

fn main() {
    // (static for the original, target, detour, function type)
    let _hook = detour_helper!(ORG_ADD, add, detour_add, AddFn).expect("hook failed");
    assert_eq!(add(2, 3), 50);
}
```

### Transactions

Install several hooks atomically - if one fails, none stays applied:

```rust
use neohook::DetourTransaction;

let mut tx = DetourTransaction::begin();
tx.update_all_threads(); // suspended while the commit patches

let original_a = tx.attach(fn_a as *mut u8, detour_a as *const u8).unwrap(); // trampoline
tx.attach(fn_b as *mut u8, detour_b as *const u8).unwrap();

let hooks = tx.commit().expect("transaction failed"); // Vec<Hook>, unhooked on drop
```

`attach` follows leading jump thunks to the real function body. Queueing the same
target twice with the same detour patches it once; with a different detour it is
rejected - chain onto the returned trampoline instead.

### IAT hooks

Redirect one module's calls to an import, without touching the function itself:

```rust
use std::sync::OnceLock;
use neohook::DetourTransaction;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

type SleepFn = unsafe extern "system" fn(u32);
static ORIG_SLEEP: OnceLock<SleepFn> = OnceLock::new();

unsafe extern "system" fn hooked_sleep(ms: u32) {
    if let Some(orig) = ORIG_SLEEP.get() {
        unsafe { orig(ms / 2) };
    }
}

fn main() {
    let exe = unsafe { GetModuleHandleW(std::ptr::null()) };
    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();
    tx.attach_iat(exe, "KERNEL32.dll", "Sleep", hooked_sleep as *const u8)
        .expect("IAT hook failed");
    let hooks = tx.commit().expect("transaction failed");
    let _ = ORIG_SLEEP.set(unsafe { std::mem::transmute(hooks[0].original_ptr()) });
}
```

### Mid-function hooks

Hook any instruction and read or change the live CPU state:

```rust
use neohook::{HookContext, MidHook};

#[inline(never)]
extern "system" fn price_for(quantity: u64) -> u64 {
    std::hint::black_box(quantity) * 100
}

unsafe extern "C" fn handler(ctx: *mut HookContext) {
    let ctx = unsafe { &mut *ctx };
    ctx.rcx = ctx.rcx.wrapping_add(5); // Win64: first argument in RCX
}

fn main() {
    let hook = unsafe { MidHook::install(price_for as *const u8, handler) }.unwrap();
    assert_eq!(price_for(2), 700); // (2 + 5) * 100
    hook.unhook().unwrap();
}
```

The handler can also set `ctx.redirect_rip` (`redirect_eip` on x86) to continue
somewhere else, e.g. `hook.resume_address()` to skip the patched instructions.
XMM registers are in `ctx.xmm[..]`; the x87 stack is not captured.

### VEH and INT3 hooks

Breakpoint-based hooks replace the target without a jump patch:

```rust
use neohook::{Int3Hook, VehHook};

let veh = unsafe { VehHook::install(target, detour) }.unwrap();   // no byte changed, max. 4
let int3 = unsafe { Int3Hook::install(target2, detour) }.unwrap(); // one 0xCC byte, max. 256
```

Both are full replacements; `install_with_original` builds a gateway
(`hook.original_ptr()`) to call the original. VEH breakpoints are per-thread:
threads created after the install are not armed.

### Keeping hooks alive in a DLL

Hooks are removed when their guard drops. In an injected DLL, move the guard
into a global so it outlives the initialization thread:

```rust
use std::sync::OnceLock;
use neohook::{DetourTransaction, Hook};

static ACTIVE_HOOKS: OnceLock<Vec<Hook>> = OnceLock::new();

fn install_hooks() {
    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();
    tx.attach(target as *mut u8, detour as *const u8).unwrap();
    let _ = ACTIVE_HOOKS.set(tx.commit().expect("hook install failed"));
}
```

For a single teardown point (e.g. `DLL_PROCESS_DETACH`), park hooks in the
[named registry](#more-features) and call `registry::unhook_all()`.

### C / C++

`include/neohook.h` (generated with `cargo build --features generate-headers`)
exposes the C ABI; `include/neohook.hpp` wraps it in RAII types. A committed
transaction returns a handle that keeps its hooks alive until
`detours_handle_unhook_and_free`. See [`examples/c`](examples/c) and
[`examples/cpp`](examples/cpp).

### More features

| Feature | API | Example |
| :------ | :-- | :------ |
| EAT hooks | `attach_eat` - every later `GetProcAddress` gets the detour | [`eat_hook.rs`](examples/eat_hook.rs) |
| Hook by export name | `attach_export("user32.dll", "MessageBoxW", detour)` | [`attach_export.rs`](examples/attach_export.rs) |
| Signature scanning | `Pattern::parse("48 8B 05 ?? ??")`, `scan_module`, `attach_pattern` | [`pattern_scan.rs`](examples/pattern_scan.rs) |
| Relative references | `resolve_call_target`, `resolve_rip_relative` after a scan | [`resolve_relative.rs`](examples/resolve_relative.rs) |
| Signature inference | `infer_signature(ptr)` / `infer_signature_by_name(module, name)`: argument count and types, return type, calling convention - an estimate from the machine code | [`signature.cpp`](examples/cpp/signature.cpp) |
| Hook detection | `check_function`, `check_export`, `scan_module_hooks`: inline, INT3, VEH, IAT and EAT hooks compared against the module file and debug registers, with destination and owning module | [`hook_detection.cpp`](examples/cpp/hook_detection.cpp) |
| Closure detours | `detour_closure!(target, "system" fn(a: i32) -> i32, move \|orig, a\| ...)` - capturing `Fn + Send + Sync` closures | [`closure_detour.rs`](examples/closure_detour.rs) |
| Delay hooks | `DelayHook::register("d3d11.dll", "Func", detour)` - installed when the module loads | [`delay_hook.rs`](examples/delay_hook.rs) |
| Named registry | `registry::register`, `enable` / `disable`, `unhook_all` | - |
| VTable hooks | `attach_vtable`, `attach_vtable_instance` (per object) | [`vtable_hook.rs`](examples/vtable_hook.rs), [`com_vtable_hook.rs`](examples/com_vtable_hook.rs) |
| Graphics APIs | `Present`, `Present1`, `EndScene`, `wglSwapBuffers` - runnable without a GPU | [`d3d11_present.rs`](examples/d3d11_present.rs), [`d3d9_endscene.rs`](examples/d3d9_endscene.rs), [`opengl_swapbuffers.rs`](examples/opengl_swapbuffers.rs) |
| Introspection | `enumerate_modules`, `enumerate_exports`, `enumerate_imports`, `find_function_by_ordinal` | [`introspect.rs`](examples/introspect.rs) |
| PDB symbols | `resolve_symbol("ntdll.dll", "LdrpInitializeProcess")` via `dbghelp` | - |
| Watchdog | `Watchdog::guard` re-applies (or reports) a patch that something restored | [`watchdog.rs`](examples/watchdog.rs) |
| Tracing | `detour_trace!(f, "system" fn(a: i32) -> i32)` logs arguments and result; `trace_raw!(f, args = 2)` needs no signature | [`trace_detour.rs`](examples/trace_detour.rs) |
| Control Flow Guard | automatic; `cfg::register_valid_target` for your own generated code | - |
| Enable / disable, reentrancy | `Hook::enable` / `disable`, `reentrancy_guard!` | - |

Nearly everything above is also in the C ABI and the C++ wrapper; the registry
and tracing are Rust-only.

---

## How It Works

### The problem

A `JMP` patch takes several bytes. Another core may be executing exactly those
bytes while they are overwritten, and a relative jump (`E9 rel32`) copied to a new
address jumps to the wrong place.

### The commit sequence

Every inline hook gets a trampoline near the target: a **managed gateway** (a
small jump stub that is the stable `original_ptr()` and can itself be hooked)
followed by the **relocated stolen instructions** and a jump back.

```
DetourTransaction::commit()
│
├─ 1. PREPARE ── allocate and build everything that needs memory, take the
│                code-write lock (nothing may allocate while threads are frozen)
├─ 2. FREEZE  ── SuspendThread() on every tracked thread
├─ 3. REDIRECT ─ an instruction pointer inside the stolen bytes moves to the
│                trampoline; so does a return address into them anywhere on the stack
├─ 4. PATCH   ── write the jump into each target; on any failure roll back
│                every patch and redirection
├─ 5. THAW    ── ResumeThread()
└─ 6. PUBLISH ── register the new gateways for chaining, finalize detaches
```

### Relocation and allocation

`iced-x86` decodes the stolen instructions and re-encodes them for the
trampoline's address (RIP-relative operands, branches, calls). On x64 the
trampoline is placed within ±2 GB of the target so a 5-byte `E9 rel32` reaches
it; otherwise a 14-byte `FF 25` absolute jump is used.

### Unwinding (x64)

x64 unwinding needs a `RUNTIME_FUNCTION` for every frame. Each stub gets one,
registered with `RtlAddFunctionTable`: trampolines and gateways reuse the
target's prologue unwind codes with their offsets translated through the
relocation; mid-hook stubs describe their own frame and store the hooked address
where a return address would be. Exceptions and stack walks then pass through
stubs to the caller. x86 unwinds through frame chains and needs none of this.

### Hook chaining

To layer a second detour, attach it to the first hook's managed gateway - the
trampoline `attach` returned. Each detour calls the next through its own
gateway:

```
target ──► detour_A ──► gateway_A (hooked) ──► detour_B ──► gateway_B ──► original body
```

See [`managed_gateway_chain.rs`](examples/managed_gateway_chain.rs).

---

## Architecture

```
src/
├── lib.rs          - public API, macros
├── code.rs         - follows jump thunks to the real function body
├── api.rs          - DetourTransaction + C ABI
├── transaction.rs  - commit / rollback engine, locks
├── alloc.rs        - near-target trampoline allocation
├── disasm.rs       - instruction length + relocation (iced-x86)
├── iat.rs, eat.rs, vtable.rs, veh.rs, int3.rs, midhook.rs, delay.rs - hook kinds
├── gateway.rs      - call-the-original gateway for VEH / INT3
├── inflight.rs     - traps still dispatching before a handler is removed
├── reclaim.rs      - quiescence-checked release of retired stubs
├── unwind.rs       - x64 unwind data for stubs
├── pe.rs, introspect.rs, module.rs, symbols.rs - PE parsing, enumeration, lookup
├── scan.rs, resolve.rs, signature.rs, detect.rs - finding and analysing targets
├── registry.rs, watchdog.rs, trace.rs, cfg.rs, reentrancy.rs - tooling
└── mem.rs, threads.rs - memory writes, thread enumeration
include/
├── neohook.h       - generated C header
└── neohook.hpp     - C++ wrapper
```

---

## Error Handling

Fallible operations return `Result<T, DetourError>` (`std::error::Error` + `Display`):

| Variant | When |
| :------ | :--- |
| `NotStarted` | The transaction was already committed or aborted |
| `AllocationFailed` | No free memory near the target |
| `RelocationFailed` | The stolen instructions cannot be relocated, or a thread could not be redirected |
| `InvalidParameter` | Null pointer, target too short, overlapping or duplicate hook |
| `Pattern` / `PatternNotFound` | A signature does not parse / does not match |
| `Iat` / `Eat` / `Vtable` | The table hook failed (missing import or export, protection change) |
| `CommitFailed { index, kind, source }` | Which queued hook failed, after the commit rolled back |

---

## Development

```bash
cargo test   # tests run single-threaded (set in .cargo/config.toml)
```

The relocator has a mutation fuzzer, ignored by default:

```bash
NEOHOOK_FUZZ_ITERS=5000000 cargo test --release fuzz_relocate_deep -- --ignored --nocapture
```

`NEOHOOK_FUZZ_SEED` reproduces a run.

### Roadmap

- ARM64 inline hooking (planned)

---

## License

Licensed under either of:

- **MIT License** ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)

at your option.
