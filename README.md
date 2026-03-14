# NeoHook 🪝🦀

[![Crates.io](https://img.shields.io/crates/v/neohook.svg)](https://crates.io/crates/neohook)
[![License: MIT / Apache-2.0](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-blue.svg)](#license)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows)](https://www.microsoft.com/windows)
[![Arch: x86 / x86_64](https://img.shields.io/badge/arch-x86%20%7C%20x86__64-lightgrey)](https://en.wikipedia.org/wiki/X86)
[![CI](https://github.com/aliendwarf/neohook/actions/workflows/ci.yml/badge.svg)](https://github.com/aliendwarf/neohook/actions/workflows/ci.yml)

<img align="right" width="320px" height="320px" src="logo.png">


Hook any function in one line — transactional, and thread-safe. Leave pointer-to-pointer chaos behind.

NeoHook makes runtime function hooking simple and reliable: Win32 APIs, game engine functions, third-party DLL exports, anything with a code pointer. It brings the precision of low-level binary patching together with Rust's memory safety, type system, and RAII ownership model.

---

## Why NeoHook?

Function hooking is deceptively difficult to get right. Writing a `JMP` patch is only a few lines of assembly - but doing it safely in a live, multi-threaded process requires solving multiple problems at once:

| Problem                                               |          Naive approach          |                     NeoHook                      |
| :---------------------------------------------------- | :------------------------------: | :----------------------------------------------: |
| Another thread executes the bytes you are patching    |       Access Violation        |      ✅ Threads suspended during patch       |
| Instruction pointer on overwritten bytes        |             Crash             |  ✅ IP redirected   |
| Return address on stack points to patched region      |        Crash on return        |  ✅ Stack redirected   |
| JMP/CALL instructions break after relocation |         Wrong target          |  ✅ Instruction relocation via `iced-x86`   |
| One hook in a batch fails            |   Unstable    |       ✅ Atomic rollback - all or nothing        |
| Hook leaks after your code exits scope                | Permanent patch, crash on unload |       ✅ RAII: automatic unhook on `Drop`        |

---

## Features

- **Atomic Transactions** - Queue multiple hooks and commit them in one step. If any hook fails, every previously applied change in the same transaction is rolled back automatically, leaving the process in a known-good state.

- **Full Thread Safety** - Enumerates and suspends every thread in the process before applying patches.

- **RIP / EIP Redirection** - If a thread's instruction pointer falls within the bytes being overwritten, it is relocated.

- **Stack Scanning** - Scans the top 512 stack slots per thread for return addresses pointing into the patch area and rewrites them to the trampoline equivalent.

- **Instruction Relocation** - Uses [`iced-x86`](https://github.com/icedland/iced) to accurately decode, relocate, and re-encode.

- **Smart Trampoline Allocation** - On x64, allocates trampoline memory within ±2 GB of the target so that a compact 5-byte relative jump suffices. Falls back to a 14-byte absolute jump `(FF 25)`.

- **IAT Hooking** - Rewrites Import Address Table entries to redirect calls to entire DLL exports without touching function preambles.

- **Hook Chaining** - Detour the trampoline of an already-installed hook to layer multiple interceptors in a defined order.

- **RAII Ownership** - The `Vec<Hook>` returned by `commit()` unhooks and restores original memory automatically when dropped.

- **Zero-Boilerplate Macros** - `detour_inline!` and `detour_helper!` install a complete hook with a single expression.

- **C FFI** - Exposes a stable C ABI with auto-generated headers (`cbindgen`), usable from C, C++, Python (`ctypes`), or any FFI-capable language.

---

## Installation

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
NeoHook = { git = "https://github.com/AlienDwarf/neohook" }
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

static mut ORIG_SLEEP: Option<unsafe extern "system" fn(u32)> = None;

unsafe extern "system" fn hooked_sleep(ms: u32) {
    // Skip the actual sleep - or log, modify arguments, etc.
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
                &mut orig_ptr,
            )
            .expect("IAT hook failed");

        let _guard = session.commit().expect("transaction failed");
        ORIG_SLEEP = Some(std::mem::transmute(orig_ptr));

        // Sleep is now intercepted for this module
        windows_sys::Win32::System::Threading::Sleep(1000); // returns immediately
    }
}
```

---

### Keeping hooks alive (DLL injection / DllMain)

In Rust, values are dropped (and hooks uninstalled) when they leave scope. Inside a DLL that is injected into a running process, your initialization thread will eventually finish - taking your hooks with it unless you explicitly extend their lifetime.

The correct pattern is to move the hook guard into a `OnceLock<Vec<Hook>>` global:

```rust
use std::sync::OnceLock;
use neohook::{DetourTransaction, transaction::Hook};

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

NeoHook exposes a stable C ABI. Generate the header with:

```bash
cargo build --features generate-headers
```

The header is written to `include` directory.

**Notes on FFI ownership:**

- `detours_transaction_commit` takes ownership of the transaction pointer and frees it.
- The returned handle keeps hooks alive until you call `detours_handle_unhook_and_free`.
- All thread safety guarantees (suspension, RIP redirection, stack scanning) apply equally when called from C/C++.

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
│                        redirect it to trampoline/body + same offset
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
A managed gateway can itself be used as the target of another inline hook. That is how hook chaining works.
First hook

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
│   ├── mem.rs          - Memory helpers: VirtualProtect wrapper, atomic write
│   ├── module.rs      - Module utilities: find_function, get_module_handle
│   └── thread.rs      - ThreadEnumerator: toolhelp32 snapshot, open/suspend threads
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

`DetourError` implements `std::error::Error` and `Display`, so it works with `?`, `anyhow`, `thiserror`, etc.

---

## Development

### Running tests

```bash
cargo test -- --test-threads=1
```

You have to make sure that you use one thread or you risk race conditions.

---

## Disclaimer

This library is intended for **debugging, legitimate game modding, educational purposes, and reverse engineering of software you own or have explicit permission to analyse**.

The authors do not endorse use of this library for developing software that violates terms of service, circumvents security measures without authorisation, or causes harm to others.

---

## License

Licensed under either of:

- **MIT License** ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)

at your option.
