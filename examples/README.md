# NeoHook Examples

Runnable, self-contained examples for every hooking mechanism NeoHook provides.
Each file hooks something in **its own process** and prints (or renders) the
effect, so you can see a hook work end-to-end without a target application.

## Running

```bash
cargo run --example <name>
```

For example:

```bash
cargo run --example simple_hook
```

All examples build and run on both `x86_64-pc-windows-msvc` and
`i686-pc-windows-msvc`. The graphics and input examples open a window — see the
[Interactive / windowed](#interactive--windowed) note below.

---

## Start here — inline hooking & transactions

The core of NeoHook: overwrite a function prologue with a jump to your detour,
relocate the displaced instructions into a trampoline, and call the original
through it.

| Example | What it shows |
| :------ | :------------ |
| [`simple_hook`](simple_hook.rs) | The one-liner. `detour_inline!` hooks a local function — the smallest possible hook. |
| [`inline_sleep`](inline_sleep.rs) | Inline-hook a real Win32 export (`Sleep`), clamp the argument, and forward to the original. |
| [`transaction_two_hooks`](transaction_two_hooks.rs) | The Transaction API: queue two hooks and commit them atomically. |
| [`transaction_detach`](transaction_detach.rs) | Attach and later detach hooks through transactions. |
| [`managed_gateway_chain`](managed_gateway_chain.rs) | Hook chaining: stack multiple hooks on one target, each calling the previous original via a managed gateway. |

## Finding the target

Real targets are often unexported, stripped, or move between builds. These show
how to locate an address before hooking it.

| Example | What it shows |
| :------ | :------------ |
| [`attach_export`](attach_export.rs) | Hook a named export in one call — no manual `GetModuleHandle` / `GetProcAddress`. |
| [`pattern_scan`](pattern_scan.rs) | Signature (byte-pattern) scanning, then hooking purely by signature with `attach_pattern`. |
| [`resolve_relative`](resolve_relative.rs) | Turn a scan match on a `call rel32` / RIP-relative `lea` into the absolute target it references. |
| [`code_from_pointer_thunk`](code_from_pointer_thunk.rs) | Build a callable detour target from a raw code pointer with `detour_code_from_pointer`. |

## Import / Export table hooking

Redirect calls without touching the target's bytes by rewriting lookup tables.

| Example | What it shows |
| :------ | :------------ |
| [`iat_sleep`](iat_sleep.rs) | IAT hook: rewrite this module's imported `Sleep` slot (affects only calls through this module). |
| [`iat_messagebox`](iat_messagebox.rs) | IAT hook of `MessageBoxA`. |
| [`eat_hook`](eat_hook.rs) | EAT hook: rewrite an exporting module's export table so every *later* `GetProcAddress` resolves to your detour. |

## VTable & COM

| Example | What it shows |
| :------ | :------------ |
| [`vtable_hook`](vtable_hook.rs) | Patch a shared vtable slot (synthetic vtable array). |
| [`vtable_instance_hook`](vtable_instance_hook.rs) | Per-instance vtable hook — redirect one object without affecting others. |
| [`com_vtable_hook`](com_vtable_hook.rs) | Hook a real COM-style interface vtable (the `IUnknown` slot layout). |

## Other hooking mechanisms

Beyond the inline trampoline — different trade-offs in stealth, placement, and
how the redirect is triggered.

| Example | What it shows |
| :------ | :------------ |
| [`midhook`](midhook.rs) | Mid-function detour at an arbitrary instruction boundary, with a full readable/writable register `HookContext`. |
| [`veh_hook`](veh_hook.rs) | VEH hook: a hardware-breakpoint (debug register) redirect — the function body is never modified. |
| [`int3_hook`](int3_hook.rs) | INT3 software-breakpoint hook via a vectored handler. Installs six hooks at once (no four-register ceiling). |
| [`delay_hook`](delay_hook.rs) | Delay / on-load hook: arm a hook on a module that isn't loaded yet; it installs the moment the module appears. |

## Rust-native ergonomics

Things the C/C++ hooking libraries can't express cleanly.

| Example | What it shows |
| :------ | :------------ |
| [`closure_detour`](closure_detour.rs) | A detour that is a capturing Rust closure, receiving the original as its first argument. |
| [`trace_detour`](trace_detour.rs) | `detour_trace!` generates a logging detour that records arguments and return value, then forwards. |
| [`watchdog`](watchdog.rs) | Anti-tamper watchdog: re-applies the hook from a background thread the moment something restores the original bytes. |

## Interactive / windowed

These open a real window and run a render or message loop. Close the window to
exit. The overlay examples clear the window to **black** in the app's own draw
loop and draw a **red square** from inside the hook — so red on screen means the
hook is running.

| Example | What it shows |
| :------ | :------------ |
| [`force_keystroke_to_a`](force_keystroke_to_a.rs) | Hook `user32!GetMessageW` and rewrite every `WM_CHAR` to `'a'` in an edit control. |
| [`d3d11_present`](d3d11_present.rs) | Hook `IDXGISwapChain::Present` and draw an overlay each frame. |
| [`d3d9_endscene`](d3d9_endscene.rs) | Hook `IDirect3DDevice9::EndScene` (vtable slot 42) and draw an overlay each frame. |
| [`opengl_swapbuffers`](opengl_swapbuffers.rs) | Hook `wglSwapBuffers` and draw an overlay each frame. |

## Introspection

| Example | What it shows |
| :------ | :------------ |
| [`introspect`](introspect.rs) | Enumerate loaded modules, then list a module's entry point, exports, and imports. |

---

For the full API walkthrough and the "how it works under the hood" section, see
the [top-level README](../README.md).
