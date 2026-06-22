// Pattern (signature) scanning and signature-based hook resolution.
//
// Many hook targets are unexported or stripped functions whose address moves
// between builds. A byte signature - opcode bytes with wildcards over the parts
// that change - locates them reliably at runtime.
//
// This example:
//   1. Derives a signature from a local function's prologue and resolves it
//      with `scan_module` / `scan_range`.
//   2. Hooks that function purely by signature with `attach_pattern`.
//
// Run with:  cargo run --example pattern_scan

use std::sync::OnceLock;

use neohook::{DetourTransaction, Pattern, scan_module, scan_range};
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW};

#[inline(never)]
extern "system" fn compute(x: i32) -> i32 {
    std::hint::black_box(x) * 3 + std::hint::black_box(1)
}

type ComputeFn = extern "system" fn(i32) -> i32;
static ORIG_COMPUTE: OnceLock<ComputeFn> = OnceLock::new();

extern "system" fn compute_detour(x: i32) -> i32 {
    let original = ORIG_COMPUTE.get().expect("original set");
    original(x) + 1000
}

/// Builds an IDA-style signature string from the first `len` bytes at `addr`.
fn signature_from(addr: *const u8, len: usize) -> String {
    let bytes = unsafe { std::slice::from_raw_parts(addr, len) };
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn main_module_name() -> String {
    let mut buf = [0u16; 1024];
    let len =
        unsafe { GetModuleFileNameW(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32) };
    let full = String::from_utf16_lossy(&buf[..len as usize]);
    full.rsplit(['\\', '/']).next().unwrap_or(&full).to_string()
}

fn main() {
    let target = compute as *const u8;
    let signature = signature_from(target, 20);
    println!("Derived signature for `compute`:\n  {signature}\n");

    // --- 1. Resolve the signature in memory ---------------------------------
    let pat = Pattern::parse(&signature).expect("valid signature");

    let main_module: HMODULE = unsafe { GetModuleHandleW(std::ptr::null()) };
    match unsafe { scan_module(main_module, &pat) } {
        Some(addr) => println!("scan_module    -> {addr:p} (target = {target:p})"),
        None => println!("scan_module    -> <not found>"),
    }
    match unsafe { scan_range(target, 256, &pat) } {
        Some(addr) => println!("scan_range     -> {addr:p}"),
        None => println!("scan_range     -> <not found>"),
    }

    // You can also build a signature from a byte array + mask string:
    let _code_style =
        Pattern::from_code_style(b"\x48\x8B\x00\x00", "xx??").expect("valid code-style signature");

    // --- 2. Hook the function purely by signature ---------------------------
    println!("\ncompute(10) before hook = {}", compute(10)); // 31

    let module = main_module_name();
    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();
    let trampoline = tx
        .attach_pattern(&module, &signature, compute_detour as *const u8)
        .expect("attach_pattern should resolve and queue the hook");
    ORIG_COMPUTE
        .set(unsafe { std::mem::transmute::<*mut u8, ComputeFn>(trampoline) })
        .ok();

    let hooks = tx.commit().expect("commit failed");
    println!("compute(10) while hooked = {}", compute(10)); // 1031

    drop(hooks); // RAII restores the original bytes.
    println!("compute(10) after unhook = {}", compute(10)); // 31
}
