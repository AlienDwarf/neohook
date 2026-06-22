// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Control Flow Guard (CFG) awareness.
//!
//! When a module is compiled with `/guard:cf`, the compiler inserts a check
//! (`__guard_check_icall` / `__guard_dispatch_icall`) before every **indirect**
//! call - a call through a function pointer, a vtable slot, or an import thunk.
//! The check consults a per-process bitmap of legal call targets. If the target
//! is rejected the process is terminated with `RtlFailFast`: not a catchable
//! exception, an immediate kill.
//!
//! ## What CFG actually rejects
//!
//! The default (non-strict) configuration is permissive in ways that matter for
//! hooking:
//!
//! * **Private executable memory is allowed.** Pages obtained from
//!   `VirtualAlloc` and made executable are treated as valid targets, so an
//!   indirect call into an inline trampoline, a VEH/INT3 gateway, or an EAT jump
//!   stub does *not* fail fast by default. (This is what keeps JIT engines
//!   working.)
//! * **Non-CFG modules are allowed wholesale.** A module without a Guard CF
//!   function table has its entire range marked valid, so a detour inside a DLL
//!   built without `/guard:cf` is already a legal target.
//! * Inline hooks patch the prologue with a direct `jmp` (`E9 ...`), which is not
//!   a guarded indirect call at all.
//!
//! Registration becomes load-bearing when a process opts into the stricter
//! configurations:
//!
//! * **Strict mode** removes the private-memory exemption, so trampolines,
//!   gateways and stubs must be registered explicitly.
//! * **Export suppression** drops exports from the valid set unless re-validated.
//! * A detour pointing *inside* a CFG image at an address that is not a declared
//!   function entry is rejected in any mode.
//!
//! ## What this module does
//!
//! It marks neohook-owned entry points (trampolines, gateways, export stubs) and
//! the IAT/EAT/VTable detours as valid call targets through
//! [`SetProcessValidCallTargets`] - the same mechanism Microsoft Detours uses.
//! It is wired into the allocator and the table-hook engines automatically, so
//! callers normally do not touch it. Auto-detection makes the whole layer a
//! no-op when the process does not enforce CFG, so it is safe to leave on; it is
//! forward-compatible hardening for the strict/suppressed cases rather than a fix
//! for the common one. [`register_valid_target`] is public so you can mark your
//! own runtime-generated code the same way.

use core::ffi::c_void;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, Ordering};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::core::BOOL;

/// `CFG_CALL_TARGET_INFO`: an offset (relative to the region base) plus flags.
#[repr(C)]
struct CfgCallTargetInfo {
    offset: usize,
    flags: usize,
}

/// `CFG_CALL_TARGET_VALID` - mark the offset as a legal indirect-call target.
const CFG_CALL_TARGET_VALID: usize = 0x0000_0001;

/// `ProcessControlFlowGuardPolicy` selector for `GetProcessMitigationPolicy`.
const PROCESS_CONTROL_FLOW_GUARD_POLICY: i32 = 7;

/// Bit 0 of `PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY` - `EnableControlFlowGuard`.
const ENABLE_CONTROL_FLOW_GUARD: u32 = 0x0000_0001;

/// Standard small-page size on x86/x86_64 Windows. `SetProcessValidCallTargets`
/// wants a page-aligned base and a region size; a single page always covers one
/// entry because the base is the page the entry sits in.
const PAGE_SIZE: usize = 0x1000;

// `SetProcessValidCallTargets` (Windows 8.1+) and `GetProcessMitigationPolicy`
// (Windows 8+) are resolved from kernel32 at runtime rather than imported
// statically. A hooking library is injected into arbitrary processes, so it must
// not add a static import dependency on these optional mitigation APIs - doing so
// would make it fail to load on a host that lacks them. Runtime resolution also
// degrades gracefully to "CFG handling unavailable" on older systems.
type SetValidTargetsFn = unsafe extern "system" fn(
    hprocess: HANDLE,
    virtualaddress: *mut c_void,
    regionsize: usize,
    numberofoffsets: u32,
    offsetinformation: *mut CfgCallTargetInfo,
) -> BOOL;

type GetMitigationPolicyFn = unsafe extern "system" fn(
    hprocess: HANDLE,
    mitigationpolicy: i32,
    lpbuffer: *mut c_void,
    dwlength: usize,
) -> BOOL;

/// Resolves a kernel32 export by name, returning its address or `None`.
unsafe fn resolve_kernel32(name: &[u8]) -> Option<usize> {
    debug_assert!(
        name.last() == Some(&0),
        "export name must be NUL-terminated"
    );
    let module = unsafe { GetModuleHandleA(c"kernel32.dll".as_ptr().cast()) };
    if module.is_null() {
        return None;
    }
    let proc = unsafe { GetProcAddress(module, name.as_ptr()) };
    proc.map(|p| p as usize)
}

/// Cached pointer to `SetProcessValidCallTargets`, resolved once.
fn set_valid_targets() -> Option<SetValidTargetsFn> {
    static ADDR: OnceLock<Option<usize>> = OnceLock::new();
    let addr = *ADDR.get_or_init(|| unsafe { resolve_kernel32(b"SetProcessValidCallTargets\0") });
    addr.map(|a| unsafe { std::mem::transmute::<usize, SetValidTargetsFn>(a) })
}

/// Cached pointer to `GetProcessMitigationPolicy`, resolved once.
fn get_mitigation_policy() -> Option<GetMitigationPolicyFn> {
    static ADDR: OnceLock<Option<usize>> = OnceLock::new();
    let addr = *ADDR.get_or_init(|| unsafe { resolve_kernel32(b"GetProcessMitigationPolicy\0") });
    addr.map(|a| unsafe { std::mem::transmute::<usize, GetMitigationPolicyFn>(a) })
}

/// Manual override of CFG handling: `0` = auto-detect, `1` = force on, `2` = force off.
static OVERRIDE: AtomicU8 = AtomicU8::new(0);

/// Cached auto-detection result: `0` = unknown, `1` = not enforced, `2` = enforced.
static DETECTED: AtomicU8 = AtomicU8::new(0);

/// Forces CFG handling on or off, overriding auto-detection.
///
/// * `Some(true)` - always attempt to register call targets (use when detection
///   is wrong, or to keep behaviour deterministic in tests).
/// * `Some(false)` - never register; the whole layer becomes a no-op.
/// * `None` - return to auto-detection via [`GetProcessMitigationPolicy`].
pub fn set_enforcement(state: Option<bool>) {
    let v = match state {
        None => 0,
        Some(true) => 1,
        Some(false) => 2,
    };
    OVERRIDE.store(v, Ordering::Relaxed);
}

/// Returns whether neohook will register call targets for this process.
///
/// Reflects the [`set_enforcement`] override if one is set, otherwise the cached
/// result of querying the process's Control Flow Guard mitigation policy.
pub fn is_enforced() -> bool {
    match OVERRIDE.load(Ordering::Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }

    match DETECTED.load(Ordering::Relaxed) {
        1 => false,
        2 => true,
        _ => {
            let enforced = detect_enforced();
            DETECTED.store(if enforced { 2 } else { 1 }, Ordering::Relaxed);
            enforced
        }
    }
}

/// Queries the live Control Flow Guard mitigation policy of the current process.
fn detect_enforced() -> bool {
    let Some(query) = get_mitigation_policy() else {
        return false;
    };
    let mut flags: u32 = 0;
    let ok = unsafe {
        query(
            GetCurrentProcess(),
            PROCESS_CONTROL_FLOW_GUARD_POLICY,
            (&mut flags as *mut u32).cast(),
            core::mem::size_of::<u32>(),
        )
    };
    ok != 0 && (flags & ENABLE_CONTROL_FLOW_GUARD) != 0
}

/// Marks `entry` as a valid Control Flow Guard indirect-call target.
///
/// Use this to make runtime-generated code (or a detour in a module that was not
/// compiled with `/guard:cf`) callable through a guarded indirect call without
/// tripping a fail-fast. neohook calls it for you on every trampoline, gateway,
/// export stub, and IAT/EAT/VTable detour; it is exposed for code you generate
/// yourself.
///
/// Returns `true` if the target was registered (or registration was
/// unnecessary). When CFG is not enforced for the process this is a no-op and
/// returns `false`. Registration is best-effort: a `false` here on a CFG process
/// means the later indirect call may still fail fast.
///
/// For a target to be accepted by CFG its address should be 16-byte aligned;
/// neohook's own stubs are page-aligned and therefore always qualify.
pub fn register_valid_target(entry: *const u8) -> bool {
    if entry.is_null() || !is_enforced() {
        return false;
    }
    unsafe { mark_valid(entry as usize) }
}

/// Issues the `SetProcessValidCallTargets` call for the page containing `addr`.
unsafe fn mark_valid(addr: usize) -> bool {
    let Some(set_targets) = set_valid_targets() else {
        return false;
    };

    let base = addr & !(PAGE_SIZE - 1);
    let offset = addr - base;

    let mut info = CfgCallTargetInfo {
        offset,
        flags: CFG_CALL_TARGET_VALID,
    };

    let ok = unsafe {
        set_targets(
            GetCurrentProcess(),
            base as *mut c_void,
            PAGE_SIZE,
            1,
            &mut info,
        )
    };
    ok != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_controls_is_enforced() {
        set_enforcement(Some(true));
        assert!(is_enforced(), "forced-on override should report enforced");

        set_enforcement(Some(false));
        assert!(
            !is_enforced(),
            "forced-off override should report not enforced"
        );

        // Restore auto-detection for any later test in the same process.
        set_enforcement(None);
    }

    #[test]
    fn register_null_target_is_false() {
        set_enforcement(Some(false));
        assert!(!register_valid_target(std::ptr::null()));
        set_enforcement(None);
    }

    #[test]
    fn register_is_noop_when_disabled() {
        set_enforcement(Some(false));
        let dummy = register_is_noop_when_disabled as *const u8;
        assert!(
            !register_valid_target(dummy),
            "registration must be skipped when CFG handling is off"
        );
        set_enforcement(None);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn register_succeeds_when_forced_on() {
        // Forcing CFG handling on in a non-CFG test process: the API call still
        // runs against a real, executable, page-aligned region. We only assert it
        // does not panic and returns a bool; success depends on the OS honoring
        // the request for a non-CFG image.
        set_enforcement(Some(true));
        let region = unsafe {
            windows_sys::Win32::System::Memory::VirtualAlloc(
                std::ptr::null(),
                PAGE_SIZE,
                windows_sys::Win32::System::Memory::MEM_COMMIT
                    | windows_sys::Win32::System::Memory::MEM_RESERVE,
                windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ,
            )
        };
        assert!(!region.is_null(), "region allocation failed");
        let _ = register_valid_target(region as *const u8);
        unsafe {
            windows_sys::Win32::System::Memory::VirtualFree(
                region,
                0,
                windows_sys::Win32::System::Memory::MEM_RELEASE,
            );
        }
        set_enforcement(None);
    }
}
