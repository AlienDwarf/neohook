#![cfg(windows)]

//! Integration tests for mid-function / arbitrary-address detours.
//!
//! The strongest assertions (observing and rewriting a live argument register)
//! are x86_64-only, because on x86 `extern "system"` passes arguments on the
//! stack rather than in registers. The mechanism itself - snapshot, invoke,
//! restore, continue - is identical on both architectures and is covered by the
//! "called" and "unhook restores" tests on every target.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use neohook::{HookContext, MidHook};

// A function whose entry we treat as an arbitrary code address to detour.
// `black_box` keeps the compiler from constant-folding or inlining it away.
#[inline(never)]
extern "system" fn triple(x: u64) -> u64 {
    std::hint::black_box(x).wrapping_mul(3)
}

#[inline(never)]
extern "system" fn noop_work(x: u64) -> u64 {
    std::hint::black_box(x).wrapping_add(1)
}

static HANDLER_RAN: AtomicBool = AtomicBool::new(false);
static OBSERVED_ARG: AtomicU64 = AtomicU64::new(0);

unsafe extern "system" fn observe_handler(ctx: *mut HookContext) {
    HANDLER_RAN.store(true, Ordering::SeqCst);
    let ctx = unsafe { &*ctx };
    #[cfg(target_arch = "x86_64")]
    OBSERVED_ARG.store(ctx.rcx, Ordering::SeqCst); // Win64: first integer arg in RCX
    #[cfg(target_arch = "x86")]
    let _ = ctx;
}

#[cfg(target_arch = "x86_64")]
unsafe extern "system" fn add_to_arg_handler(ctx: *mut HookContext) {
    // Rewrite the first argument (RCX) in flight: x -> x + 10.
    let ctx = unsafe { &mut *ctx };
    ctx.rcx = ctx.rcx.wrapping_add(10);
}

#[test]
fn handler_runs_and_function_still_returns_correctly() {
    HANDLER_RAN.store(false, Ordering::SeqCst);

    assert_eq!(noop_work(41), 42); // baseline

    let hook = unsafe { MidHook::install(noop_work as *const u8, observe_handler) }
        .expect("mid-function hook should install");

    // The detour fires, then the original instructions resume unchanged.
    let result = noop_work(41);
    assert!(HANDLER_RAN.load(Ordering::SeqCst), "handler must have run");
    assert_eq!(result, 42, "original computation must complete after the detour");

    hook.unhook().expect("unhook should succeed");

    // After unhook the handler no longer fires.
    HANDLER_RAN.store(false, Ordering::SeqCst);
    assert_eq!(noop_work(41), 42);
    assert!(
        !HANDLER_RAN.load(Ordering::SeqCst),
        "handler must not run after unhook"
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn handler_observes_live_argument_register() {
    OBSERVED_ARG.store(0, Ordering::SeqCst);

    let hook = unsafe { MidHook::install(triple as *const u8, observe_handler) }
        .expect("install");

    let _ = triple(7);
    assert_eq!(
        OBSERVED_ARG.load(Ordering::SeqCst),
        7,
        "handler should see the argument in RCX"
    );

    hook.unhook().expect("unhook");
}

#[cfg(target_arch = "x86_64")]
#[test]
fn handler_can_rewrite_a_register_in_flight() {
    assert_eq!(triple(5), 15); // baseline: 5 * 3

    let hook = unsafe { MidHook::install(triple as *const u8, add_to_arg_handler) }
        .expect("install");

    // Handler bumps RCX (the argument) by 10 before the body runs: (5 + 10) * 3.
    assert_eq!(triple(5), 45, "register edit must take effect");

    hook.unhook().expect("unhook");
    assert_eq!(triple(5), 15, "behaviour restored after unhook");
}

#[test]
fn install_rejects_null_target() {
    let err = unsafe { MidHook::install(std::ptr::null(), observe_handler) };
    assert!(err.is_err(), "null target must be rejected");
}

#[test]
fn dropping_the_guard_unhooks() {
    HANDLER_RAN.store(false, Ordering::SeqCst);

    {
        let _hook = unsafe { MidHook::install(noop_work as *const u8, observe_handler) }
            .expect("install");
        let _ = noop_work(1);
        assert!(HANDLER_RAN.load(Ordering::SeqCst));
    } // _hook drops here -> original bytes restored

    HANDLER_RAN.store(false, Ordering::SeqCst);
    let _ = noop_work(1);
    assert!(
        !HANDLER_RAN.load(Ordering::SeqCst),
        "drop should have restored the original bytes"
    );
}
