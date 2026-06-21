// Demonstrates the anti-tamper / re-hook watchdog.
//
// Some code periodically verifies its own integrity and restores the original
// bytes, silently removing an inline hook. A Watchdog snapshots the patched
// bytes and re-applies them from a background thread the moment anything reverts
// them.
//
// Here we install a normal inline hook, simulate an integrity check restoring
// the original prologue, and watch the watchdog put the hook back.
/* Expected output (the [watchdog] line comes from the background thread and may
   interleave):
    before hook:    1
    after hook:     9999
    after tamper:   1 (hook removed)
    [watchdog] tamper at 0x... restored=true
    after watchdog: 9999 (re-applied 1 time(s))
    after unhook:   1
*/
use neohook::{DetourTransaction, Hook, Watchdog};
use std::error::Error;
use std::time::{Duration, Instant};
use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

#[inline(never)]
extern "system" fn protected() -> u32 {
    std::hint::black_box(1)
}

extern "system" fn detour() -> u32 {
    std::hint::black_box(9999)
}

// Force an indirect call so the optimizer cannot fold in the known return value
// and actually dispatches through the (possibly patched) function entry.
fn call(f: extern "system" fn() -> u32) -> u32 {
    let f = std::hint::black_box(f);
    f()
}

/// Simulates an external integrity check writing the original prologue back over
/// the target, which removes the hook's jump.
unsafe fn tamper(target: *mut u8, original: &[u8]) {
    let mut old = 0u32;
    unsafe {
        VirtualProtect(
            target as _,
            original.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old,
        );
        std::ptr::copy_nonoverlapping(original.as_ptr(), target, original.len());
        FlushInstructionCache(GetCurrentProcess(), target as _, original.len());
        let mut tmp = 0u32;
        VirtualProtect(target as _, original.len(), old, &mut tmp);
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let target_fn: extern "system" fn() -> u32 = protected;
    println!("before hook:    {}", call(target_fn));

    // Install a normal inline hook.
    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();
    tx.attach(protected as *mut u8, detour as *const u8)?;
    let hooks = tx.commit()?;
    println!("after hook:     {}", call(target_fn));

    // Pull the patched site and the original prologue bytes out of the inline
    // hook so we can both guard and tamper with the exact same region.
    let (target_addr, orig_bytes) = match &hooks[0] {
        Hook::Inline(h) => (h.target, h.orig_bytes.clone()),
        _ => unreachable!("attach installs an inline hook"),
    };

    // Guard the patched prologue: the watchdog snapshots whatever is there now
    // (the freshly written jump) and will re-apply it on tamper.
    let wd = Watchdog::with_interval(Duration::from_millis(20));

    // Get notified on tamper. The default WatchMode::Restore also re-applies the
    // patch; for "detect but do not re-patch" call wd.set_mode(WatchMode::DetectOnly).
    wd.on_tamper(|e| {
        println!(
            "[watchdog] tamper at {:p} restored={}",
            e.target, e.restored
        );
    });

    let _id = unsafe { wd.guard(target_addr as *const u8, orig_bytes.len()) }?;

    // A self-integrity check restores the original bytes -> the hook is removed.
    unsafe { tamper(target_addr, &orig_bytes) };
    println!("after tamper:   {} (hook removed)", call(target_fn));

    // Wait for the watchdog's next sweep to re-apply the patch.
    let start = Instant::now();
    while call(target_fn) != 9999 && start.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(10));
    }
    println!(
        "after watchdog: {} (re-applied {} time(s))",
        call(target_fn),
        wd.restorations()
    );

    // Stop the watchdog *before* unhooking, otherwise it would faithfully
    // re-install the very patch we are about to remove.
    drop(wd);
    drop(hooks);
    println!("after unhook:   {}", call(target_fn));

    Ok(())
}
