// Demonstrates IAT hooking by replacing this module's imported Sleep() entry.
// Unlike an inline hook, this only affects calls that go through the current
// module's import table.
/* Expected output:
    before hook: slept for ~5xx ms
    hooked Sleep import from KERNEL32.dll
    [iat detour] Sleep(500) intercepted
    [iat detour] forwarding to original Sleep(100)
    after hook: slept for ~1xx ms
    after unhook: slept for ~5xx ms
*/
use neohook::TransactionCore;
use std::error::Error;
use std::ptr;
use std::time::Instant;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
use windows_sys::Win32::System::Threading::Sleep;

type SleepFn = unsafe extern "system" fn(u32);

static mut ORIGINAL_SLEEP: Option<SleepFn> = None;

unsafe extern "system" fn sleep_detour(ms: u32) {
    println!("[iat detour] Sleep({ms}) intercepted");

    let original = unsafe { ORIGINAL_SLEEP.expect("ORIGINAL_SLEEP not initialized") };

    let shortened = ms.min(100);
    println!("[iat detour] forwarding to original Sleep({shortened})");

    unsafe { original(shortened) };
}

fn main() -> Result<(), Box<dyn Error>> {
    let module = unsafe { GetModuleHandleA(ptr::null()) };
    if module.is_null() {
        return Err("GetModuleHandleA(NULL) failed".into());
    }

    let before = Instant::now();
    unsafe { Sleep(500) };
    println!("before hook: slept for ~{} ms", before.elapsed().as_millis());

    let mut original: *mut u8 = ptr::null_mut();
    let mut tx = TransactionCore::begin();

    let dll_candidates = [
        "api-ms-win-core-synch-l1-2-0.dll",
        "KERNELBASE.dll",
        "KERNEL32.dll",
    ];

    let mut hooked_from = None;

    for dll in dll_candidates {
        if tx
            .attach_iat(
                module,
                dll,
                "Sleep",
                sleep_detour as *const () as *const u8,
                &mut original as *mut *mut u8,
            )
            .is_ok()
        {
            hooked_from = Some(dll);
            break;
        }
    }

    let hooked_from = hooked_from.ok_or("Could not find imported Sleep() in this module")?;
    println!("hooked Sleep import from {hooked_from}");

    let hooks = tx.commit()?;

    unsafe {
        ORIGINAL_SLEEP = Some(std::mem::transmute::<*mut u8, SleepFn>(original));
    }

    let after = Instant::now();
    unsafe { Sleep(500) };
    println!("after hook: slept for ~{} ms", after.elapsed().as_millis());

    for hook in hooks {
        hook.unhook()?;
    }

    let restored = Instant::now();
    unsafe { Sleep(500) };
    println!(
        "after unhook: slept for ~{} ms",
        restored.elapsed().as_millis()
    );

    Ok(())
}