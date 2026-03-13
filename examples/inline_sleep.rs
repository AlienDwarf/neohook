use neohook::TransactionCore;
use std::error::Error;
use std::time::Instant;
use windows_sys::Win32::System::Threading::Sleep;

type SleepFn = unsafe extern "system" fn(u32);

static mut ORIGINAL_SLEEP: Option<SleepFn> = None;

unsafe extern "system" fn sleep_detour(ms: u32) {
    let original = unsafe { ORIGINAL_SLEEP.expect("ORIGINAL_SLEEP not initialized") };

    let patched_ms = ms.min(100);

    unsafe { original(patched_ms) };
}

fn main() -> Result<(), Box<dyn Error>> {
    let before = Instant::now();
    unsafe { Sleep(200) };
    println!(
        "before hook: slept for ~{} ms",
        before.elapsed().as_millis()
    );

    let mut tx = TransactionCore::begin();
    tx.update_all_threads();

    let trampoline = tx.attach(
        Sleep as *const () as *mut u8,
        sleep_detour as *const () as *const u8,
    )?;
    {
        let _hook = tx.commit()?;

        unsafe {
            ORIGINAL_SLEEP = Some(std::mem::transmute::<*mut u8, SleepFn>(trampoline));
        }

        let after = Instant::now();
        unsafe { Sleep(200) };
        println!("after hook: slept for ~{} ms", after.elapsed().as_millis());
    } // Hooks are automatically removed here when `_hook` goes out of scope
    // You can also manually unhook with `hook.unhook()?;`

    let restored = Instant::now();
    unsafe { Sleep(200) };
    println!(
        "after unhook: slept for ~{} ms",
        restored.elapsed().as_millis()
    );

    Ok(())
}
