// Demonstrates a delay / on-load hook: hooking a function in a module that is
// not loaded yet. NeoHook inline-hooks ntdll!LdrLoadDll once, and installs the
// real (INT3) hook the moment the target module is brought into the process.
/* Expected output:
    registered delay hook for winmm.dll!timeGetTime
    active before load? false
    loading winmm.dll ...
    active after load?  true
    timeGetTime() = 3735928865   (0xDEADBEE1 - intercepted)
    after unhook: timeGetTime() = <some real tick count>
*/
use neohook::DelayHook;
use std::error::Error;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

unsafe extern "system" fn fake_time_get_time() -> u32 {
    0xDEAD_BEE1
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn main() -> Result<(), Box<dyn Error>> {
    // Register before winmm.dll is loaded.
    let hook = unsafe {
        DelayHook::register("winmm.dll", "timeGetTime", fake_time_get_time as *const u8)
    }?;
    println!("registered delay hook for winmm.dll!timeGetTime");
    println!("active before load? {}", hook.is_active());

    println!("loading winmm.dll ...");
    let module = unsafe { LoadLibraryW(wide("winmm.dll").as_ptr()) };
    if module.is_null() {
        return Err("failed to load winmm.dll".into());
    }
    println!("active after load?  {}", hook.is_active());

    // Resolve and call the real export the on-load hook now intercepts it.
    let proc = unsafe { GetProcAddress(module, c"timeGetTime".as_ptr() as *const u8) }
        .ok_or("timeGetTime not found")?;
    let time_get_time: unsafe extern "system" fn() -> u32 = unsafe { std::mem::transmute(proc) };
    println!(
        "timeGetTime() = {}   (0xDEADBEE1 - intercepted)",
        unsafe { time_get_time() }
    );

    hook.unhook()?;
    println!("after unhook: timeGetTime() = {}", unsafe { time_get_time() });

    Ok(())
}
