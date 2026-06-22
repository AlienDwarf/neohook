// Demonstrates hooking a named export in one call with `attach_export`.
//
// Instead of resolving the address yourself (GetModuleHandle + GetProcAddress)
// and passing a raw pointer to `attach`, hand `attach_export` the module and
// function name. It loads the module if needed, resolves the export, and queues
// an inline hook on the function body
/* Expected output:
    before hook: GetTickCount() = <some real tick count>
    after hook:  GetTickCount() = 559038737   (0xDEADBEE... fixed)
    original via trampoline:    = <some real tick count>
    after unhook:GetTickCount() = <some real tick count>
*/
use neohook::DetourTransaction;
use std::error::Error;
use std::sync::OnceLock;
use windows_sys::Win32::System::SystemInformation::GetTickCount;

type GetTickCountFn = unsafe extern "system" fn() -> u32;
static ORIG: OnceLock<GetTickCountFn> = OnceLock::new();

unsafe extern "system" fn hooked_get_tick_count() -> u32 {
    // A recognizable fixed value so the interception is obvious.
    0xDEAD_BEE1
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("before hook: GetTickCount() = {}", unsafe {
        GetTickCount()
    });

    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();

    // One call: resolve kernel32!GetTickCount by name and queue the inline hook.
    let tramp = tx.attach_export(
        "kernel32.dll",
        "GetTickCount",
        hooked_get_tick_count as *const u8,
    )?;

    let _hooks = tx.commit()?;
    let _ = ORIG.set(unsafe { std::mem::transmute::<*mut u8, GetTickCountFn>(tramp) });

    println!("after hook:  GetTickCount() = {}", unsafe {
        GetTickCount()
    });
    println!("original via trampoline:    = {}", unsafe {
        (ORIG.get().unwrap())()
    });

    // _hooks drops here -> the original bytes are restored automatically.
    drop(_hooks);
    println!("after unhook:GetTickCount() = {}", unsafe {
        GetTickCount()
    });

    Ok(())
}
