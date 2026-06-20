// Demonstrates EAT (Export Address Table) hooking.
//
// Unlike an IAT hook, which rewrites one *caller's* import slot, an EAT hook
// rewrites the *exporting* module's export table. Every consumer that resolves
// the export *after* the hook is installed - here through GetProcAddress - is
// redirected to the detour. Code that already cached the resolved address keeps
// calling the original, because only the lookup table changed.
//
// We hook kernel32!GetTickCount and show that a fresh GetProcAddress lookup now
// returns our detour, while the trampoline-free original pointer still works.
/* Expected output:
    real GetTickCount() = ~xxxxxxxx
    hooked GetTickCount in kernel32 EAT
    [eat detour] GetTickCount() intercepted
    after hook, GetProcAddress -> 0xDEADBEEF
    original still returns ~xxxxxxxx
    after unhook, GetProcAddress -> ~xxxxxxxx
*/
use neohook::TransactionCore;
use std::error::Error;
use std::ffi::CString;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

type GetTickCountFn = unsafe extern "system" fn() -> u32;

const SENTINEL: u32 = 0xDEAD_BEEF;

unsafe extern "system" fn get_tick_count_detour() -> u32 {
    println!("[eat detour] GetTickCount() intercepted");
    SENTINEL
}

/// Resolves an export freshly through GetProcAddress (the lookup an EAT hook
/// affects).
unsafe fn resolve(module: *mut core::ffi::c_void, name: &str) -> GetTickCountFn {
    let cname = CString::new(name).unwrap();
    let addr = unsafe { GetProcAddress(module, cname.as_ptr() as *const u8) }
        .expect("GetProcAddress failed") as *const u8;
    unsafe { std::mem::transmute::<*const u8, GetTickCountFn>(addr) }
}

fn main() -> Result<(), Box<dyn Error>> {
    let module = unsafe { GetModuleHandleA(c"kernel32.dll".as_ptr() as *const u8) };
    if module.is_null() {
        return Err("GetModuleHandleA(kernel32.dll) failed".into());
    }

    let real = unsafe { resolve(module, "GetTickCount")() };
    println!("real GetTickCount() = ~{real}");

    let mut tx = TransactionCore::begin();
    tx.attach_eat(module, "GetTickCount", get_tick_count_detour as *const u8)?;
    let hooks = tx.commit()?;
    println!("hooked GetTickCount in kernel32 EAT");

    // A fresh resolution now lands on our detour.
    let hooked = unsafe { resolve(module, "GetTickCount")() };
    println!("after hook, GetProcAddress -> {hooked:#X}");
    assert_eq!(hooked, SENTINEL, "EAT lookup should now hit the detour");

    // The hook records the original resolved address; calling it bypasses the
    // detour and reaches the real function body.
    let original =
        unsafe { std::mem::transmute::<*const u8, GetTickCountFn>(hooks[0].original_ptr()) };
    println!("original still returns ~{}", unsafe { original() });

    for hook in hooks {
        hook.unhook()?;
    }

    let restored = unsafe { resolve(module, "GetTickCount")() };
    println!("after unhook, GetProcAddress -> ~{restored}");
    assert_ne!(restored, SENTINEL, "EAT lookup should be restored");

    Ok(())
}
