#![cfg(windows)]

//! When the original bytes cannot be written back, the target keeps jumping to
//! the detour, which may still call the original through the trampoline. The
//! trampoline must then stay mapped instead of being retired and freed.

use neohook::DetourTransaction;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_DECOMMIT, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE,
    VirtualAlloc, VirtualFree, VirtualQuery,
};

extern "C" fn detour() -> u32 {
    7
}

fn committed(address: *const u8) -> bool {
    let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
    let written = unsafe { VirtualQuery(address.cast(), &mut info, size) };
    written == size && info.State == MEM_COMMIT
}

#[test]
fn trampoline_survives_a_failed_restore() {
    // mov eax, 42 ; ret ; padding
    let mut code = vec![0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3];
    code.resize(64, 0xCC);
    let page = unsafe {
        VirtualAlloc(
            std::ptr::null(),
            4096,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    } as *mut u8;
    assert!(!page.is_null());
    unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), page, code.len()) };

    let mut tx = DetourTransaction::begin();
    let trampoline = tx
        .attach(page, detour as *const u8)
        .expect("attach should succeed");
    let hooks = tx.commit().expect("commit should succeed");

    // The target page goes away, so the unhook cannot restore it.
    assert_ne!(unsafe { VirtualFree(page.cast(), 4096, MEM_DECOMMIT) }, 0);
    drop(hooks);
    neohook::reclaim();

    assert!(committed(trampoline), "trampoline was freed");
}
