use neohook::alloc::TrampolineAlloc;
use std::ptr;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
};

#[test]
fn test_alloc_nearby_basic_conditions() {
    unsafe {
        let res_null = TrampolineAlloc::alloc_nearby_trampoline(ptr::null(), 64);
        assert!(res_null.is_none(), "null target should return None");

        let target =
            VirtualAlloc(ptr::null(), 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) as *mut u8;

        assert!(!target.is_null(), "target allocation failed");

        let res_zero = TrampolineAlloc::alloc_nearby_trampoline(target, 0);
        assert!(res_zero.is_none(), "size 0 should return None");

        let tramp = TrampolineAlloc::alloc_nearby_trampoline(target, 64);
        assert!(
            tramp.is_some(),
            "expected nearby trampoline allocation to succeed"
        );

        let free_ok = VirtualFree(target as _, 0, MEM_RELEASE);
        assert_ne!(free_ok, 0, "failed to free target allocation");
    }
}
