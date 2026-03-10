use neohook::mem::virtual_protect_same_execute;
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualQuery, MEMORY_BASIC_INFORMATION,
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
};

#[test]
fn changes_protection_and_returns_old_protect() {
    unsafe {
        let size = 4096usize;

        // allocate a page with execute-readwrite permissions
        let ptr = VirtualAlloc(
            std::ptr::null_mut(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        ) as *mut u8;

        // Ensure the allocation succeeded
        assert!(!ptr.is_null());

        let mut old_protect = 0u32;

        // Change the protection to readwrite, but since the original page had execute permissions, 
        // we expect it to keep them.
        let ok = virtual_protect_same_execute(
            ptr,
            size,
            PAGE_READWRITE,
            &mut old_protect as *mut u32,
        );

        // Ensure the protection change succeeded and that the old protection is what we set initially.
        assert_ne!(ok, 0);
        assert_eq!(old_protect, PAGE_EXECUTE_READWRITE);

        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let q = VirtualQuery(
            ptr as _,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        );

        assert_ne!(q, 0);

        // The new protection should still include execute permissions.
        assert_eq!(mbi.Protect, PAGE_EXECUTE_READWRITE);

        let freed = VirtualFree(ptr as _, 0, MEM_RELEASE);
        assert_ne!(freed, 0);
    }
}