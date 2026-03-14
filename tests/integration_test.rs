#[cfg(all(test, windows))]
mod tests {
    use neohook::alloc::TrampolineAlloc;
    use neohook::disasm::Disassembler;
    use neohook::mem;
    use neohook::{DetourError, DetourTransaction};

    use std::ptr;
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_READWRITE, VirtualAlloc, VirtualFree, VirtualQuery,
    };

    fn detour_1() -> i32 {
        std::hint::black_box(100);
        1
    }

    #[inline(never)]
    fn target_for_abort(a: i32, b: i32) -> i32 {
        std::hint::black_box(a) + std::hint::black_box(b) + std::hint::black_box(0)
    }

    #[inline(never)]
    fn target_for_lifecycle(a: i32, b: i32) -> i32 {
        std::hint::black_box(a) + std::hint::black_box(b) + std::hint::black_box(1)
    }

    #[inline(never)]
    fn universal_detour(_a: i32, _b: i32) -> i32 {
        std::hint::black_box(9999)
    }

    #[test]
    fn virtual_protect_same_execute_preserves_execute_permission() {
        unsafe {
            let page = VirtualAlloc(
                ptr::null(),
                4096,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READ,
            );
            assert!(!page.is_null(), "setup allocation failed");

            let mut old_protect = 0u32;
            let ok = mem::virtual_protect_same_execute(
                page as *mut u8,
                4096,
                PAGE_READWRITE,
                &mut old_protect,
            );
            assert_ne!(ok, 0, "virtual_protect_same_execute failed");

            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let q = VirtualQuery(
                page,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            assert_ne!(q, 0, "VirtualQuery failed");

            let free_ok = VirtualFree(page, 0, MEM_RELEASE);
            assert_ne!(free_ok, 0, "VirtualFree failed");

            assert_eq!(
                mbi.Protect, PAGE_EXECUTE_READWRITE,
                "execute permission should have been preserved"
            );
        }
    }

    #[test]
    fn disassembler_returns_expected_instruction_lengths() {
        let code: [u8; 10] = [0x90, 0x90, 0xB8, 0xAA, 0xBB, 0xCC, 0xDD, 0x90, 0x90, 0x90];
        let ptr = code.as_ptr();

        unsafe {
            assert_eq!(Disassembler::get_instruction_len(ptr, 1).unwrap(), 1);
            assert_eq!(Disassembler::get_instruction_len(ptr, 2).unwrap(), 2);
            assert_eq!(Disassembler::get_instruction_len(ptr, 3).unwrap(), 7);
        }
    }

    #[test]
    fn allocator_basic_allocation_and_write() {
        unsafe {
            let target = VirtualAlloc(ptr::null(), 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            assert!(!target.is_null(), "target allocation failed");

            let memory = TrampolineAlloc::alloc_nearby(target as *const u8, 128);
            assert!(memory.is_some(), "alloc_nearby returned None");

            let ptr = memory.unwrap();
            assert!(!ptr.is_null(), "allocated pointer must not be null");

            std::ptr::write_volatile(ptr, 0xCC);
            assert_eq!(std::ptr::read_volatile(ptr), 0xCC);

            let free_alloc = VirtualFree(ptr as _, 0, MEM_RELEASE);
            assert_ne!(free_alloc, 0, "failed to free trampoline allocation");

            let free_target = VirtualFree(target, 0, MEM_RELEASE);
            assert_ne!(free_target, 0, "failed to free target allocation");
        }
    }

    #[test]
    fn transaction_abort_keeps_original_function_intact() {
        let target_ptr = target_for_abort as *mut u8;
        let hook_ptr = universal_detour as *const u8;

        let mut tx = DetourTransaction::begin();
        tx.attach(target_ptr, hook_ptr).expect("attach failed");

        tx.abort();

        let result = tx.commit();
        assert!(matches!(result, Err(DetourError::NotStarted)));

        assert_eq!(
            target_for_abort(10, 10),
            20,
            "abort should not leave the function patched"
        );
    }

    #[test]
    fn inline_hook_lifecycle_works() {
        let target_ptr = target_for_lifecycle as *mut u8;
        let hook_ptr = universal_detour as *const u8;

        assert_eq!(target_for_lifecycle(10, 10), 21);

        let mut tx = DetourTransaction::begin();
        tx.attach(target_ptr, hook_ptr).expect("attach failed");
        let mut hooks = tx.commit().expect("commit failed");

        assert_eq!(target_for_lifecycle(10, 10), 9999);

        let hook = hooks.remove(0);
        hook.unhook().expect("unhook failed");

        assert_eq!(target_for_lifecycle(10, 10), 21);
    }

    #[test]
    fn detour_helper_function_is_callable() {
        let result = detour_1();
        assert_eq!(result, 1);
    }
}
