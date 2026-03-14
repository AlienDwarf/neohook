#[cfg(all(test, windows))]
mod tests {
    use neohook::{DetourError, DetourTransaction};
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
