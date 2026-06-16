#![cfg(windows)]

//! Coverage for the reentrancy guard used to keep detours from recursing into
//! themselves.

use neohook::reentrancy_guard;

#[test]
fn same_call_site_blocks_nested_entry() {
    fn site() -> Option<neohook::ReentrancyGuard> {
        reentrancy_guard!()
    }

    let first = site();
    assert!(first.is_some(), "outermost entry should succeed");

    // Same call site, while the first guard is still held -> reentrant.
    let second = site();
    assert!(
        second.is_none(),
        "nested entry on same thread should be blocked"
    );

    drop(first);

    // Once the guard is dropped the region is free again.
    let third = site();
    assert!(third.is_some(), "entry after drop should succeed again");
}

#[test]
fn recursive_detour_pattern_bails_on_reentry() {
    fn recursive(depth: u32) -> u32 {
        let _guard = match reentrancy_guard!() {
            Some(g) => g,
            None => return 0, // reentrant call: bail out
        };
        if depth == 0 {
            return 1;
        }
        // The nested call hits the same guard and returns 0.
        recursive(depth - 1)
    }

    assert_eq!(recursive(5), 0);
}

#[test]
fn distinct_call_sites_are_independent() {
    // Two different textual uses of the macro must not share a flag.
    let a = reentrancy_guard!();
    let b = reentrancy_guard!();
    assert!(a.is_some());
    assert!(b.is_some());
}

#[test]
fn guard_is_per_thread() {
    fn enter() -> Option<neohook::ReentrancyGuard> {
        reentrancy_guard!()
    }

    // Keep the guard held on this thread...
    let held = enter();
    assert!(held.is_some());

    // ...a separate thread shares the same call site but has its own
    // thread-local flag, so it must still be able to enter.
    let other = std::thread::spawn(|| enter().is_some()).join().unwrap();
    assert!(other, "a separate thread should enter freely");

    drop(held);
}
