#![cfg(windows)]

//! Concurrency coverage for the process-wide transaction lock.
//!
//! Several threads install, verify, and remove hooks at the same time. NeoHook
//! serializes the critical section of each transaction process-wide (mirroring
//! Microsoft Detours' "one transaction at a time" model), so concurrent
//! transactions must complete without corrupting each other's state.
//!
//! Each worker operates on its own thread-local object, so the only thing the
//! threads contend on is the global transaction lock itself.

use neohook::DetourTransaction;
use std::sync::{Arc, Barrier};
use std::thread;

#[repr(C)]
struct Object {
    vptr: *mut u8,
}

extern "system" fn base_method() -> i32 {
    1
}

extern "system" fn detour_method() -> i32 {
    2
}

unsafe fn call_slot0(obj: *const Object) -> i32 {
    let slot = unsafe { *((*obj).vptr as *mut *mut u8).add(0) };
    let f: extern "system" fn() -> i32 = unsafe { std::mem::transmute(slot) };
    f()
}

#[test]
fn concurrent_transactions_are_serialized_and_safe() {
    const THREADS: usize = 8;
    const ITERATIONS: usize = 25;

    let barrier = Arc::new(Barrier::new(THREADS));
    let mut handles = Vec::new();

    for _ in 0..THREADS {
        let barrier = Arc::clone(&barrier);

        handles.push(thread::spawn(move || {
            // Thread-local table and object: nothing here is shared between
            // threads except the global transaction lock inside NeoHook.
            let mut vtable: [*mut u8; 1] = [base_method as *mut u8];
            let mut object = Object {
                vptr: vtable.as_mut_ptr() as *mut u8,
            };

            // Maximize the chance of overlapping commits.
            barrier.wait();

            for _ in 0..ITERATIONS {
                let mut tx = DetourTransaction::begin();
                tx.attach_vtable_instance(
                    &mut object.vptr as *mut *mut u8,
                    0,
                    1,
                    detour_method as *const u8,
                )
                .expect("attach_vtable_instance should succeed");

                let hooks = tx.commit().expect("commit should succeed");
                assert_eq!(unsafe { call_slot0(&object) }, 2);

                drop(hooks);
                assert_eq!(unsafe { call_slot0(&object) }, 1);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("a worker thread panicked");
    }
}
