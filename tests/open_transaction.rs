#![cfg(windows)]

//! An open transaction - tracked threads, not yet committed - must not block
//! code writes made by other threads outside it.
//!
//! The transaction lock is held from the first `update_thread` until the
//! commit, and the caller may do anything in between, including waiting for
//! another thread or loading a library. If every enable, disable, unhook or
//! drop also waited for that lock, a thread that opens a transaction and joins
//! a thread that drops a hook would deadlock, and so would a
//! `DLL_PROCESS_DETACH` teardown under the loader lock against a transaction
//! that is loading a library. Only the short patch phase of a commit may hold
//! up other writers.

use neohook::{DelayHook, DetourTransaction, Int3Hook};
use std::hint::black_box;
use std::sync::mpsc;
use std::time::Duration;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, LoadLibraryW};

const WAIT: Duration = Duration::from_secs(5);

#[inline(never)]
extern "system" fn inline_target(x: u32) -> u32 {
    black_box(x).wrapping_mul(3).wrapping_add(1)
}

#[inline(never)]
extern "system" fn inline_detour(x: u32) -> u32 {
    black_box(x).wrapping_add(100)
}

#[inline(never)]
extern "system" fn int3_target(x: u32) -> u32 {
    black_box(x).wrapping_mul(5).wrapping_add(2)
}

#[inline(never)]
extern "system" fn int3_detour(x: u32) -> u32 {
    black_box(x).wrapping_add(200)
}

/// Moves a hook to the writer thread. `Hook` is not `Send` because it holds
/// raw code pointers, which have no thread affinity.
struct Moved<T>(T);
unsafe impl<T> Send for Moved<T> {}

/// Runs `write` on another thread while this thread holds a transaction open,
/// and reports whether it finished without waiting for the commit.
fn finishes_while_a_transaction_is_open(write: impl FnOnce() + Send + 'static) -> bool {
    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();

    let (done_tx, done_rx) = mpsc::channel();
    let writer = std::thread::spawn(move || {
        write();
        done_tx.send(()).unwrap();
    });
    let finished = done_rx.recv_timeout(WAIT).is_ok();

    // Closing the transaction lets a blocked writer finish either way.
    tx.abort();
    writer.join().expect("writer panicked");
    finished
}

#[test]
fn hook_writes_do_not_wait_for_an_open_transaction() {
    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();
    tx.attach(inline_target as *mut u8, inline_detour as *const u8)
        .expect("attach");
    let mut hooks = tx.commit().expect("commit");
    let hook = Moved(hooks.pop().expect("one hook"));
    assert_eq!(inline_target(1), 101);

    let (back_tx, back_rx) = mpsc::channel();
    let disabled = finishes_while_a_transaction_is_open(move || {
        let mut hook = hook;
        hook.0.disable().expect("disable");
        back_tx.send(hook).unwrap();
    });
    let hook: Moved<_> = back_rx.recv().expect("hook returned");
    assert!(disabled, "disabling a hook waited for an open transaction");
    assert_eq!(inline_target(1), 4, "original runs while disabled");

    let dropped = finishes_while_a_transaction_is_open(move || drop(hook));
    assert!(dropped, "dropping a hook waited for an open transaction");
    assert_eq!(inline_target(1), 4);

    let t = int3_target as *const () as usize;
    let d = int3_detour as *const () as usize;
    let (back_tx, back_rx) = mpsc::channel();
    let installed = finishes_while_a_transaction_is_open(move || {
        let hook =
            unsafe { Int3Hook::install(t as *const u8, d as *const u8) }.expect("int3 install");
        back_tx.send(hook).unwrap();
    });
    let int3 = back_rx.recv().expect("int3 hook returned");
    assert!(installed, "an INT3 install waited for an open transaction");
    assert_eq!(int3_target(1), 201);
    int3.unhook().unwrap();
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe extern "system" fn fake_time() -> u32 {
    0x5EED_0001
}

#[test]
fn delay_hook_installs_when_its_module_loads_during_an_open_transaction() {
    let name = wide("winmm.dll");
    assert!(
        unsafe { GetModuleHandleW(name.as_ptr()) }.is_null(),
        "winmm.dll must not be loaded yet"
    );
    let delay = unsafe { DelayHook::register("winmm.dll", "timeGetTime", fake_time as *const u8) }
        .expect("register");
    assert!(!delay.is_active(), "pending until winmm.dll loads");

    let loaded = finishes_while_a_transaction_is_open(move || {
        let module = unsafe { LoadLibraryW(wide("winmm.dll").as_ptr()) };
        assert!(!module.is_null(), "winmm.dll loads");
    });
    assert!(loaded, "the load waited for an open transaction");
    assert!(
        delay.is_active(),
        "a delay hook stayed pending because a transaction was open while its module loaded"
    );
    drop(delay);
}
