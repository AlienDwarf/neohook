// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Anti-tamper / re-hook watchdog.
//!
//! Some code verifies its own integrity. A periodic self-check may scan the
//! bytes it shipped with and *restore* the original bytes, silently removing an
//! inline or INT3 hook some time after it was installed. A [`Watchdog`] keeps a
//! hook stable across such a check: it snapshots the bytes a hook left at the
//! target and watches a background thread for tampering.
//!
//! What it does on tamper is **your choice**:
//!
//! * [`WatchMode::Restore`] (the default) rewrites the canonical bytes back -
//!   re-applying the hook the instant something reverts it.
//! * [`WatchMode::DetectOnly`] leaves the tampered bytes in place and only
//!   reports the event, so you can react yourself (log it, re-install through a
//!   different technique, bail out).
//!
//! Either way an optional [`on_tamper`](Watchdog::on_tamper) callback fires once
//! per tamper episode with a [`TamperEvent`] describing what changed.
//!
//! It works at the raw-byte level, so it is agnostic to *how* the patch was
//! made - it guards inline-hook jumps, the single `0xCC` of an INT3 hook, or any
//! other run of bytes you point it at:
//!
//! ```rust,ignore
//! use neohook::{Hook, Watchdog, WatchMode};
//! use std::time::Duration;
//!
//! // Take the patched site and its length straight from the inline hook.
//! let hooks = tx.commit()?;
//! let (target, len) = match &hooks[0] {
//!     Hook::Inline(h) => (h.target as *const u8, h.orig_bytes.len()),
//!     _ => unreachable!(),
//! };
//!
//! let wd = Watchdog::with_interval(Duration::from_millis(50));
//! wd.on_tamper(|e| eprintln!("tamper at {:p}, restored={}", e.target, e.restored));
//! let id = unsafe { wd.guard(target, len) }?; // snapshot the freshly written jump
//!
//! // Default WatchMode::Restore re-applies the jump; switch to detect-only with:
//! // wd.set_mode(WatchMode::DetectOnly);
//!
//! wd.unguard(id); // stop guarding (do this *before* you unhook)
//! ```
//!
//! In [`WatchMode::Restore`] the watchdog only ever writes back the exact bytes it
//! captured at [`Watchdog::guard`] time, so guard a region **after** the hook is
//! installed and **unguard it before** you unhook - otherwise the watchdog would
//! faithfully re-install the hook you are trying to remove.

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::mem::write_memory_atomic;

/// Identifies a region registered with [`Watchdog::guard`], used to stop
/// guarding it again with [`Watchdog::unguard`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GuardId(u64);

impl GuardId {
    /// Returns the raw identifier, primarily for the C ABI.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Reconstructs a [`GuardId`] from a raw identifier returned by
    /// [`Self::raw`].
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }
}

/// What a [`Watchdog`] does when it finds a guarded region has been tampered
/// with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WatchMode {
    /// Rewrite the canonical bytes back, re-applying the patch (the default).
    #[default]
    Restore,
    /// Leave the tampered bytes in place and only report the event - "detect,
    /// but do not re-patch".
    DetectOnly,
}

impl WatchMode {
    /// Encodes the mode as a small integer for the C ABI / atomic storage.
    const fn as_u8(self) -> u8 {
        match self {
            Self::Restore => 0,
            Self::DetectOnly => 1,
        }
    }

    /// Decodes a mode from its integer form; any non-zero value is
    /// [`Self::DetectOnly`].
    const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Restore,
            _ => Self::DetectOnly,
        }
    }
}

/// Describes a detected tamper of a guarded region, passed to an
/// [`on_tamper`](Watchdog::on_tamper) callback. Fired once per episode (when a
/// region first diverges from its snapshot), not on every sweep.
///
/// The byte slices borrow the watchdog's working buffers and are only valid for
/// the duration of the callback; copy anything you need to keep.
pub struct TamperEvent<'a> {
    /// The guard whose region was tampered with.
    pub guard_id: GuardId,
    /// The address of the guarded region.
    pub target: *const u8,
    /// The canonical bytes the watchdog expects to find there.
    pub expected: &'a [u8],
    /// The bytes actually found at the target this sweep.
    pub found: &'a [u8],
    /// `true` if the watchdog rewrote the canonical bytes back this sweep
    /// ([`WatchMode::Restore`] and the write succeeded); `false` in
    /// [`WatchMode::DetectOnly`] or if the rewrite failed.
    pub restored: bool,
}

/// A callback invoked once per tamper episode. Runs on the watchdog's background
/// thread, so it must be `Send + Sync` and should not block for long.
type TamperFn = dyn for<'a> Fn(&TamperEvent<'a>) + Send + Sync + 'static;

/// A single guarded region: a target address and the canonical bytes that must
/// remain there.
struct Region {
    id: u64,
    target: usize,
    expected: Vec<u8>,
    /// Whether the region was already diverging on the previous sweep, so the
    /// callback fires only on the intact -> tampered transition.
    tampered: bool,
}

/// State shared between the owning [`Watchdog`] and its background thread.
struct Shared {
    /// The set of regions currently being guarded.
    regions: Mutex<Vec<Region>>,
    /// Cleared on shutdown to make the background thread exit.
    running: AtomicBool,
    /// How many times the watchdog has rewritten a tampered region.
    restorations: AtomicU64,
    /// Monotonic source of [`GuardId`]s; starts at 1 so `0` is never a valid id.
    next_id: AtomicU64,
    /// The active [`WatchMode`], encoded via [`WatchMode::as_u8`].
    mode: AtomicU8,
    /// Optional tamper callback, shared as an `Arc` so a sweep can clone it and
    /// release the lock before invoking user code.
    callback: Mutex<Option<Arc<TamperFn>>>,
    /// How long the background thread sleeps between sweeps.
    interval: Duration,
}

/// A background guard that reacts to tampered byte patches.
///
/// Created with [`Self::with_interval`], it spawns a thread that wakes every
/// `interval`, compares each guarded region against its snapshot, and - per the
/// active [`WatchMode`] - rewrites or merely reports any that differ. The thread
/// is stopped and joined when the `Watchdog` is dropped.
pub struct Watchdog {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl Watchdog {
    /// Creates a watchdog whose background thread sweeps every `interval`, in the
    /// default [`WatchMode::Restore`].
    ///
    /// A very small interval increases CPU use; a few tens of milliseconds is a
    /// good balance for reacting to a periodic integrity check. An `interval` of
    /// zero is treated as 1 ms to avoid a busy loop.
    pub fn with_interval(interval: Duration) -> Self {
        let interval = if interval.is_zero() {
            Duration::from_millis(1)
        } else {
            interval
        };

        let shared = Arc::new(Shared {
            regions: Mutex::new(Vec::new()),
            running: AtomicBool::new(true),
            restorations: AtomicU64::new(0),
            next_id: AtomicU64::new(1),
            mode: AtomicU8::new(WatchMode::Restore.as_u8()),
            callback: Mutex::new(None),
            interval,
        });

        let worker = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("neohook-watchdog".into())
            .spawn(move || run(worker))
            .ok();

        Self { shared, thread }
    }

    /// Sets what the watchdog does when it finds tampering: re-apply the patch
    /// ([`WatchMode::Restore`]) or only report it ([`WatchMode::DetectOnly`]).
    ///
    /// Takes effect on the next sweep and applies to every guarded region.
    pub fn set_mode(&self, mode: WatchMode) {
        self.shared.mode.store(mode.as_u8(), Ordering::Release);
    }

    /// Returns the current [`WatchMode`].
    pub fn mode(&self) -> WatchMode {
        WatchMode::from_u8(self.shared.mode.load(Ordering::Acquire))
    }

    /// Installs a callback invoked once per tamper episode, in either mode.
    ///
    /// The callback runs on the watchdog's background thread, so it must be
    /// `Send + Sync` and should return quickly. Replaces any previously installed
    /// callback.
    pub fn on_tamper<F>(&self, callback: F)
    where
        F: for<'a> Fn(&TamperEvent<'a>) + Send + Sync + 'static,
    {
        *self.lock_callback() = Some(Arc::new(callback));
    }

    /// Removes any installed tamper callback.
    pub fn clear_on_tamper(&self) {
        *self.lock_callback() = None;
    }

    /// Snapshots `len` bytes at `target` and guards them, returning a
    /// [`GuardId`] that can later be passed to [`Self::unguard`].
    ///
    /// The bytes are read **now**, so install the hook first: whatever is at
    /// `target` at this moment becomes the canonical image the watchdog compares
    /// against (and, in [`WatchMode::Restore`], re-applies) on every sweep.
    ///
    /// # Errors
    ///
    /// Returns [`WatchdogError::InvalidParameter`] if `target` is null or `len`
    /// is zero.
    ///
    /// # Safety
    ///
    /// `target` must point at `len` readable bytes of committed memory (a hooked
    /// code site qualifies) for the lifetime of the guard.
    pub unsafe fn guard(&self, target: *const u8, len: usize) -> Result<GuardId, WatchdogError> {
        if target.is_null() || len == 0 {
            return Err(WatchdogError::InvalidParameter);
        }
        let expected = unsafe { std::slice::from_raw_parts(target, len) }.to_vec();
        Ok(self.insert_region(target as usize, expected))
    }

    /// Guards `target` against the explicit byte image `expected`, rather than
    /// snapshotting whatever is currently there.
    ///
    /// Useful when the canonical bytes are known up front (for example the exact
    /// jump encoding a hook writes) and you want to guard before installing.
    ///
    /// # Errors
    ///
    /// Returns [`WatchdogError::InvalidParameter`] if `target` is null or
    /// `expected` is empty.
    ///
    /// # Safety
    ///
    /// `target` must point at `expected.len()` writable bytes of committed
    /// memory for the lifetime of the guard.
    pub unsafe fn guard_bytes(
        &self,
        target: *const u8,
        expected: &[u8],
    ) -> Result<GuardId, WatchdogError> {
        if target.is_null() || expected.is_empty() {
            return Err(WatchdogError::InvalidParameter);
        }
        Ok(self.insert_region(target as usize, expected.to_vec()))
    }

    fn insert_region(&self, target: usize, expected: Vec<u8>) -> GuardId {
        let id = self.shared.next_id.fetch_add(1, Ordering::Relaxed);
        self.lock_regions().push(Region {
            id,
            target,
            expected,
            tampered: false,
        });
        GuardId(id)
    }

    /// Stops guarding the region identified by `id`.
    ///
    /// Returns `true` if a matching region was being guarded. Call this **before**
    /// unhooking the target so the watchdog does not re-install the patch you are
    /// removing.
    pub fn unguard(&self, id: GuardId) -> bool {
        let mut regions = self.lock_regions();
        let before = regions.len();
        regions.retain(|r| r.id != id.0);
        regions.len() != before
    }

    /// Returns the number of regions currently being guarded.
    pub fn guarded(&self) -> usize {
        self.lock_regions().len()
    }

    /// Returns how many times the watchdog has rewritten a tampered region since
    /// it was created. Always `0` in [`WatchMode::DetectOnly`].
    pub fn restorations(&self) -> u64 {
        self.shared.restorations.load(Ordering::Relaxed)
    }

    /// Locks the region list, recovering from a poisoned mutex (the guarded
    /// vector carries no invariant a panicking holder could corrupt).
    fn lock_regions(&self) -> MutexGuard<'_, Vec<Region>> {
        self.shared
            .regions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    fn lock_callback(&self) -> MutexGuard<'_, Option<Arc<TamperFn>>> {
        self.shared
            .callback
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.shared.running.store(false, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            // Wake the thread if it is parked so shutdown is not delayed by a
            // full sweep interval, then wait for it to exit.
            thread.thread().unpark();
            let _ = thread.join();
        }
    }
}

/// Errors produced while registering a region with a [`Watchdog`].
#[derive(Debug, PartialEq, Eq)]
pub enum WatchdogError {
    /// A null target pointer or a zero-length region was supplied.
    InvalidParameter,
}

impl std::fmt::Display for WatchdogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidParameter => {
                write!(f, "invalid watchdog region (null target or zero len)")
            }
        }
    }
}

impl std::error::Error for WatchdogError {}

/// The watchdog thread body: sleep, then check every guarded region.
fn run(shared: Arc<Shared>) {
    loop {
        if !shared.running.load(Ordering::Acquire) {
            break;
        }
        std::thread::park_timeout(shared.interval);
        if !shared.running.load(Ordering::Acquire) {
            break;
        }
        sweep(&shared);
    }
}

/// One detected tamper, captured under the region lock so the callback can run
/// after the lock is released.
struct TamperHit {
    id: u64,
    target: usize,
    expected: Vec<u8>,
    found: Vec<u8>,
    restored: bool,
}

/// Compares each guarded region against its snapshot; in [`WatchMode::Restore`]
/// rewrites any that differ, and collects newly-tampered regions to report.
fn sweep(shared: &Shared) {
    let mode = WatchMode::from_u8(shared.mode.load(Ordering::Acquire));

    let hits = {
        let mut regions = shared.regions.lock().unwrap_or_else(|p| p.into_inner());
        let mut hits = Vec::new();

        for region in regions.iter_mut() {
            // SAFETY: the guard contract requires `target` to stay valid for
            // `expected.len()` readable bytes while it is guarded.
            let current = unsafe {
                std::slice::from_raw_parts(region.target as *const u8, region.expected.len())
            };

            if current == region.expected.as_slice() {
                region.tampered = false;
                continue;
            }

            // Snapshot the tampered bytes before any restore overwrites them.
            let found = current.to_vec();

            let restored = if mode == WatchMode::Restore {
                let ok = unsafe {
                    write_memory_atomic(
                        region.target as *mut u8,
                        region.expected.as_ptr(),
                        region.expected.len(),
                    )
                }
                .is_some();
                if ok {
                    shared.restorations.fetch_add(1, Ordering::Relaxed);
                }
                ok
            } else {
                false
            };

            // Report only on the intact -> tampered transition, so DetectOnly
            // does not spam the callback every sweep while bytes stay reverted.
            if !region.tampered {
                region.tampered = true;
                hits.push(TamperHit {
                    id: region.id,
                    target: region.target,
                    expected: region.expected.clone(),
                    found,
                    restored,
                });
            }
        }
        hits
    };

    if hits.is_empty() {
        return;
    }

    // Clone the callback out from under the lock so user code runs unlocked and
    // may freely call back into the watchdog.
    let callback = shared
        .callback
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    if let Some(callback) = callback {
        for hit in &hits {
            let event = TamperEvent {
                guard_id: GuardId(hit.id),
                target: hit.target as *const u8,
                expected: &hit.expected,
                found: &hit.found,
                restored: hit.restored,
            };
            // Contain a panicking callback so it cannot unwind out of and kill
            // the watchdog thread (which would silently stop all guarding).
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| callback(&event)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc, VirtualFree,
    };

    /// A small executable scratch page used to stand in for a hooked code site.
    struct Page(*mut u8);

    impl Page {
        fn new() -> Self {
            let p = unsafe {
                VirtualAlloc(
                    std::ptr::null(),
                    4096,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )
            } as *mut u8;
            assert!(!p.is_null(), "scratch page allocation failed");
            Self(p)
        }

        fn write(&self, bytes: &[u8]) {
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.0, bytes.len()) };
        }

        fn read(&self, len: usize) -> Vec<u8> {
            unsafe { std::slice::from_raw_parts(self.0, len) }.to_vec()
        }
    }

    impl Drop for Page {
        fn drop(&mut self) {
            unsafe { VirtualFree(self.0 as _, 0, MEM_RELEASE) };
        }
    }

    /// Spins until `cond` holds or the timeout elapses, so the test does not race
    /// the watchdog thread.
    fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        cond()
    }

    #[test]
    fn restore_mode_rewrites_tampered_bytes_and_fires_callback() {
        static FIRED: AtomicU32 = AtomicU32::new(0);
        static SAW_RESTORED: AtomicU32 = AtomicU32::new(0);
        FIRED.store(0, Ordering::SeqCst);
        SAW_RESTORED.store(0, Ordering::SeqCst);

        let page = Page::new();
        let patched = [0xE9u8, 0x11, 0x22, 0x33, 0x44];
        page.write(&patched);

        let wd = Watchdog::with_interval(Duration::from_millis(10));
        wd.on_tamper(|e| {
            FIRED.fetch_add(1, Ordering::SeqCst);
            if e.restored {
                SAW_RESTORED.fetch_add(1, Ordering::SeqCst);
            }
        });
        let id = unsafe { wd.guard(page.0, patched.len()) }.expect("guard");
        assert_eq!(wd.mode(), WatchMode::Restore, "default mode is Restore");

        // Simulate an integrity check restoring the original prologue.
        page.write(&[0x90, 0x90, 0x90, 0x90, 0x90]);

        let ok = wait_until(Duration::from_secs(5), || page.read(5) == patched);
        assert!(ok, "Restore mode should re-apply the patched bytes");
        // The worker writes the restored bytes before bumping the counter, so
        // observing the restored bytes above does not guarantee the increment is
        // visible yet. Wait for the count instead of racing it.
        assert!(
            wait_until(Duration::from_secs(3), || wd.restorations() >= 1),
            "a restoration should be counted"
        );
        assert!(
            wait_until(Duration::from_secs(3), || FIRED.load(Ordering::SeqCst) >= 1),
            "the tamper callback should have fired"
        );
        assert!(
            SAW_RESTORED.load(Ordering::SeqCst) >= 1,
            "callback should observe restored=true in Restore mode"
        );

        // After unguarding, tampering must stick.
        assert!(wd.unguard(id));
        let restores_after = wd.restorations();
        page.write(&[0xCCu8, 0xCC, 0xCC, 0xCC, 0xCC]);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(
            page.read(5),
            [0xCC; 5],
            "unguarded region must not be touched"
        );
        assert_eq!(
            wd.restorations(),
            restores_after,
            "no restorations after unguard"
        );
    }

    #[test]
    fn detect_only_reports_without_rewriting() {
        static FIRED: AtomicU32 = AtomicU32::new(0);
        FIRED.store(0, Ordering::SeqCst);

        let page = Page::new();
        let patched = [0xE9u8, 0x55, 0x66, 0x77, 0x88];
        page.write(&patched);

        let wd = Watchdog::with_interval(Duration::from_millis(10));
        wd.set_mode(WatchMode::DetectOnly);
        wd.on_tamper(|e| {
            assert!(!e.restored, "DetectOnly must never restore");
            FIRED.fetch_add(1, Ordering::SeqCst);
        });
        let _id = unsafe { wd.guard(page.0, patched.len()) }.expect("guard");
        assert_eq!(wd.mode(), WatchMode::DetectOnly);

        // Tamper: in DetectOnly the bytes must be left as-is.
        let tampered = [0x90u8, 0x90, 0x90, 0x90, 0x90];
        page.write(&tampered);

        assert!(
            wait_until(Duration::from_secs(5), || FIRED.load(Ordering::SeqCst) >= 1),
            "detect-only should report the tamper"
        );
        // Give a couple more sweeps: bytes stay tampered, and the callback must
        // not fire again for the same unbroken episode.
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(page.read(5), tampered, "DetectOnly must not rewrite bytes");
        assert_eq!(wd.restorations(), 0, "DetectOnly never restores");
        assert_eq!(
            FIRED.load(Ordering::SeqCst),
            1,
            "callback fires once per tamper episode, not every sweep"
        );
    }

    #[test]
    fn guard_rejects_invalid_input() {
        let wd = Watchdog::with_interval(Duration::from_millis(50));
        assert_eq!(
            unsafe { wd.guard(std::ptr::null(), 4) },
            Err(WatchdogError::InvalidParameter)
        );
        let page = Page::new();
        assert_eq!(
            unsafe { wd.guard(page.0, 0) },
            Err(WatchdogError::InvalidParameter)
        );
    }

    #[test]
    fn guard_bytes_uses_the_supplied_image() {
        let page = Page::new();
        page.write(&[0x00, 0x00, 0x00]);

        let wd = Watchdog::with_interval(Duration::from_millis(10));
        let want = [0xAAu8, 0xBB, 0xCC];
        // Guard against bytes that are not currently present; the watchdog should
        // write them in on its first sweep.
        let _id = unsafe { wd.guard_bytes(page.0, &want) }.expect("guard_bytes");

        let ok = wait_until(Duration::from_secs(5), || page.read(3) == want);
        assert!(ok, "watchdog should enforce the supplied image");
    }

    #[test]
    fn guard_id_round_trips_through_raw() {
        let id = GuardId::from_raw(42);
        assert_eq!(id.raw(), 42);
    }

    #[test]
    fn panicking_callback_does_not_kill_the_watchdog() {
        let page = Page::new();
        let patched = [0xE9u8, 0x01, 0x02, 0x03, 0x04];
        page.write(&patched);

        let wd = Watchdog::with_interval(Duration::from_millis(10));
        wd.on_tamper(|_e| panic!("intentional panic in tamper callback"));
        let _id = unsafe { wd.guard(page.0, patched.len()) }.expect("guard");

        // Silence the contained-panic message printed on the watchdog thread.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));

        // Tamper: the callback will panic, but the watchdog must survive and keep
        // restoring on this and subsequent sweeps.
        page.write(&[0x90, 0x90, 0x90, 0x90, 0x90]);
        let restored = wait_until(Duration::from_secs(5), || page.read(5) == patched);

        std::panic::set_hook(prev);

        assert!(
            restored,
            "watchdog must keep restoring despite a panicking callback"
        );
        // As above: the restored bytes become visible before the counter bump,
        // so wait for the count rather than reading it immediately.
        assert!(
            wait_until(Duration::from_secs(3), || wd.restorations() >= 1),
            "a restoration should be counted despite the panicking callback"
        );
    }
}
