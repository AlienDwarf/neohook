// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
// expect: E0277
use neohook::reentrancy_guard;

fn main() {
    // Dropped on another thread, the guard would clear that thread's flag.
    let guard = reentrancy_guard!().unwrap();
    std::thread::spawn(move || drop(guard));
}
