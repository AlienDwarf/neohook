// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
// expect: E0505
use neohook::DetourTransaction;

fn main() {
    let mut hooks = DetourTransaction::begin().commit().unwrap();

    let mut tx = DetourTransaction::begin();
    tx.detach(&mut hooks[0]).unwrap();
    // The queued hook must stay borrowed until the transaction is finished.
    drop(hooks);
    let _ = tx.commit();
}
