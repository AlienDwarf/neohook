/*
 * NeoHook C example: the anti-tamper watchdog and its tamper callback.
 *
 * The C counterpart of `examples/watchdog.rs`. Code that verifies its own
 * integrity can silently remove an inline hook by writing its original prologue
 * back. A watchdog snapshots the patched bytes and re-applies them from a
 * background thread as soon as anything reverts them, reporting each episode
 * through a callback.
 *
 * Note the ordering rules: guard the region *after* installing the hook (the
 * snapshot is what gets restored), and stop the watchdog *before* unhooking, or
 * it will faithfully re-install the patch you are trying to remove.
 *
 * Expected output:
 *   before hook:     1
 *   after hook:      9999
 *   guarding 5 byte(s) at 0x...
 *   tampered: original prologue written back
 *   [watchdog thread] tamper at 0x... len=5 restored=1
 *   after watchdog:  9999 (re-applied 1 time(s))
 *   after unhook:    1
 *   OK
 */

#include <windows.h>
#include <stdio.h>

#include "neohook.h"

/* The watchdog restores whatever it snapshotted, so guarding the first bytes of
   the patch is enough - NeoHook's smallest inline patch is 5 bytes. */
#define GUARDED_BYTES 5
#define TIMEOUT_MS 2000

typedef uint32_t(WINAPI *ProtectedFn)(void);

static volatile long g_tamper_events = 0;
static int g_failures = 0;

#define CHECK(cond, msg)                   \
    do {                                   \
        if (!(cond)) {                     \
            printf("  FAIL: %s\n", (msg)); \
            g_failures++;                  \
        }                                  \
    } while (0)

__declspec(noinline) static uint32_t WINAPI protected_function(void)
{
    volatile uint32_t value = 1;
    return value;
}

static uint32_t WINAPI detour(void)
{
    return 9999;
}

/* Calls through a volatile pointer so the optimizer cannot fold in the known
   return value and actually dispatches through the (possibly patched) entry. */
static uint32_t call_target(void)
{
    ProtectedFn volatile fn = protected_function;
    return fn();
}

/* Runs on the watchdog's background thread, once per tamper episode. */
static void on_tamper(uint64_t guard_id, const uint8_t *target, const uint8_t *expected,
                      const uint8_t *found, uintptr_t len, int32_t restored, void *user)
{
    (void)guard_id;
    (void)expected;
    (void)found;
    (void)user;

    printf("[watchdog thread] tamper at %p len=%llu restored=%d\n",
           (const void *)target, (unsigned long long)len, restored);
    InterlockedIncrement(&g_tamper_events);
}

/* Simulates an external integrity check writing the original prologue back. */
static int overwrite(uint8_t *target, const uint8_t *bytes, size_t len)
{
    DWORD old_protect = 0, tmp = 0;

    if (!VirtualProtect(target, len, PAGE_EXECUTE_READWRITE, &old_protect)) {
        return 0;
    }
    memcpy(target, bytes, len);
    FlushInstructionCache(GetCurrentProcess(), target, len);
    VirtualProtect(target, len, old_protect, &tmp);
    return 1;
}

int main(void)
{
    uint8_t original_bytes[GUARDED_BYTES];
    DetourTransaction *tx;
    struct Watchdog *wd;
    void *hooks;
    uint8_t *code;
    uint64_t guard_id;
    DWORD deadline;
    uint32_t value;

    /* Under an incremental link, &protected_function is a jump thunk rather than
       the function body. NeoHook follows such thunks when it patches, so resolve
       the same address here - otherwise we would guard the wrong bytes. */
    code = detours_code_from_pointer((const uint8_t *)protected_function);
    if (!code) {
        fprintf(stderr, "detours_code_from_pointer failed\n");
        return 1;
    }
    memcpy(original_bytes, code, sizeof(original_bytes));

    printf("before hook:     %u\n", call_target());

    tx = detours_transaction_begin();
    if (!tx) {
        fprintf(stderr, "detours_transaction_begin failed\n");
        return 1;
    }
    detours_transaction_update_all_threads(tx);
    if (!detours_transaction_attach(tx, (uint8_t *)protected_function, (const uint8_t *)detour)) {
        fprintf(stderr, "detours_transaction_attach failed\n");
        detours_transaction_abort(tx);
        return 1;
    }
    hooks = detours_transaction_commit(tx);
    if (!hooks) {
        fprintf(stderr, "detours_transaction_commit failed\n");
        return 1;
    }

    value = call_target();
    printf("after hook:      %u\n", value);
    CHECK(value == 9999, "the inline hook did not intercept the call");

    wd = detours_watchdog_create(20);
    if (!wd) {
        fprintf(stderr, "detours_watchdog_create failed\n");
        return 1;
    }
    CHECK(detours_watchdog_set_on_tamper(wd, on_tamper, NULL) != 0, "set_on_tamper failed");

    /* Snapshots the freshly written jump; that image is what gets re-applied. */
    guard_id = detours_watchdog_guard(wd, code, GUARDED_BYTES);
    printf("guarding %d byte(s) at %p\n", GUARDED_BYTES, (void *)code);
    CHECK(guard_id != 0, "watchdog_guard failed");

    /* The target is left in a half-patched state until the watchdog sweeps, so
       deliberately do not call it here. */
    CHECK(overwrite(code, original_bytes, sizeof(original_bytes)) != 0, "tampering failed");
    printf("tampered: original prologue written back\n");

    deadline = GetTickCount() + TIMEOUT_MS;
    while (detours_watchdog_restorations(wd) == 0 && GetTickCount() < deadline) {
        Sleep(10);
    }

    value = call_target();
    printf("after watchdog:  %u (re-applied %llu time(s))\n", value,
           (unsigned long long)detours_watchdog_restorations(wd));
    CHECK(value == 9999, "the watchdog did not re-apply the patch in time");
    CHECK(detours_watchdog_restorations(wd) >= 1, "no restoration was recorded");
    CHECK(g_tamper_events >= 1, "the tamper callback never fired");

    /* Stop guarding and shut the thread down before removing the hook. */
    CHECK(detours_watchdog_unguard(wd, guard_id) != 0, "watchdog_unguard failed");
    CHECK(detours_watchdog_destroy(wd) != 0, "watchdog_destroy failed");

    CHECK(detours_handle_unhook_and_free(hooks) != 0, "unhook_and_free failed");

    value = call_target();
    printf("after unhook:    %u\n", value);
    CHECK(value == 1, "the target was not restored");

    if (g_failures) {
        printf("FAILED (%d check(s))\n", g_failures);
        return 1;
    }
    printf("OK\n");
    return 0;
}
