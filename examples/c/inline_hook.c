/*
 * NeoHook C example: inline hooking through the transaction API.
 *
 * The C counterpart of `examples/attach_export.rs`. Resolves kernel32!GetTickCount
 * by name, overwrites its prologue with a jump to a detour, calls the original
 * through the returned trampoline, toggles the hook off and on again, and finally
 * restores everything by freeing the hook handle.
 *
 * Expected output:
 *   before hook:     GetTickCount() = <real tick count>
 *   after hook:      GetTickCount() = 3735928545
 *   via trampoline:  GetTickCount() = <real tick count>
 *   while disabled:  GetTickCount() = <real tick count>
 *   re-enabled:      GetTickCount() = 3735928545
 *   handle holds 1 hook(s)
 *   after unhook:    GetTickCount() = <real tick count>
 *   OK
 */

#include <windows.h>
#include <stdio.h>

#include "neohook.h"

/* A recognizable fixed value, so an intercepted call is unmistakable. */
#define FAKE_TICKS 0xDEADBEE1u

typedef uint32_t(WINAPI *GetTickCountFn)(void);

static int g_failures = 0;

#define CHECK(cond, msg)                          \
    do {                                          \
        if (!(cond)) {                            \
            printf("  FAIL: %s\n", (msg));        \
            g_failures++;                         \
        }                                         \
    } while (0)

static uint32_t WINAPI hooked_get_tick_count(void)
{
    return FAKE_TICKS;
}

int main(void)
{
    DetourTransaction *tx;
    GetTickCountFn original;
    uint8_t *trampoline;
    void *hooks;
    uint32_t ticks;

    printf("before hook:     GetTickCount() = %u\n", GetTickCount());

    tx = detours_transaction_begin();
    if (!tx) {
        fprintf(stderr, "detours_transaction_begin failed\n");
        return 1;
    }

    /* Suspend the other threads for the duration of the patch, so none of them
       can be executing inside the prologue we are about to overwrite. */
    detours_transaction_update_all_threads(tx);

    /* One call instead of GetModuleHandle + GetProcAddress + attach. */
    trampoline = detours_transaction_attach_export(
        tx, "kernel32.dll", "GetTickCount", (const uint8_t *)hooked_get_tick_count);
    if (!trampoline) {
        fprintf(stderr, "detours_transaction_attach_export failed\n");
        detours_transaction_abort(tx);
        return 1;
    }

    /* Commit consumes the transaction and hands back a handle owning the hooks. */
    hooks = detours_transaction_commit(tx);
    if (!hooks) {
        fprintf(stderr, "detours_transaction_commit failed\n");
        return 1;
    }

    original = (GetTickCountFn)trampoline;

    ticks = GetTickCount();
    printf("after hook:      GetTickCount() = %u\n", ticks);
    CHECK(ticks == FAKE_TICKS, "the detour did not intercept the call");

    /* The trampoline holds the relocated prologue plus a jump back into the
       untouched remainder of the function, so it reaches the real implementation. */
    ticks = original();
    printf("via trampoline:  GetTickCount() = %u\n", ticks);
    CHECK(ticks != FAKE_TICKS, "the trampoline re-entered the detour");

    /* Disabling restores the original bytes but keeps the hook installed, which
       is much cheaper than an unhook/rehook cycle. */
    CHECK(detours_handle_set_enabled(hooks, 0, 0) != 0, "set_enabled(0) failed");
    CHECK(detours_handle_is_enabled(hooks, 0) == 0, "hook still reports enabled");
    ticks = GetTickCount();
    printf("while disabled:  GetTickCount() = %u\n", ticks);
    CHECK(ticks != FAKE_TICKS, "the disabled hook still intercepted the call");

    CHECK(detours_handle_set_enabled(hooks, 0, 1) != 0, "set_enabled(1) failed");
    CHECK(detours_handle_is_enabled(hooks, 0) != 0, "hook does not report enabled");
    ticks = GetTickCount();
    printf("re-enabled:      GetTickCount() = %u\n", ticks);
    CHECK(ticks == FAKE_TICKS, "the re-enabled hook did not intercept the call");

    printf("handle holds %llu hook(s)\n",
           (unsigned long long)detours_handle_len(hooks));
    CHECK(detours_handle_len(hooks) == 1, "unexpected hook count");

    /* Frees the handle and unhooks everything it owns. */
    CHECK(detours_handle_unhook_and_free(hooks) != 0, "unhook_and_free failed");

    ticks = GetTickCount();
    printf("after unhook:    GetTickCount() = %u\n", ticks);
    CHECK(ticks != FAKE_TICKS, "the target was not restored");

    if (g_failures) {
        printf("FAILED (%d check(s))\n", g_failures);
        return 1;
    }
    printf("OK\n");
    return 0;
}
