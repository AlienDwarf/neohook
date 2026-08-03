/*
 * NeoHook C example: IAT (Import Address Table) hooking.
 *
 * The C counterpart of `examples/iat_sleep.rs`. Instead of patching the target's
 * bytes, this rewrites the pointer this executable's import table uses for
 * kernel32!GetTickCount. The scope is therefore narrower than an inline hook:
 * calls made through *this module's* imports are redirected, while a pointer
 * resolved directly with GetProcAddress still reaches the untouched original.
 *
 * Expected output:
 *   hooked GetTickCount import from KERNEL32.dll
 *   through this module's IAT:   3735928545  (intercepted)
 *   through GetProcAddress:      <real tick count>  (not intercepted)
 *   detour saw 1 call(s), original still returns <real tick count>
 *   after unhook:                <real tick count>
 *   OK
 */

#include <windows.h>
#include <stdio.h>

#include "neohook.h"

#define FAKE_TICKS 0xDEADBEE1u

typedef uint32_t(WINAPI *GetTickCountFn)(void);

static GetTickCountFn g_original = NULL;
static int g_detour_calls = 0;
static int g_failures = 0;

#define CHECK(cond, msg)                   \
    do {                                   \
        if (!(cond)) {                     \
            printf("  FAIL: %s\n", (msg)); \
            g_failures++;                  \
        }                                  \
    } while (0)

static uint32_t WINAPI hooked_get_tick_count(void)
{
    g_detour_calls++;
    return FAKE_TICKS;
}

/*
 * Import slots are not volatile, so an optimizing compiler is free to load
 * __imp__GetTickCount once and reuse the value for every later call - which
 * makes an IAT hook look like it was never removed. MSVC does exactly that on
 * x86 at /O2. Routing observations through a noinline wrapper forces the slot
 * to be re-read on each call. An inline hook needs no such care: there the
 * pointer stays the same and the code behind it changes.
 */
__declspec(noinline) static uint32_t observe_get_tick_count(void)
{
    return GetTickCount();
}

int main(void)
{
    /* Depending on the Windows version and how the import was linked, the entry
       may sit under the API-set name, KERNELBASE or KERNEL32 - try each. */
    static const char *const dll_candidates[] = {
        "api-ms-win-core-sysinfo-l1-1-0.dll",
        "KERNELBASE.dll",
        "KERNEL32.dll",
    };

    HMODULE self;
    DetourTransaction *tx;
    const char *hooked_from = NULL;
    GetTickCountFn direct;
    void *hooks;
    uint32_t ticks;
    size_t i;

    self = GetModuleHandleW(NULL);
    if (!self) {
        fprintf(stderr, "GetModuleHandleW(NULL) failed\n");
        return 1;
    }

    /* Resolved by hand, so it bypasses the import table entirely. */
    direct = (GetTickCountFn)(void *)detours_find_function("kernel32.dll", "GetTickCount");
    if (!direct) {
        fprintf(stderr, "detours_find_function failed\n");
        return 1;
    }

    tx = detours_transaction_begin();
    if (!tx) {
        fprintf(stderr, "detours_transaction_begin failed\n");
        return 1;
    }

    for (i = 0; i < sizeof(dll_candidates) / sizeof(dll_candidates[0]); ++i) {
        if (detours_transaction_attach_iat(tx, self, dll_candidates[i], "GetTickCount",
                                           (const uint8_t *)hooked_get_tick_count)) {
            hooked_from = dll_candidates[i];
            break;
        }
    }

    if (!hooked_from) {
        fprintf(stderr, "no imported GetTickCount found in this module\n");
        detours_transaction_abort(tx);
        return 1;
    }
    printf("hooked GetTickCount import from %s\n", hooked_from);

    hooks = detours_transaction_commit(tx);
    if (!hooks) {
        fprintf(stderr, "detours_transaction_commit failed\n");
        return 1;
    }

    /* For an IAT hook this is the original imported function pointer, not a
       trampoline - the target's code was never modified. */
    g_original = (GetTickCountFn)(void *)detours_handle_get_original_ptr(hooks, 0);
    CHECK(g_original != NULL, "no original pointer for the IAT hook");

    ticks = observe_get_tick_count();
    printf("through this module's IAT:   %u  (intercepted)\n", ticks);
    CHECK(ticks == FAKE_TICKS, "the IAT hook did not intercept the call");

    ticks = direct();
    printf("through GetProcAddress:      %u  (not intercepted)\n", ticks);
    CHECK(ticks != FAKE_TICKS, "an IAT hook must not affect direct calls");

    printf("detour saw %d call(s), original still returns %u\n",
           g_detour_calls, g_original ? g_original() : 0);
    CHECK(g_detour_calls == 1, "unexpected detour call count");

    CHECK(detours_handle_unhook_and_free(hooks) != 0, "unhook_and_free failed");

    ticks = observe_get_tick_count();
    printf("after unhook:                %u\n", ticks);
    CHECK(ticks != FAKE_TICKS, "the import slot was not restored");

    if (g_failures) {
        printf("FAILED (%d check(s))\n", g_failures);
        return 1;
    }
    printf("OK\n");
    return 0;
}
