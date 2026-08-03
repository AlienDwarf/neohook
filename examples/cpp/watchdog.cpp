/*
 * NeoHook C++ example: the anti-tamper watchdog.
 *
 * The C++ counterpart of `examples/watchdog.rs`. Code that verifies its own
 * integrity can silently remove an inline hook by writing its original prologue
 * back. neohook::Watchdog snapshots the patched bytes and re-applies them from a
 * background thread as soon as anything reverts them, reporting each episode
 * through a callback.
 *
 * Two ordering rules matter:
 *   - guard() *after* installing the hook - the snapshot is what gets restored.
 *   - stop the watchdog *before* unhooking, or it will faithfully re-install the
 *     very patch you are removing. Here the nested scopes do that for us: the
 *     Watchdog is declared after the HookGuard, so it is destroyed first.
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

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "neohook.hpp"

namespace {

// The watchdog restores whatever it snapshotted, so guarding the first bytes of
// the patch is enough - NeoHook's smallest inline patch is 5 bytes.
constexpr std::size_t kGuardedBytes = 5;
constexpr DWORD kTimeoutMs = 2000;

std::atomic<int> g_tamper_events{0};
int g_failures = 0;

void check(bool condition, const char *message)
{
    if (!condition) {
        std::printf("  FAIL: %s\n", message);
        ++g_failures;
    }
}

using ProtectedFn = std::uint32_t(WINAPI *)();

__declspec(noinline) std::uint32_t WINAPI protected_function()
{
    volatile std::uint32_t value = 1;
    return value;
}

std::uint32_t WINAPI detour()
{
    return 9999;
}

std::uint32_t call_target()
{
    ProtectedFn volatile fn = protected_function;
    return fn();
}

// Runs on the watchdog's background thread, once per tamper episode.
void on_tamper(std::uint64_t guard_id, const std::uint8_t *target, const std::uint8_t *expected,
               const std::uint8_t *found, std::uintptr_t len, std::int32_t restored, void *user)
{
    (void)guard_id;
    (void)expected;
    (void)found;
    (void)user;

    std::printf("[watchdog thread] tamper at %p len=%llu restored=%d\n",
                static_cast<const void *>(target), static_cast<unsigned long long>(len), restored);
    g_tamper_events.fetch_add(1);
}

// Simulates an external integrity check writing the original prologue back.
bool overwrite(std::uint8_t *target, const std::uint8_t *bytes, std::size_t len)
{
    DWORD old_protect = 0;
    DWORD tmp = 0;

    if (!VirtualProtect(target, len, PAGE_EXECUTE_READWRITE, &old_protect)) {
        return false;
    }
    std::memcpy(target, bytes, len);
    FlushInstructionCache(GetCurrentProcess(), target, len);
    VirtualProtect(target, len, old_protect, &tmp);
    return true;
}

} // namespace

int main()
{
    try {
        // Under an incremental link, &protected_function is a jump thunk rather
        // than the function body. NeoHook follows such thunks when it patches, so
        // resolve the same address here - otherwise we would guard the wrong bytes.
        auto *code = static_cast<std::uint8_t *>(
            neohook::code_from_pointer(reinterpret_cast<const void *>(&protected_function)));
        if (!code) {
            std::fprintf(stderr, "code_from_pointer failed\n");
            return 1;
        }

        std::uint8_t original_bytes[kGuardedBytes];
        std::memcpy(original_bytes, code, sizeof(original_bytes));

        std::printf("before hook:     %u\n", call_target());

        std::uint32_t value = 0;
        {
            neohook::Transaction tx;
            tx.update_all_threads();
            tx.attach(reinterpret_cast<void *>(&protected_function), &detour);
            neohook::HookGuard hooks = tx.commit();

            value = call_target();
            std::printf("after hook:      %u\n", value);
            check(value == 9999, "the inline hook did not intercept the call");

            {
                // Nested inside the hook's scope, so the watchdog is destroyed -
                // and its thread joined - before the HookGuard removes the patch.
                neohook::Watchdog wd(20);
                check(wd.on_tamper(&on_tamper), "on_tamper failed");

                // Snapshots the freshly written jump; that image is re-applied.
                std::uint64_t guard_id = wd.guard(code, kGuardedBytes);
                std::printf("guarding %zu byte(s) at %p\n", kGuardedBytes,
                            static_cast<void *>(code));
                check(guard_id != 0, "guard() failed");

                // The target is left half-patched until the watchdog sweeps, so
                // deliberately do not call it here.
                check(overwrite(code, original_bytes, sizeof(original_bytes)), "tampering failed");
                std::printf("tampered: original prologue written back\n");

                const DWORD deadline = GetTickCount() + kTimeoutMs;
                while (wd.restorations() == 0 && GetTickCount() < deadline) {
                    Sleep(10);
                }

                value = call_target();
                std::printf("after watchdog:  %u (re-applied %llu time(s))\n", value,
                            static_cast<unsigned long long>(wd.restorations()));
                check(value == 9999, "the watchdog did not re-apply the patch in time");
                check(wd.restorations() >= 1, "no restoration was recorded");
                check(g_tamper_events.load() >= 1, "the tamper callback never fired");

                check(wd.unguard(guard_id), "unguard() failed");
            } // the watchdog stops here
        } // the HookGuard removes the patch here

        value = call_target();
        std::printf("after unhook:    %u\n", value);
        check(value == 1, "the target was not restored");
    } catch (const std::exception &e) {
        std::fprintf(stderr, "unexpected exception: %s\n", e.what());
        return 1;
    }

    if (g_failures) {
        std::printf("FAILED (%d check(s))\n", g_failures);
        return 1;
    }
    std::printf("OK\n");
    return 0;
}
