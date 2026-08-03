/*
 * NeoHook C++ example: the RAII transaction wrapper.
 *
 * neohook.hpp wraps the C ABI in exception-safe types: neohook::Transaction
 * aborts itself if it is destroyed before commit(), and the neohook::HookGuard
 * that commit() hands back unhooks everything it owns when it goes out of scope.
 * No explicit cleanup path is needed, even when something throws in between.
 *
 * Expected output:
 *   before hook:     GetTickCount() = <real tick count>
 *   after hook:      GetTickCount() = 3735928545
 *   via trampoline:  GetTickCount() = <real tick count>
 *   while disabled:  GetTickCount() = <real tick count>
 *   re-enabled:      GetTickCount() = 3735928545
 *   guard owns 1 hook(s)
 *   after scope exit: GetTickCount() = <real tick count>
 *   an abandoned transaction rolls back: GetTickCount() = <real tick count>
 *   OK
 */

#include <windows.h>

#include <cstdint>
#include <cstdio>

#include "neohook.hpp"

namespace {

constexpr std::uint32_t kFakeTicks = 0xDEADBEE1u;

using GetTickCountFn = std::uint32_t(WINAPI *)();

int g_failures = 0;

void check(bool condition, const char *message)
{
    if (!condition) {
        std::printf("  FAIL: %s\n", message);
        ++g_failures;
    }
}

std::uint32_t WINAPI hooked_get_tick_count()
{
    return kFakeTicks;
}

} // namespace

int main()
{
    try {
        std::printf("before hook:     GetTickCount() = %u\n", GetTickCount());

        {
            neohook::Transaction tx;
            tx.update_all_threads();

            // The template argument is deduced from the detour, so the returned
            // trampoline comes back already typed.
            GetTickCountFn original =
                tx.attach_export("kernel32.dll", "GetTickCount", &hooked_get_tick_count);

            // commit() transfers ownership of the installed hooks to the guard.
            neohook::HookGuard guard = tx.commit();

            std::uint32_t ticks = GetTickCount();
            std::printf("after hook:      GetTickCount() = %u\n", ticks);
            check(ticks == kFakeTicks, "the detour did not intercept the call");

            ticks = original();
            std::printf("via trampoline:  GetTickCount() = %u\n", ticks);
            check(ticks != kFakeTicks, "the trampoline re-entered the detour");

            // Disable restores the original bytes but keeps the hook installed,
            // which is far cheaper than an unhook/rehook cycle.
            check(guard.disable(0), "disable() failed");
            check(!guard.is_enabled(0), "hook still reports enabled");
            ticks = GetTickCount();
            std::printf("while disabled:  GetTickCount() = %u\n", ticks);
            check(ticks != kFakeTicks, "the disabled hook still intercepted the call");

            check(guard.enable(0), "enable() failed");
            check(guard.is_enabled(0), "hook does not report enabled");
            ticks = GetTickCount();
            std::printf("re-enabled:      GetTickCount() = %u\n", ticks);
            check(ticks == kFakeTicks, "the re-enabled hook did not intercept the call");

            std::printf("guard owns %zu hook(s)\n", guard.count());
            check(guard.count() == 1, "unexpected hook count");

            // The guard's destructor unhooks here.
        }

        std::uint32_t ticks = GetTickCount();
        std::printf("after scope exit: GetTickCount() = %u\n", ticks);
        check(ticks != kFakeTicks, "the target was not restored");

        {
            // A transaction destroyed before commit() aborts, so the queued hook
            // is discarded and nothing is patched.
            neohook::Transaction tx;
            tx.attach_export("kernel32.dll", "GetTickCount", &hooked_get_tick_count);
        }

        ticks = GetTickCount();
        std::printf("an abandoned transaction rolls back: GetTickCount() = %u\n", ticks);
        check(ticks != kFakeTicks, "an aborted transaction installed a hook anyway");
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
