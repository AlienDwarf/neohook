/*
 * NeoHook C++ example: breakpoint-based hooks (VEH and INT3).
 *
 * Both redirect a function without leaving a jump in its prologue, and both are
 * plain replacements - the detour does not get a trampoline. Passing through to
 * the original therefore needs the *_with_original variant, which builds a
 * callable gateway that reaches the real implementation without re-triggering
 * the breakpoint.
 *
 *   VehHook  - a hardware breakpoint in a debug register. The target's bytes are
 *              never modified at all, but there are only four debug registers,
 *              and each thread has its own set.
 *   Int3Hook - a single 0xCC byte plus a vectored handler. No four-hook ceiling,
 *              and threads created after the install still trap.
 *
 * Expected output:
 *   baseline:             checksum(7) = 70
 *   VEH hook:             checksum(7) = 71  (70 from the original + 1)
 *   after VEH unhook:     checksum(7) = 70
 *   INT3 hook:            checksum(7) = 1070  (70 from the original + 1000)
 *   after INT3 unhook:    checksum(7) = 70
 *   OK
 */

#include <windows.h>

#include <cstdint>
#include <cstdio>

#include "neohook.hpp"

namespace {

int g_failures = 0;

void check(bool condition, const char *message)
{
    if (!condition) {
        std::printf("  FAIL: %s\n", message);
        ++g_failures;
    }
}

using ChecksumFn = std::uint32_t(WINAPI *)(std::uint32_t);

__declspec(noinline) std::uint32_t WINAPI checksum(std::uint32_t value)
{
    volatile std::uint32_t v = value;
    return v * 10;
}

// The detours need the gateway of the hook that is currently installed; the
// guards are stored here so the free functions below can reach them.
neohook::VehHook *g_veh = nullptr;
neohook::Int3Hook *g_int3 = nullptr;

std::uint32_t WINAPI veh_detour(std::uint32_t value)
{
    ChecksumFn original = g_veh->original<ChecksumFn>();
    return original ? original(value) + 1 : 0;
}

std::uint32_t WINAPI int3_detour(std::uint32_t value)
{
    ChecksumFn original = g_int3->original<ChecksumFn>();
    return original ? original(value) + 1000 : 0;
}

std::uint32_t call_checksum(std::uint32_t value)
{
    ChecksumFn volatile fn = checksum;
    return fn(value);
}

} // namespace

int main()
{
    try {
        std::uint32_t value = call_checksum(7);
        std::printf("baseline:             checksum(7) = %u\n", value);
        check(value == 70, "unexpected baseline result");

        {
            // Static factory instead of a constructor, because it needs a second
            // C entry point (detours_veh_install_with_original).
            neohook::VehHook hook = neohook::VehHook::with_original(
                reinterpret_cast<const void *>(&checksum), reinterpret_cast<const void *>(&veh_detour));
            g_veh = &hook;

            value = call_checksum(7);
            std::printf("VEH hook:             checksum(7) = %u\n", value);
            check(value == 71, "the VEH hook did not intercept the call");
        }
        g_veh = nullptr;

        value = call_checksum(7);
        std::printf("after VEH unhook:     checksum(7) = %u\n", value);
        check(value == 70, "the debug register was not cleared");

        {
            neohook::Int3Hook hook = neohook::Int3Hook::with_original(
                reinterpret_cast<const void *>(&checksum),
                reinterpret_cast<const void *>(&int3_detour));
            g_int3 = &hook;

            value = call_checksum(7);
            std::printf("INT3 hook:            checksum(7) = %u\n", value);
            check(value == 1070, "the INT3 hook did not intercept the call");
        }
        g_int3 = nullptr;

        value = call_checksum(7);
        std::printf("after INT3 unhook:    checksum(7) = %u\n", value);
        check(value == 70, "the 0xCC byte was not restored");
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
