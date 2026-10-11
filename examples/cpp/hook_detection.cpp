/*
 * NeoHook C++ example: hook detection.
 *
 * Checks a function, hooks it with an inline hook, checks it again - this time
 * the jump and its destination are found - and scans kernel32 for hooks.
 *
 * Expected output: the findings, ending in
 *   OK
 */

#include <windows.h>

#include <cstdio>
#include <cstdlib>

#include "neohook.hpp"

namespace {

void check(bool ok, const char *what)
{
    if (!ok) {
        std::printf("FAIL: %s\n", what);
        std::exit(1);
    }
}

const char *kind_name(uint8_t kind)
{
    switch (kind) {
    case DETOURS_DETECTED_INLINE_JUMP: return "inline jump";
    case DETOURS_DETECTED_BREAKPOINT: return "breakpoint";
    case DETOURS_DETECTED_HARDWARE_BREAKPOINT: return "hardware breakpoint";
    case DETOURS_DETECTED_MODIFIED_CODE: return "modified code";
    case DETOURS_DETECTED_IMPORT_REDIRECT: return "import redirect";
    case DETOURS_DETECTED_EXPORT_REDIRECT: return "export redirect";
    default: return "?";
    }
}

extern "C" __declspec(noinline) int target(int x)
{
    return x * 3 + 1;
}

extern "C" __declspec(noinline) int detour(int x)
{
    return x + 1000;
}

} // namespace

int main()
{
    try {
        check(!neohook::check_function(reinterpret_cast<const void *>(&target)).has_value(),
              "the function is hooked before anything hooked it");

        neohook::Transaction tx;
        tx.update_all_threads();
        tx.attach(reinterpret_cast<void *>(&target), &detour);
        neohook::HookGuard guard = tx.commit();

        auto hook = neohook::check_function(reinterpret_cast<const void *>(&target));
        check(hook.has_value(), "the inline hook was not found");
        std::printf("target: %s at %p -> %p in %s\n", kind_name(hook->kind), static_cast<const void *>(hook->address),
                    static_cast<const void *>(hook->destination),
                    hook->destination_module[0] ? hook->destination_module : "private memory");
        check(hook->kind == DETOURS_DETECTED_INLINE_JUMP, "not reported as an inline jump");
        check(hook->destination == neohook::code_from_pointer(reinterpret_cast<const void *>(&detour)),
              "the destination is not the detour");

        std::vector<DetoursDetectedHook> found = neohook::scan_module_hooks("kernel32.dll");
        std::printf("kernel32.dll: %zu hook(s)\n", found.size());
        for (const DetoursDetectedHook &h : found)
            std::printf("  %s %s\n", kind_name(h.kind), h.function);
    } catch (const std::exception &e) {
        std::printf("FAIL: %s\n", e.what());
        return 1;
    }

    std::printf("OK\n");
    return 0;
}
