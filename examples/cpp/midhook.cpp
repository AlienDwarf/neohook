/*
 * NeoHook C++ example: mid-function detour with a full register context.
 *
 * The C++ counterpart of `examples/midhook.rs`. Unlike an entry-point hook, a
 * mid-function detour can sit at *any* instruction boundary and is reached with
 * arbitrary registers live. NeoHook snapshots the CPU state, hands the handler a
 * ::HookContext it may read and modify, restores it, then resumes the original
 * instructions - so an edit to the context is visible to the code that follows.
 *
 * ::HookContext has a different shape per architecture, and neohook.h emits
 * exactly one definition guarded by the compiler's _M_X64 / _M_IX86 macros. The
 * handler below is written against both.
 *
 * Expected output (x64):
 *   price_for(2) before hook = 200
 *     [handler] observed quantity = 2
 *   price_for(2) while hooked = 700   (2 + 5 free units) * 100
 *   price_for(2) after unhook = 200
 *   OK
 */

#include <windows.h>

#include <cstdint>
#include <cstdio>

#include "neohook.hpp"

namespace {

int g_failures = 0;
int g_handler_calls = 0;

void check(bool condition, const char *message)
{
    if (!condition) {
        std::printf("  FAIL: %s\n", message);
        ++g_failures;
    }
}

// Pretend this sits deep inside a larger program. `volatile` keeps the argument
// out of a constant fold so the multiplication really happens at run time.
__declspec(noinline) std::uint64_t WINAPI price_for(std::uint64_t quantity)
{
    volatile std::uint64_t q = quantity;
    return q * 100;
}

#if defined(_M_X64)
void handle_price(HookContext *ctx)
{
    // Win64 passes the first integer argument in RCX. Bump the quantity before
    // the stolen instructions run, giving every order five free units.
    std::printf("  [handler] observed quantity = %llu\n", (unsigned long long)ctx->rcx);
    ctx->rcx += 5;
    ++g_handler_calls;
}
#elif defined(_M_IX86)
void handle_price(HookContext *ctx)
{
    // On x86 __stdcall arguments arrive on the stack, so this handler observes a
    // register instead of rewriting the argument.
    std::printf("  [handler] eax = 0x%08X\n", ctx->eax);
    ++g_handler_calls;
}
#else
#error "This example covers x86 and x86_64 only."
#endif

// Called through a volatile pointer so the compiler dispatches through the
// (possibly patched) function entry instead of folding in the result.
std::uint64_t call_price_for(std::uint64_t quantity)
{
    std::uint64_t(WINAPI * volatile fn)(std::uint64_t) = price_for;
    return fn(quantity);
}

} // namespace

int main()
{
    try {
        std::uint64_t before = call_price_for(2);
        std::printf("price_for(2) before hook = %llu\n", (unsigned long long)before);
        check(before == 200, "unexpected baseline result");

        {
            // The guard restores the original bytes and releases the context
            // bridge stub when it leaves scope.
            neohook::MidHook hook(reinterpret_cast<const void *>(&price_for), &handle_price);

            std::uint64_t hooked = call_price_for(2);
            std::printf("price_for(2) while hooked = %llu\n", (unsigned long long)hooked);
            check(g_handler_calls == 1, "the context handler did not run");
#if defined(_M_X64)
            check(hooked == 700, "the handler's RCX edit did not take effect");
#else
            check(hooked == 200, "an observing handler must not change the result");
#endif
        }

        std::uint64_t after = call_price_for(2);
        std::printf("price_for(2) after unhook = %llu\n", (unsigned long long)after);
        check(after == 200, "the target was not restored");
        check(g_handler_calls == 1, "the handler ran after the hook was removed");
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
