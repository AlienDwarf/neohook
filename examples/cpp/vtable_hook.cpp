/*
 * NeoHook C++ example: virtual-table hooking, shared and per-instance.
 *
 * Redirecting a vtable slot leaves the target's code untouched - only the
 * function pointer in the table changes. This is how DirectX / COM interfaces
 * are usually intercepted, so the interface below uses the same shape: pure
 * virtual methods declared __stdcall, which makes `this` an ordinary leading
 * parameter and lets a plain free function stand in as the detour on both x86
 * and x64.
 *
 * Two variants are shown:
 *   attach_vtable          - patches the shared table, affecting every instance.
 *   attach_vtable_instance - clones the table for one object, leaving its
 *                            siblings on the original implementation.
 *
 * The calls go through noinline helpers so the optimizer cannot devirtualize
 * them and call the implementation directly, bypassing the table we patch.
 *
 * Expected output:
 *   fresh objects:      a.draw(3) = 3   b.draw(3) = 3
 *   shared vtable hook: a.draw(3) = 300 b.draw(3) = 300
 *   after unhook:       a.draw(3) = 3   b.draw(3) = 3
 *   per-instance hook:  a.draw(3) = 777 b.draw(3) = 3
 *   after unhook:       a.draw(3) = 3   b.draw(3) = 3
 *   OK
 */

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <memory>

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

// A COM-style interface. There is deliberately no virtual destructor: it would
// occupy slot 0 and shift the indices below.
struct IRenderer
{
    virtual int STDMETHODCALLTYPE draw(int scale) = 0;
    virtual int STDMETHODCALLTYPE frame_count() = 0;
    virtual void STDMETHODCALLTYPE destroy() = 0;
};

constexpr std::size_t kSlotDraw = 0;
constexpr std::size_t kVTableSlots = 3;

struct Renderer final : IRenderer
{
    int STDMETHODCALLTYPE draw(int scale) override { return scale; }
    int STDMETHODCALLTYPE frame_count() override { return 42; }
    void STDMETHODCALLTYPE destroy() override { delete this; }
};

using DrawFn = int(STDMETHODCALLTYPE *)(IRenderer *, int);

DrawFn g_original_draw = nullptr;

int STDMETHODCALLTYPE draw_x100(IRenderer *self, int scale)
{
    // Forward to the original implementation and scale its result.
    return g_original_draw ? g_original_draw(self, scale) * 100 : -1;
}

int STDMETHODCALLTYPE draw_fixed(IRenderer *self, int scale)
{
    (void)self;
    (void)scale;
    return 777;
}

// Hiding the concrete type behind a noinline boundary keeps MSVC from proving
// the dynamic type and turning the virtual calls below into direct ones.
__declspec(noinline) IRenderer *make_renderer()
{
    return new Renderer();
}

__declspec(noinline) int call_draw(IRenderer *renderer, int scale)
{
    return renderer->draw(scale);
}

__declspec(noinline) int call_frame_count(IRenderer *renderer)
{
    return renderer->frame_count();
}

// The vptr is the first word of a single-inheritance polymorphic object.
void **vptr_of(IRenderer *object)
{
    return *reinterpret_cast<void ***>(object);
}

void report(const char *label, IRenderer *a, IRenderer *b)
{
    const int left = call_draw(a, 3);
    const int right = call_draw(b, 3);
    std::printf("%-19s a.draw(3) = %-3d b.draw(3) = %d\n", label, left, right);
}

} // namespace

int main()
{
    int exit_code = 0;
    IRenderer *a = make_renderer();
    IRenderer *b = make_renderer();

    try {
        check(call_frame_count(a) == 42, "unexpected baseline frame_count");
        report("fresh objects:", a, b);
        check(call_draw(a, 3) == 3 && call_draw(b, 3) == 3, "unexpected baseline draw()");

        // --- Shared vtable: both instances share one table, so both change. ---
        {
            neohook::Transaction tx;
            g_original_draw = tx.attach_vtable(vptr_of(a), kSlotDraw, &draw_x100);
            neohook::HookGuard guard = tx.commit();

            report("shared vtable hook:", a, b);
            check(call_draw(a, 3) == 300, "the shared vtable hook missed instance a");
            check(call_draw(b, 3) == 300, "a shared vtable hook must affect every instance");
            check(call_frame_count(a) == 42, "an unrelated slot was disturbed");
        }
        g_original_draw = nullptr;

        report("after unhook:", a, b);
        check(call_draw(a, 3) == 3 && call_draw(b, 3) == 3, "the shared vtable was not restored");

        // --- Per-instance: the table is cloned, so only `a` is redirected. ---
        {
            neohook::Transaction tx;
            tx.attach_vtable_instance(reinterpret_cast<void **>(a), kSlotDraw, kVTableSlots,
                                      &draw_fixed);
            neohook::HookGuard guard = tx.commit();

            report("per-instance hook:", a, b);
            check(call_draw(a, 3) == 777, "the per-instance hook missed its object");
            check(call_draw(b, 3) == 3, "a per-instance hook must not affect siblings");
            check(call_frame_count(a) == 42, "the cloned vtable lost an unrelated slot");
        }

        report("after unhook:", a, b);
        check(call_draw(a, 3) == 3 && call_draw(b, 3) == 3, "the object's vptr was not restored");
    } catch (const std::exception &e) {
        std::fprintf(stderr, "unexpected exception: %s\n", e.what());
        exit_code = 1;
    }

    a->destroy();
    b->destroy();

    if (exit_code || g_failures) {
        std::printf("FAILED (%d check(s))\n", g_failures);
        return 1;
    }
    std::printf("OK\n");
    return 0;
}
