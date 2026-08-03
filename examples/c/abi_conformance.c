/*
 * NeoHook C example: compile-time ABI conformance checks.
 *
 * `HookContext` is the one type NeoHook passes by address into foreign code, so
 * the struct cbindgen emits into neohook.h has to agree, field for field, with
 * the Rust struct the mid-hook stub actually writes. A disagreement is invisible
 * from Rust - it only shows up as a foreign handler reading the wrong register.
 *
 * This file is the last link in the chain that rules that out:
 *
 *   stub <-> Rust struct   `x86_context_layout_matches_stub` and friends,
 *                          unit tests in src/midhook.rs
 *   Rust struct <-> header the "generated C header is up to date" CI step,
 *                          which regenerates neohook.h and diffs it
 *   header <-> C           this file
 *
 * Everything below is checked by the compiler, so a mismatch is a *build*
 * failure rather than a test failure; main() only reports what was verified. If
 * these numbers ever need updating, that is the signal to check whether the stub
 * was updated too.
 */

#include <windows.h>
#include <stddef.h>
#include <stdio.h>

#include "neohook.h"

/*
 * `_Static_assert` needs C11 and `static_assert` needs <assert.h> from C11, but
 * this file should compile as far back as C89 - it is the one place where being
 * portable is the whole point. The negative-array-size trick works everywhere.
 */
#define NEOHOOK_CAT_(a, b) a##b
#define NEOHOOK_CAT(a, b) NEOHOOK_CAT_(a, b)
#define STATIC_ASSERT(cond) \
    typedef char NEOHOOK_CAT(neohook_static_assert_, __LINE__)[(cond) ? 1 : -1]

/* `_Alignof` is C11 too; a leading char measures the same thing portably. */
struct neohook_align_probe_xmm {
    char c;
    struct Xmm x;
};
#define ALIGNOF_XMM offsetof(struct neohook_align_probe_xmm, x)

struct neohook_align_probe_ctx {
    char c;
    struct HookContext x;
};
#define ALIGNOF_HOOK_CONTEXT offsetof(struct neohook_align_probe_ctx, x)

/*
 * If neither arch macro is defined, neohook.h declares no HookContext at all and
 * every check below would fail with a confusing "incomplete type" cascade. Say
 * so plainly instead. GCC / MinGW land here: they define __x86_64__ rather than
 * the MSVC-style _M_X64, so mid-function hooks are MSVC / clang-cl only today.
 */
#if !defined(_M_X64) && !defined(_M_IX86)
#error "neohook.h defines HookContext only for _M_X64 / _M_IX86 (MSVC or clang-cl)."
#endif

/* ------------------------------------------------------------------ Xmm --- */

STATIC_ASSERT(sizeof(struct Xmm) == 16);
STATIC_ASSERT(ALIGNOF_XMM == 8);
STATIC_ASSERT(offsetof(struct Xmm, low) == 0);
STATIC_ASSERT(offsetof(struct Xmm, high) == 8);

/* ---------------------------------------------------------- HookContext --- */

STATIC_ASSERT(ALIGNOF_HOOK_CONTEXT == 8);

#if defined(_M_X64)

STATIC_ASSERT(sizeof(struct HookContext) == 400);

STATIC_ASSERT(offsetof(struct HookContext, rflags) == 0);
STATIC_ASSERT(offsetof(struct HookContext, rax) == 8);
STATIC_ASSERT(offsetof(struct HookContext, rcx) == 16);
STATIC_ASSERT(offsetof(struct HookContext, rdx) == 24);
STATIC_ASSERT(offsetof(struct HookContext, rbx) == 32);
STATIC_ASSERT(offsetof(struct HookContext, rbp) == 40);
STATIC_ASSERT(offsetof(struct HookContext, rsi) == 48);
STATIC_ASSERT(offsetof(struct HookContext, rdi) == 56);
STATIC_ASSERT(offsetof(struct HookContext, r8) == 64);
STATIC_ASSERT(offsetof(struct HookContext, r9) == 72);
STATIC_ASSERT(offsetof(struct HookContext, r10) == 80);
STATIC_ASSERT(offsetof(struct HookContext, r11) == 88);
STATIC_ASSERT(offsetof(struct HookContext, r12) == 96);
STATIC_ASSERT(offsetof(struct HookContext, r13) == 104);
STATIC_ASSERT(offsetof(struct HookContext, r14) == 112);
STATIC_ASSERT(offsetof(struct HookContext, r15) == 120);
STATIC_ASSERT(offsetof(struct HookContext, mxcsr) == 128);
STATIC_ASSERT(offsetof(struct HookContext, _reserved) == 132);
STATIC_ASSERT(offsetof(struct HookContext, xmm) == 136);
STATIC_ASSERT(sizeof(((struct HookContext *)0)->xmm) == 16 * 16);
/* The stub reads the redirect slot at this fixed displacement. */
STATIC_ASSERT(offsetof(struct HookContext, redirect_rip) == 392);

#define ARCH_NAME "x86_64"
#define REDIRECT_OFFSET offsetof(struct HookContext, redirect_rip)

#elif defined(_M_IX86)

STATIC_ASSERT(sizeof(struct HookContext) == 176);

STATIC_ASSERT(offsetof(struct HookContext, eflags) == 0);
STATIC_ASSERT(offsetof(struct HookContext, edi) == 4);
STATIC_ASSERT(offsetof(struct HookContext, esi) == 8);
STATIC_ASSERT(offsetof(struct HookContext, ebp) == 12);
STATIC_ASSERT(offsetof(struct HookContext, esp) == 16);
STATIC_ASSERT(offsetof(struct HookContext, ebx) == 20);
STATIC_ASSERT(offsetof(struct HookContext, edx) == 24);
STATIC_ASSERT(offsetof(struct HookContext, ecx) == 28);
STATIC_ASSERT(offsetof(struct HookContext, eax) == 32);
STATIC_ASSERT(offsetof(struct HookContext, mxcsr) == 36);
STATIC_ASSERT(offsetof(struct HookContext, xmm) == 40);
STATIC_ASSERT(sizeof(((struct HookContext *)0)->xmm) == 8 * 16);
/* Must stay 168: the x86 stub hard-codes that displacement. */
STATIC_ASSERT(offsetof(struct HookContext, redirect_eip) == 168);

#define ARCH_NAME "x86"
#define REDIRECT_OFFSET offsetof(struct HookContext, redirect_eip)

#endif

/* ------------------------------------------------- calling conventions --- */

/*
 * The stub calls the handler as __cdecl and pops the argument itself. Declaring
 * this __stdcall used to compile here and then unbalance the stack on x86, so
 * pin it: assigning a plain (default-convention) function is the check.
 */
static void conformance_handler(struct HookContext *context)
{
    (void)context;
}

static MidHookHandler g_handler_convention_check = conformance_handler;

/* Same for the watchdog callback: a plain C function must be assignable. */
static void conformance_tamper(uint64_t guard_id, const uint8_t *target,
                               const uint8_t *expected, const uint8_t *found,
                               uintptr_t len, int32_t restored, void *user)
{
    (void)guard_id; (void)target; (void)expected; (void)found;
    (void)len; (void)restored; (void)user;
}

static DetoursTamperCallback g_tamper_convention_check = conformance_tamper;

/* ---------------------------------------------------- pointer widths --- */

STATIC_ASSERT(sizeof(uintptr_t) == sizeof(void *));
STATIC_ASSERT(sizeof(uintptr_t) == sizeof(size_t));

int main(void)
{
    /* Referencing these keeps /W4 quiet and proves they were really emitted. */
    if (!g_handler_convention_check || !g_tamper_convention_check) {
        printf("FAILED: a callback typedef resolved to a null function\n");
        return 1;
    }

    printf("ABI conformance (%s), verified at compile time:\n", ARCH_NAME);
    printf("  sizeof(Xmm)                = %u, alignment %u\n",
           (unsigned)sizeof(struct Xmm), (unsigned)ALIGNOF_XMM);
    printf("  sizeof(HookContext)        = %u, alignment %u\n",
           (unsigned)sizeof(struct HookContext), (unsigned)ALIGNOF_HOOK_CONTEXT);
    printf("  offsetof(xmm)              = %u\n",
           (unsigned)offsetof(struct HookContext, xmm));
    printf("  offsetof(redirect slot)    = %u\n", (unsigned)REDIRECT_OFFSET);
    printf("  MidHookHandler             = default (__cdecl) convention\n");
    printf("  DetoursTamperCallback      = default (__cdecl) convention\n");
    printf("\nA mismatch here would have failed the build, not this run.\n");
    printf("OK\n");
    return 0;
}
