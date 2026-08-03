/*
 * NeoHook C example: PE introspection and target discovery.
 *
 * The C counterpart of `examples/introspect.rs` and `examples/pattern_scan.rs`.
 * Everything here is read-only - no hooks are installed. It walks the loaded
 * modules, the export and import tables of kernel32, resolves a function by name
 * and by ordinal, and finally locates that same function again purely by byte
 * signature.
 *
 * Every handle returned by an enumerate/scan API is owned by the caller and must
 * be released with the matching *_free function; the strings and addresses it
 * hands out stay valid only until then.
 *
 * Expected output: a few dozen lines of module/export/import listings, ending in
 *   OK
 */

#include <windows.h>
#include <stdio.h>

#include "neohook.h"

#define MAX_LISTED 8

static int g_failures = 0;

#define CHECK(cond, msg)                   \
    do {                                   \
        if (!(cond)) {                     \
            printf("  FAIL: %s\n", (msg)); \
            g_failures++;                  \
        }                                  \
    } while (0)

static void list_modules(void)
{
    void *handle = detours_enumerate_modules();
    uintptr_t count, i;

    printf("== loaded modules ==\n");
    if (!handle) {
        printf("  <enumeration failed>\n");
        g_failures++;
        return;
    }

    count = detours_modules_len(handle);
    for (i = 0; i < count && i < MAX_LISTED; ++i) {
        printf("  %-28s base=%p size=%u bytes\n",
               detours_modules_name(handle, i),
               detours_modules_base(handle, i),
               detours_modules_size(handle, i));
    }
    if (count > MAX_LISTED) {
        printf("  ... and %llu more\n", (unsigned long long)(count - MAX_LISTED));
    }

    CHECK(count > 0, "no modules enumerated");
    detours_modules_free(handle);
}

static void list_exports(HMODULE kernel32)
{
    void *handle = detours_enumerate_exports(kernel32);
    uintptr_t count, i, listed = 0;

    printf("\n== kernel32.dll exports ==\n");
    if (!handle) {
        printf("  <enumeration failed>\n");
        g_failures++;
        return;
    }

    count = detours_exports_len(handle);
    printf("  %llu total, first %d:\n", (unsigned long long)count, MAX_LISTED);
    for (i = 0; i < count && listed < MAX_LISTED; ++i, ++listed) {
        const char *name = detours_exports_name(handle, i);
        const char *forwarder = detours_exports_forwarder(handle, i);

        /* A forwarder has no local code; it names "OTHERDLL.Function" instead. */
        if (forwarder) {
            printf("    #%-6u %-34s -> %s\n", detours_exports_ordinal(handle, i),
                   name ? name : "<by ordinal>", forwarder);
        } else {
            printf("    #%-6u %-34s %p\n", detours_exports_ordinal(handle, i),
                   name ? name : "<by ordinal>",
                   (const void *)detours_exports_address(handle, i));
        }
    }

    CHECK(count > 0, "kernel32 exports nothing");
    detours_exports_free(handle);
}

static void list_imports(HMODULE self)
{
    void *handle = detours_enumerate_imports(self);
    uintptr_t count, i;

    printf("\n== this executable's imports ==\n");
    if (!handle) {
        printf("  <enumeration failed>\n");
        g_failures++;
        return;
    }

    count = detours_imports_len(handle);
    printf("  %llu total, first %d:\n", (unsigned long long)count, MAX_LISTED);
    for (i = 0; i < count && i < MAX_LISTED; ++i) {
        const char *name = detours_imports_name(handle, i);

        if (name) {
            printf("    %-24s :: %-30s -> %p\n", detours_imports_dll(handle, i), name,
                   (const void *)detours_imports_address(handle, i));
        } else {
            printf("    %-24s :: #%-29u -> %p\n", detours_imports_dll(handle, i),
                   detours_imports_ordinal(handle, i),
                   (const void *)detours_imports_address(handle, i));
        }
    }

    CHECK(count > 0, "this module imports nothing");
    detours_imports_free(handle);
}

/* Builds an IDA / x64dbg-style signature ("48 8B 05 ??") from live bytes. */
static void build_pattern(const uint8_t *code, size_t len, char *out, size_t out_size)
{
    size_t i, used = 0;

    out[0] = '\0';
    for (i = 0; i < len && used + 3 < out_size; ++i) {
        used += (size_t)sprintf_s(out + used, out_size - used, i ? " %02X" : "%02X", code[i]);
    }
}

int main(void)
{
    HMODULE kernel32, self;
    const uint8_t *by_name, *by_ordinal, *by_symbol, *found;
    char pattern[64];

    self = GetModuleHandleW(NULL);
    kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!self || !kernel32) {
        fprintf(stderr, "GetModuleHandleW failed\n");
        return 1;
    }

    list_modules();
    printf("\n  kernel32 entry point: %p\n", (void *)detours_get_entry_point(kernel32));

    list_exports(kernel32);
    list_imports(self);

    printf("\n== resolving a single function ==\n");

    by_name = detours_find_function("kernel32.dll", "GetTickCount");
    printf("  find_function(\"GetTickCount\")   = %p\n", (const void *)by_name);
    CHECK(by_name != NULL, "find_function could not resolve GetTickCount");

    /* dbghelp-backed: also finds non-exported symbols when PDBs are available. */
    by_symbol = detours_resolve_symbol("kernel32.dll", "GetTickCount");
    printf("  resolve_symbol(\"GetTickCount\")  = %p\n", (const void *)by_symbol);

    by_ordinal = detours_find_function_by_ordinal("kernel32.dll", 1);
    printf("  find_function_by_ordinal(#1)    = %p\n", (const void *)by_ordinal);

    printf("\n== finding the same function by signature ==\n");
    if (by_name) {
        /* Turn the first bytes of the resolved function into a signature, then
           search kernel32's executable sections for it. A real signature would
           come from a disassembler and use ?? for volatile operands. */
        build_pattern(by_name, 8, pattern, sizeof(pattern));
        printf("  pattern: %s\n", pattern);

        found = detours_scan_module(kernel32, pattern);
        printf("  scan_module        -> %p\n", (const void *)found);
        CHECK(found == by_name, "scan_module did not find the function it was built from");

        found = detours_scan_module_by_name("kernel32.dll", pattern);
        printf("  scan_module_by_name-> %p\n", (const void *)found);
        CHECK(found == by_name, "scan_module_by_name disagreed with scan_module");
    }

    if (g_failures) {
        printf("\nFAILED (%d check(s))\n", g_failures);
        return 1;
    }
    printf("\nOK\n");
    return 0;
}
