// Copyright (c) 2026 NeoHook Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

/*
 * NeoHook C++ example: signature inference.
 *
 * Infers the arguments and return type of kernel32!MulDiv (int MulDiv(int, int,
 * int)) and of a function in this program from their machine code, and prints
 * what the analysis found.
 *
 * Expected output: the two signatures, ending in
 *   OK
 */

#include <cstdio>
#include <cstdlib>

#include "neohook.hpp"

static const char *kind_name(uint8_t kind)
{
    switch (kind) {
    case DETOURS_VALUE_KIND_INT8: return "int8";
    case DETOURS_VALUE_KIND_INT16: return "int16";
    case DETOURS_VALUE_KIND_INT32: return "int32";
    case DETOURS_VALUE_KIND_INT64: return "int64";
    case DETOURS_VALUE_KIND_POINTER: return "pointer";
    case DETOURS_VALUE_KIND_FLOAT: return "float";
    case DETOURS_VALUE_KIND_DOUBLE: return "double";
    default: return "unknown";
    }
}

static void print(const char *label, const DetoursSignature &sig)
{
    std::printf("%s: %u argument(s), returns %s\n", label, sig.arg_count,
                sig.has_return ? kind_name(sig.returns) : "void");
    for (uint32_t i = 0; i < sig.arg_count; ++i) {
        const DetoursArgGuess &arg = sig.args[i];
        std::printf("  %u: %-7s %s\n", i, kind_name(arg.kind), arg.on_stack ? "(stack)" : arg.register_name);
    }
}

// Reads through its first argument, so the analysis sees it as a pointer.
extern "C" __declspec(noinline) int read_first(const int *values, int index)
{
    return values[index];
}

static void check(bool ok, const char *what)
{
    if (!ok) {
        std::printf("FAIL: %s\n", what);
        std::exit(1);
    }
}

int main()
{
    auto muldiv = neohook::infer_signature("kernel32.dll", "MulDiv");
    check(muldiv.has_value(), "MulDiv could not be analysed");
    print("MulDiv", *muldiv);
    check(muldiv->arg_count == 3, "MulDiv takes three arguments");
    check(muldiv->has_return && muldiv->returns == DETOURS_VALUE_KIND_INT32, "MulDiv returns an int");

    auto own = neohook::infer_signature(reinterpret_cast<const void *>(&read_first));
    check(own.has_value(), "read_first could not be analysed");
    print("read_first", *own);
    check(own->arg_count == 2, "read_first takes two arguments");
    check(own->args[0].kind == DETOURS_VALUE_KIND_POINTER, "the first argument is a pointer");

    check(!neohook::infer_signature(nullptr).has_value(), "a null pointer is rejected");

    std::printf("OK\n");
    return 0;
}
