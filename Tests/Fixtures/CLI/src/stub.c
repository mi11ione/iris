// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// CLI fixture source for stub symbolication. Compiled by
// Scripts/build-cli-fixtures.sh into bin/stub-arm64 and
// bin/stub-stripped. The artifacts are our own compiled code (never
// Apple-owned binaries) and are redistributable.
//
// The point of this fixture is a call to an external libc function, so
// the linker emits a __stubs entry that forwards through the indirect
// symbol table to the imported symbol. A branch to that stub must
// annotate `; symbol stub for: _strcoll` in the listing (matching
// otool/llvm-objdump) and carry `targetSymbol` in --json.
//
// Expected shape (noinline pins the call graph at -O1):
//   _compare — calls strcoll (an imported function -> __stubs entry)
//   _main    — calls _compare (an internal direct call, symbolicated)
// strcoll is chosen because it is a stable libc export that is not
// inlined or constant-folded.

#include <string.h>

__attribute__((noinline)) int compare(const char *a, const char *b) {
    return strcoll(a, b);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 0;
    }
    return compare(argv[0], argv[1]);
}
