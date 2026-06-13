// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// CLI fixture source for the referenced-data annotation. Compiled by
// Scripts/build-cli-fixtures.sh into bin/strings-arm64. The artifact is
// our own compiled code (never an Apple-owned binary) and is
// redistributable.
//
// The point of this fixture is the address-formation idioms the listing
// annotates:
//   - an adrp+add pair forming a __cstring pointer (the format string and
//     the "world" argument) -> `; "the string"`
//   - char comparisons whose immediate is printable ASCII -> `; 'c'`
//   - a bl through a __stubs entry to an imported function (_printf)
// so the golden carries a real referencedString / referencedSymbol /
// charLiteral example next to the synthetic /tmp demonstrations.
//
// Expected shape (noinline pins the call graph at -O1):
//   _greet   , printf("hello, %s!\n", "world"): two __cstring adrp+add
//               idioms, then a bl to the _printf stub
//   _classify, three printable-ASCII char comparisons ('A', 'z', ' ')
//   _main    , calls _greet then _classify

#include <stdio.h>

__attribute__((noinline)) void greet(void) {
    printf("hello, %s!\n", "world");
}

__attribute__((noinline)) int classify(int c) {
    if (c == 'A') {
        return 1;
    }
    if (c == 'z') {
        return 2;
    }
    if (c == ' ') {
        return 3;
    }
    return 0;
}

int main(int argc, char **argv) {
    (void)argv;
    greet();
    return classify(argc);
}
