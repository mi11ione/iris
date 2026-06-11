// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// CLI fixture source with a documented structure (RULES: each fixture
// has a known structure). Compiled by Scripts/build-cli-fixtures.sh
// into bin/hello-arm64, bin/hello-arm64e, bin/hello-fat, and
// bin/hello-stripped. The artifacts are our own compiled code and are
// redistributable.
//
// Expected shape (noinline pins the call graph at -O1):
//   _add42  — leaf arithmetic (add #42)
//   _sum_to — a counted loop: cmp / b.cond conditional flow, flag writes
//   _helper — calls _add42 and _sum_to (bl symbolication targets)
//   _main   — calls _helper
// All four are external symbols with LC_FUNCTION_STARTS entries; the
// arm64e build adds pointer-authentication prologues (PAC census sites).

__attribute__((noinline)) int add42(int x) {
    return x + 42;
}

__attribute__((noinline)) int sum_to(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        s += i;
    }
    return s;
}

__attribute__((noinline)) int helper(int x) {
    return add42(x) + sum_to(x);
}

int main(int argc, char **argv) {
    (void)argv;
    return helper(argc);
}
