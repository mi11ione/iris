#!/bin/sh
# Copyright (c) 2026 Roman Zhuzhgov
# Licensed under the Apache License, Version 2.0
#
# Coverage gate: 100% unit-test coverage on the library targets (Iris,
# IrisValidation, IrisCLICore), per file, across ALL reported columns
# (region, function, line — the branch column carries no Swift
# instrumentation and reports `-`).
# Coverage prevents crashes and dead code; correctness is owned by the
# external oracles (`iris-parity`). The gate fails listing every file
# and column below 100%, and cross-checks that every library source
# file appears in the report so an uninstrumented file cannot slip
# through as silently green.
#
# The test suites cover themselves 100% too, but only with the env-gated
# system-binary smoke suite enabled (IRIS_CLI_SYSTEM_SMOKE=1), which needs
# host binaries CI cannot rely on — so Tests/ is not gated here.
#
# Coverage is measured on the `native` build system: the Swift Build engine
# inlines through `@_optimize(speed)` decoders hard enough to drop region
# counters for arms that provably execute, which reads as a phantom gap.
#
# Usage: Scripts/coverage-gate.sh [--skip-tests]
#   --skip-tests  reuse existing .build coverage data (CI runs tests
#                 separately; the default runs `swift test` here)

set -u

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root" || exit 2

skip_tests=0
[ "${1:-}" = "--skip-tests" ] && skip_tests=1

# Toolchains where Swift Build is the default still accept `--build-system
# native`; ones that predate the flag reject it, so probe once and reuse.
build_system=""
if swift build --build-system native --show-bin-path > /dev/null 2>&1; then
    build_system="--build-system native"
fi

if [ "$skip_tests" -eq 0 ]; then
    echo "coverage-gate: running swift test $build_system --no-parallel --enable-code-coverage"
    # Both flags are load-bearing for a reproducible report, not speed choices.
    # Counter updates are non-atomic by default, so a region executed only once
    # or twice can lose its increment and read back as an uncovered phantom;
    # `-instrprof-atomic-counter-update-all` removes that race. `--no-parallel`
    # keeps the run in one process — parallel workers write the same profraw
    # path and clobber each other's counters, which no atomicity can fix.
    # shellcheck disable=SC2086
    swift test $build_system --no-parallel --enable-code-coverage \
        -Xswiftc -Xllvm -Xswiftc -instrprof-atomic-counter-update-all || {
        echo "coverage-gate: FAIL — test run failed" >&2
        exit 1
    }
fi

# shellcheck disable=SC2086
bin_path="$(swift build $build_system --show-bin-path 2> /dev/null)" || exit 2
profdata="$bin_path/codecov/default.profdata"
if [ ! -f "$profdata" ]; then
    echo "coverage-gate: FAIL — no coverage data at $profdata (run swift test $build_system --enable-code-coverage)" >&2
    exit 1
fi

# The test executable: macOS bundles it, Linux emits a flat executable.
test_binary="$bin_path/irisPackageTests.xctest/Contents/MacOS/irisPackageTests"
if [ ! -f "$test_binary" ]; then
    test_binary="$bin_path/irisPackageTests.xctest"
fi
if [ ! -f "$test_binary" ]; then
    echo "coverage-gate: FAIL — test binary not found under $bin_path" >&2
    exit 1
fi

# llvm-cov must come from the Swift toolchain (profdata format match):
# xcrun on Darwin; on Linux, PATH or the directory of swiftc.
if command -v xcrun > /dev/null 2>&1; then
    llvm_cov="xcrun llvm-cov"
elif command -v llvm-cov > /dev/null 2>&1; then
    llvm_cov="llvm-cov"
else
    swiftc_path="$(command -v swiftc)" || {
        echo "coverage-gate: FAIL — neither xcrun nor llvm-cov nor swiftc found" >&2
        exit 1
    }
    swiftc_real="$(readlink -f "$swiftc_path" 2> /dev/null || echo "$swiftc_path")"
    llvm_cov="$(dirname "$swiftc_real")/llvm-cov"
    if [ ! -x "$llvm_cov" ]; then
        echo "coverage-gate: FAIL — llvm-cov not found next to swiftc at $llvm_cov" >&2
        exit 1
    fi
fi

report="$($llvm_cov report "$test_binary" -instr-profile "$profdata" -use-color=false 2> /dev/null)"
if [ -z "$report" ]; then
    echo "coverage-gate: FAIL — llvm-cov report produced no output (binary/profdata mismatch?)" >&2
    exit 1
fi

# Rows are emitted with paths relative to the working directory (the package
# root after the cd above), so library rows match the target directories.
# `Sources/Iris/` needs the trailing slash to not also swallow the siblings.
lib_row='^Sources/(Iris|IrisValidation|IrisCLICore)/.*\.swift$'
failures="$(printf '%s\n' "$report" | awk -v row="$lib_row" '
    $1 ~ row {
        for (i = 2; i <= NF; i++) {
            if ($i ~ /%$/ && $i != "100.00%") { print $0; next }
        }
    }
')"
seen_count="$(printf '%s\n' "$report" | awk -v row="$lib_row" '$1 ~ row { n++ } END { print n + 0 }')"

status=0
if [ -n "$failures" ]; then
    echo "coverage-gate: FAIL — files below 100% in at least one column:" >&2
    printf '%s\n' "$failures" >&2
    status=1
fi

# Census cross-check: every library source file must either appear in
# the report or be PROVEN declaration-only. llvm-cov emits no coverage
# mapping for a file with zero executable regions (pure enum/case
# declaration files — synthesized rawValue/Hashable members are not
# file-attributed), so absence alone is not a gap; but absence with
# executable declarations in the source would be a silently-green
# hole, and fails. The proof is token-level on comment-stripped
# source; doc text cannot satisfy it, and a token inside a string
# literal or block comment can only cause a loud FAIL, never a pass.
declaration_only=0
missing_with_code=""
files_list="/tmp/coverage-gate-files.$$"
seen_list="/tmp/coverage-gate-seen.$$"
missing_list="/tmp/coverage-gate-missing.$$"
find Sources/Iris Sources/IrisValidation Sources/IrisCLICore -name '*.swift' | sort > "$files_list"
printf '%s\n' "$report" | awk -v row="$lib_row" '$1 ~ row { print $1 }' | sort > "$seen_list"
# Line-wise read (not an unquoted $(comm ...) expansion) so a path
# containing whitespace cannot word-split; the file redirect keeps the
# loop in this shell so its variable updates survive (POSIX sh pipes
# run loops in a subshell).
comm -23 "$files_list" "$seen_list" > "$missing_list"
while IFS= read -r missing; do
    if sed 's@//.*@@' "$missing" | grep -qE '(^|[^[:alnum:]_])(func|init|var|subscript|deinit)([^[:alnum:]_]|$)'; then
        missing_with_code="$missing_with_code  missing from report despite executable declarations: $missing
"
    else
        declaration_only=$((declaration_only + 1))
    fi
done < "$missing_list"
rm -f "$files_list" "$seen_list" "$missing_list"
if [ -n "$missing_with_code" ]; then
    echo "coverage-gate: FAIL — files absent from the coverage report that are not declaration-only:" >&2
    printf '%s' "$missing_with_code" >&2
    status=1
fi

if [ "$status" -eq 0 ]; then
    echo "coverage-gate: PASS — all $seen_count instrumented library files at 100% across all columns ($declaration_only declaration-only files verified free of executable declarations)"
fi
exit "$status"
