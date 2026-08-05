#!/bin/sh
# Copyright (c) 2026 Roman Zhuzhgov
# Licensed under the Apache License, Version 2.0
#
# Homebrew formula bump: rewrites a tap formula in place to point at a
# release's tarballs, taking every checksum from that release's own
# `checksums.txt` rather than recomputing one.
#
#     Scripts/bump-formula.sh <formula.rb> <version> <checksums.txt>
#
# Exists because the tap is a SECOND repository: `release.yml` publishes
# binaries to this repo's Releases, and nothing about that act updates
# mi11ione/homebrew-tap. Bumped by hand, the tap drifts silently — the
# formula keeps installing the previous version, which is worse than a
# failed install because it looks like it worked. So the release pipeline
# calls this, and this fails loudly rather than write a formula it cannot
# fully account for.
#
# Rewrites exactly three things, structurally:
#   - the `version "…"` line (whose old value is how the old version is
#     recognized everywhere else — the formula is the source of truth for
#     what it currently points at, not an argument)
#   - each `url "…"` line, old version -> new
#   - the `sha256 "…"` line FOLLOWING each url, set to the checksum
#     `checksums.txt` lists for that url's basename
#
# Pairing each sha256 with its preceding url is what keeps the per-platform
# arms honest: on_intel/on_arm differ only by a filename, and a bump that
# transposed two checksums would install a working binary on one arch and
# fail verification on the other, visible only to whoever runs the arch
# that CI doesn't.
#
# Refuses to write a partial bump. It is an error if a url has no matching
# entry in checksums.txt, if a url is not followed by a sha256, or if the
# result still mentions the superseded version. On any of those the formula
# is left untouched, exactly as it was.
#
# Idempotent: re-running for a version already written is a no-op that
# still validates. Prints a unified diff of what it changed.

set -u

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <formula.rb> <version> <checksums.txt>" >&2
    exit 2
fi

FORMULA="$1"
VERSION="$2"
CHECKSUMS="$3"

for f in "$FORMULA" "$CHECKSUMS"; do
    if [ ! -f "$f" ]; then
        echo "bump-formula: no such file: $f" >&2
        exit 1
    fi
done

case "$VERSION" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *)
        echo "bump-formula: version '$VERSION' is not semver" >&2
        exit 1
        ;;
esac

TMP="${TMPDIR:-/tmp}/bump-formula.$$"
trap 'rm -f "$TMP"' EXIT INT TERM

# Two-file awk: checksums.txt builds the basename -> sha map, then the
# formula is rewritten against it. Errors accumulate and report together
# at END, so one run tells you everything that is wrong.
if ! awk -v version="$VERSION" -v sumsfile="$CHECKSUMS" '
FNR == NR {
    if (NF >= 2) {
        file = $2
        sub(/^\*/, "", file)          # sha256sum --binary marks with *
        sums[file] = $1
    }
    next
}
{ line = $0 }

# The formula names the version it currently points at; every other
# rewrite keys off that, so a missing or contradictory version line is
# fatal rather than guessed around.
line ~ /^[[:space:]]*version[[:space:]]+"/ {
    if (match(line, /"[^"]*"/)) {
        found = substr(line, RSTART + 1, RLENGTH - 2)
        if (seen_version && old != found)
            errs = errs "contradictory version lines: " old " and " found "\n"
        old = found
        oldre = old
        gsub(/[.\\^$*+?()[\]{}|]/, "\\\\&", oldre)   # a version is not a regex
        seen_version++
        sub(/"[^"]*"/, "\"" version "\"", line)
    }
    print line
    next
}
line ~ /^[[:space:]]*url[[:space:]]+"/ {
    if (!seen_version) {
        errs = errs "url at line " FNR " precedes the version line\n"
        urls++
        print line
        next
    }
    if (pending != "")
        errs = errs "url at line " FNR " follows a url with no sha256\n"
    gsub(oldre, version, line)
    if (match(line, /"[^"]*"/)) {
        n = split(substr(line, RSTART + 1, RLENGTH - 2), parts, "/")
        base = parts[n]
        if (base in sums) {
            pending = sums[base]
        } else {
            errs = errs "no checksum for " base " in " sumsfile "\n"
            pending = ""
        }
    }
    urls++
    print line
    next
}
line ~ /^[[:space:]]*sha256[[:space:]]+"/ {
    if (pending == "") {
        errs = errs "sha256 at line " FNR " has no url to bind to\n"
        print line
        next
    }
    if (pending !~ /^[0-9a-f]{64}$/)
        errs = errs "not a sha256 for url above line " FNR ": " pending "\n"
    sub(/"[^"]*"/, "\"" pending "\"", line)
    pending = ""
    shas++
    print line
    next
}
{ print line }

END {
    if (seen_version != 1)
        errs = errs "expected exactly 1 version line, found " seen_version + 0 "\n"
    if (pending != "")
        errs = errs "the last url is not followed by a sha256\n"
    if (urls == 0)
        errs = errs "formula has no url lines\n"
    else if (urls != shas)
        errs = errs urls " urls but " shas + 0 " rewritten sha256 lines\n"
    if (errs != "") {
        printf "%s", errs > "/dev/stderr"
        exit 1
    }
    printf "bump-formula: %s -> %s, %d urls\n", old, version, urls > "/dev/stderr"
}
' "$CHECKSUMS" "$FORMULA" > "$TMP"; then
    echo "bump-formula: refusing to write a partial bump; $FORMULA untouched" >&2
    exit 1
fi

if [ ! -s "$TMP" ]; then
    echo "bump-formula: produced an empty formula; $FORMULA untouched" >&2
    exit 1
fi

if cmp -s "$TMP" "$FORMULA"; then
    echo "bump-formula: $FORMULA already at $VERSION, nothing to do"
    exit 0
fi

diff -u "$FORMULA" "$TMP" | sed 's/^/    /'
cat "$TMP" > "$FORMULA"
echo "bump-formula: wrote $FORMULA"
