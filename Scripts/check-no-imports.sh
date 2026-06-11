#!/bin/sh
# Copyright (c) 2026 Roman Zhuzhgov
# Licensed under the Apache License, Version 2.0
#
# Zero-imports gate: the Iris library target carries ZERO import
# statements — not even Foundation. Fails listing every offender.

set -u

root="$(cd "$(dirname "$0")/.." && pwd)"
library="$root/Sources/Iris"

offenders="$(grep -rn '^[[:space:]]*\(@[A-Za-z_()[:alnum:]]*[[:space:]]\{1,\}\)*import[[:space:]]' "$library" --include='*.swift' || true)"

if [ -n "$offenders" ]; then
    echo "check-no-imports: FAIL — import statements found in Sources/Iris:" >&2
    echo "$offenders" >&2
    exit 1
fi

echo "check-no-imports: PASS — Sources/Iris contains zero import statements"
