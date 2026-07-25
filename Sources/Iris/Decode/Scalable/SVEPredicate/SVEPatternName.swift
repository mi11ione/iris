// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// The SVE predicate-count `pattern` field (5-bit) → llvm-mc text mapping.
// All 32 raw values are valid encodings (none UNDEFINED); the 15 unnamed
// values 14..28 render as hash-prefixed decimal. Shared by PTRUE/PTRUES
// and the whole element-count family (CNTB/INCB/…). Empirically pinned
// against llvm-mc over all 32 values × every pattern-bearing instruction.

/// llvm-mc canonical text for a 5-bit SVE predicate `pattern` value.
enum SVEPatternName {
    /// The rendered keyword for `raw` (0..31): `pow2`, `vl1`..`vl8`, `vl16`,
    /// `vl32`, `vl64`, `vl128`, `vl256`, `mul4`, `mul3`, `all`, or `#N` for
    /// the unnamed values 14..28.
    @_effects(readonly)
    static func text(_ raw: UInt8) -> String {
        switch raw & 0b11111 {
        case 0: "pow2"
        case 1: "vl1"
        case 2: "vl2"
        case 3: "vl3"
        case 4: "vl4"
        case 5: "vl5"
        case 6: "vl6"
        case 7: "vl7"
        case 8: "vl8"
        case 9: "vl16"
        case 10: "vl32"
        case 11: "vl64"
        case 12: "vl128"
        case 13: "vl256"
        case 29: "mul4"
        case 30: "mul3"
        case 31: "all"
        default: "#\(raw & 0b11111)" // 14..28 — unnamed, hash-decimal
        }
    }

    /// Whether `raw` is the `all` (31) pattern — the assembler default,
    /// elided when it would be the trailing operand.
    @inline(__always)
    @_effects(readonly)
    static func isAll(_ raw: UInt8) -> Bool {
        raw & 0b11111 == 31
    }
}
