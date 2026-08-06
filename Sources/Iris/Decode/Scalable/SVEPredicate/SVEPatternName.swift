// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// llvm-mc canonical text for a 5-bit SVE predicate `pattern` value.
enum SVEPatternName {
    /// The rendered keyword for `raw` (0..31).
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
        default: "#\(raw & 0b11111)"
        }
    }

    /// Whether `raw` is the `all` (31) pattern.
    @inline(__always)
    @_effects(readonly)
    static func isAll(_ raw: UInt8) -> Bool {
        raw & 0b11111 == 31
    }
}
