// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Shared 4-bit cond-field → ``ConditionCode`` helper used
// by every conditional DPR decoder (CondCompare, CondSelect). Mirrors the
// `Decode/DataProcessingImmediate/RegisterEncoding.swift` precedent of a
// dedicated file for cross-file module-internal helpers.

/// Map a 4-bit cond field (0..15) to the matching ``ConditionCode``. Uses
/// an exhaustive switch so the compiler never emits a fail-trap closure
/// (which would be unreachable and dent coverage). The default case
/// handles `0b1111` (NV) — the final value in the 4-bit space.
@inline(__always)
@_effects(readonly)
func condFromBits(_ bits: UInt8) -> ConditionCode {
    switch bits & 0xF {
    case 0: .eq
    case 1: .ne
    case 2: .cs
    case 3: .cc
    case 4: .mi
    case 5: .pl
    case 6: .vs
    case 7: .vc
    case 8: .hi
    case 9: .ls
    case 10: .ge
    case 11: .lt
    case 12: .gt
    case 13: .le
    case 14: .al
    default: .nv
    }
}
