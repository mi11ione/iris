// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Map a 4-bit cond field to its ``ConditionCode``, through an exhaustive
/// switch so the compiler emits no unreachable fail-trap.
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
