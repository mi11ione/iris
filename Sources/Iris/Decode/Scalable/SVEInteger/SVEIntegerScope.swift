// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Whether `encoding` is an SVE/SVE2 integer instruction owned by family
/// SVE-integer. Safe to call on any 32-bit word (it re-checks `op0` itself). Out-of-
/// scope op0=2 words — predicate/count/index, floating-point,
/// permute/memory/crypto, SME2 counter forms — return `false`.
@inline(__always)
@_effects(readonly)
public func isSVEIntegerEncoding(_ encoding: UInt32) -> Bool {
    guard (encoding >> 25) & 0xF == 0b0010 else { return false }
    switch (encoding >> 24) & 0xFF {
    case 0x24: return true
    case 0x44: return isSVE2IntegerLowInScope(encoding)
    case 0x45: return isSVE2IntegerHighInScope(encoding)
    case 0x04: return isSVEIntegerComputeInScope(encoding)
    case 0x25: return isSVEIntegerImmediateInScope(encoding)
    case 0x05: return isSVEIntegerMoveInScope(encoding)
    default: return false
    }
}

/// 0x44 region (SVE2 integer.
@inline(__always)
@_effects(readonly)
func isSVE2IntegerLowInScope(_ e: UInt32) -> Bool {
    (e & 0xFF20_E000) != 0x4400_E000
}

/// 0x45 region (SVE2 integer.
@inline(__always)
@_effects(readonly)
func isSVE2IntegerHighInScope(_ e: UInt32) -> Bool {
    let crypto = (e >> 21) & 1 == 1 && (e >> 13) & 1 == 1 && (e >> 15) & 1 == 1
        && ((e >> 22) & 1 == 1 || (e >> 14) & 1 == 1 || (e >> 12) & 1 == 1 || (e >> 11) & 1 == 1)
    return !crypto
}

/// 0x04 region (SVE/SVE2 integer compute.
@inline(__always)
@_effects(readonly)
func isSVEIntegerComputeInScope(_ e: UInt32) -> Bool {
    if (e >> 21) & 1 == 0 {
        let group = (e >> 13) & 0b111
        if (e >> 19) & 0b111 == 0b010, (e >> 17) & 0b11 == 0, group == 0b001 { return false }
        if group == 0b101, (e >> 19) & 1 == 1, (e >> 16) & 0b111 == 0b100 || (e >> 16) & 0b111 == 0b101 {
            return false
        }
        return true
    }
    let group = (e >> 12) & 0b1111
    if group == 0b0100 || group == 0b0101 || group == 0b1100 || group == 0b1110 || group == 0b1111 {
        return false
    }
    if group == 0b1011 { return false }
    return true
}

/// 0x25 region: the integer immediate forms SVE-integer owns, carved out of
/// the predicate/count bulk. SVE-FP's FDUP needs no carve-out — it sets bit 16
/// and the DUP-immediate term pins bits[21:16].
@inline(__always)
@_effects(readonly)
func isSVEIntegerImmediateInScope(_ e: UInt32) -> Bool {
    (e & 0xFF20_4000) == 0x2500_0000
        || (e & 0xFF38_C000) == 0x2520_C000
        || (e & 0xFF38_C000) == 0x2528_C000
        || (e & 0xFF38_8000) == 0x2530_8000
        || (e & 0xFF3F_C000) == 0x2538_C000
}

/// 0x05 region: the integer move/copy and bitwise-immediate forms SVE-integer
/// owns, carved out of the permute bulk. FCPY and DUPM need no term of their
/// own; both were verified dead over the predicate's entire input domain.
@inline(__always)
@_effects(readonly)
func isSVEIntegerMoveInScope(_ e: UInt32) -> Bool {
    (e & 0xFF3F_FC00) == 0x0520_3800
        || (e & 0xFF20_FC00) == 0x0520_2000
        || (e & 0xFF3F_E000) == 0x0528_A000
        || (e & 0xFF3F_E000) == 0x0520_8000
        || (e & 0xFF30_8000) == 0x0510_0000
        || (e & 0xFF3C_0000) == 0x0500_0000
}
