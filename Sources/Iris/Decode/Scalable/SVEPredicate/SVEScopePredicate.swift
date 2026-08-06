// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Whether `encoding` is an SVE predicate-and-control instruction owned by
/// SVE-predicate. Assumes nothing about `op0` — it checks the full
/// architectural position — so it is safe on any 32-bit word. Out-of-scope
/// op0=2 words, including the SME2 counter forms sharing these mnemonics,
/// return `false`.
@inline(__always)
@_effects(readonly)
public func isSVEPredicateControlEncoding(_ encoding: UInt32) -> Bool {
    guard (encoding >> 25) & 0xF == 0b0010 else { return false }
    let topByte = (encoding >> 24) & 0xFF
    if topByte == 0x25 { return isPredicateRegionInScope(encoding) }
    if topByte == 0x04 { return isIntegerRegionInScope(encoding) }
    return false
}

/// In-scope test for the 0x25 region (bit24=1 within the SVE tier).
@inline(__always)
@_effects(readonly)
func isPredicateRegionInScope(_ e: UInt32) -> Bool {
    let b21 = (e >> 21) & 1
    let b15_14 = (e >> 14) & 0b11
    if b21 == 0 {
        switch b15_14 {
        case 0b01:
            return true
        case 0b11:
            let b20 = (e >> 20) & 1
            if b20 == 0 { return true }
            let b19 = (e >> 19) & 1
            if b19 == 0 { return true }
            let b15_10 = (e >> 10) & 0b111111
            if b15_10 == 0b111000 || b15_10 == 0b111001 { return true }
            if b15_10 == 0b111100 { return true }
            if (e >> 11) & 0b11111 == 0b11000 { return true }
            return false
        default:
            return false
        }
    }
    switch b15_14 {
    case 0b00:
        let b13 = (e >> 13) & 1
        if b13 == 0 { return true }
        let b12_10 = (e >> 10) & 0b111
        if b12_10 == 0b000 { return (e >> 23) & 1 == 1 }
        if b12_10 == 0b100 { return true }
        return false
    case 0b10:
        if (e >> 20) & 1 != 0 { return false }
        let b19 = (e >> 19) & 1
        if b19 == 0 {
            if (e >> 9) & 1 == 1 { return false }
            return (e >> 16) & 0b111 == 0b000
        }
        if (e >> 13) & 1 != 0 { return false }
        let b12_11 = (e >> 11) & 0b11
        return b12_11 == 0b00 || b12_11 == 0b01 || b12_11 == 0b10
    default:
        return false
    }
}

/// In-scope test for the 0x04 region (the SVE-integer region the scalable core
/// routes to SVE-integer).
@inline(__always)
@_effects(readonly)
func isIntegerRegionInScope(_ e: UInt32) -> Bool {
    if (e >> 21) & 1 == 0 {
        return (e >> 19) & 0b111 == 0b010
            && (e >> 17) & 0b11 == 0b00
            && (e >> 13) & 0b111 == 0b001
    }
    let b15_12 = (e >> 12) & 0b1111
    switch b15_12 {
    case 0b0100: return true
    case 0b0101: return true
    case 0b1100: return true
    case 0b1110: return true
    case 0b1111: return true
    default:
        return (e >> 11) & 0b11111 == 0b10111 && (e >> 10) & 1 == 1
    }
}
