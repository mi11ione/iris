// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// The precise encoding predicate that defines SVE-predicate's scope (SVE
// predicate & control). SVE-predicate spans two of the scalable core's coarse `SVEDecoder`
// regions — the 0x25 "predicate" region (init/test, logical, break, FFR,
// count, WHILE/CTERM) and a carve-out of the 0x04 "integer" region
// (element-count, stack-frame adjust, INDEX, MOVPRFX). Neither the scalable core region
// is a clean family boundary (both interleave SVE-integer/SVE-FP content), so
// ownership is a bit predicate, finer than the region classifier. One
// predicate, three consumers: the SVEDecoder gate, the validator's
// exhaustiveSkip, and the real-corpus harvester's isInScope.

/// Whether `encoding` is an SVE predicate-and-control instruction owned by
/// SVE-predicate (routes to one of the encoding groups G1–G9 the decoder
/// fills). Assumes nothing about `op0`: it checks the full architectural
/// position, so it is safe to call on any 32-bit word. Out-of-scope op0=2
/// words (integer/FP/permute/memory, and the SME2 predicate-as-counter
/// forms that share SVE-predicate's mnemonics) return `false`.
@inline(__always)
@_effects(readonly)
public func isSVEPredicateControlEncoding(_ encoding: UInt32) -> Bool {
    // op0 = bits[28:25] must be 0b0010 (the SVE tier).
    guard (encoding >> 25) & 0xF == 0b0010 else { return false }
    let topByte = (encoding >> 24) & 0xFF
    if topByte == 0x25 { return isPredicateRegionInScope(encoding) }
    if topByte == 0x04 { return isIntegerRegionInScope(encoding) }
    return false
}

/// In-scope test for the 0x25 region (bit24=1 within the SVE tier): G1–G6.
@inline(__always)
@_effects(readonly)
func isPredicateRegionInScope(_ e: UInt32) -> Bool {
    let b21 = (e >> 21) & 1
    let b15_14 = (e >> 14) & 0b11
    if b21 == 0 {
        switch b15_14 {
        case 0b01:
            // b20=0 → predicate-logical (G2); b20=1 → BRKA/BRKB/BRKN (G3).
            return true
        case 0b11:
            let b20 = (e >> 20) & 1
            if b20 == 0 { return true } // BRKPA/BRKPB (G3)
            let b19 = (e >> 19) & 1
            if b19 == 0 { return true } // PTEST (G1)
            // b21:19 == 011 "predicate misc", discriminate by bits[15:10].
            let b15_10 = (e >> 10) & 0b111111
            if b15_10 == 0b111000 || b15_10 == 0b111001 { return true } // PTRUE(S)/PFALSE (G1)
            if b15_10 == 0b111100 { return true } // RDFFR/RDFFRS (G4)
            if (e >> 11) & 0b11111 == 0b11000 { return true } // PFIRST/PNEXT (G3)
            return false
        default:
            // b15:14 ∈ {00,10} → integer-compare-to-predicate (SVE-integer, OUT).
            return false
        }
    }
    // b21 == 1.
    switch b15_14 {
    case 0b00:
        let b13 = (e >> 13) & 1
        if b13 == 0 { return true } // WHILE<cc> (G6)
        let b12_10 = (e >> 10) & 0b111
        if b12_10 == 0b000 { return (e >> 23) & 1 == 1 } // CTERM (G6); requires b23=1
        if b12_10 == 0b100 { return true } // WHILERW/WHILEWR (G6)
        return false
    case 0b10:
        // CNTP (G5), INCP/DECP/SQ/UQ count (G5), WRFFR/SETFFR (G4).
        if (e >> 20) & 1 != 0 { return false }
        let b19 = (e >> 19) & 1
        if b19 == 0 {
            if (e >> 9) & 1 == 1 { return false } // CNTP-as-counter (SME2, OUT)
            return (e >> 16) & 0b111 == 0b000 // CNTP; 001/010 = FIRSTP/LASTP (OUT)
        }
        // b19 == 1: predicate-count / FFR-write sub-region.
        if (e >> 13) & 1 != 0 { return false }
        let b12_11 = (e >> 11) & 0b11
        return b12_11 == 0b00 || b12_11 == 0b01 || b12_11 == 0b10
    default:
        // b15:14 ∈ {01,11}: PSEL/PEXT/WHILE-counter and wide-imm/FP-imm (SVE-integer/SVE-FP), OUT.
        return false
    }
}

/// In-scope test for the 0x04 region (the SVE-integer region the scalable core routes to
/// SVE-integer): the SVE-predicate carve-out — element count, stack-frame adjust, INDEX,
/// MOVPRFX (G7–G9). Everything else at 0x04 is SVE-integer/SVE-FP (OUT).
@inline(__always)
@_effects(readonly)
func isIntegerRegionInScope(_ e: UInt32) -> Bool {
    if (e >> 21) & 1 == 0 {
        // MOVPRFX predicated: b21:19=010, b18:17=00, b15:13=001.
        return (e >> 19) & 0b111 == 0b010
            && (e >> 17) & 0b11 == 0b00
            && (e >> 13) & 0b111 == 0b001
    }
    // b21 == 1.
    let b15_12 = (e >> 12) & 0b1111
    switch b15_12 {
    case 0b0100: return true // INDEX (G8)
    case 0b0101: return true // ADDVL/ADDPL/RDVL (+ streaming twins) (G7)
    case 0b1100: return true // element-count VECTOR (G7)
    case 0b1110: return true // CNT/INC/DEC scalar (G7)
    case 0b1111: return true // SQINC/UQINC/SQDEC/UQDEC scalar (G7)
    default:
        // MOVPRFX unpredicated: b15:11=10111, b10=1 (G9).
        return (e >> 11) & 0b11111 == 0b10111 && (e >> 10) & 1 == 1
    }
}
