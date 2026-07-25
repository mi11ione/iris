// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// The precise encoding predicate that defines SVE-FP's scope (SVE /
// SVE2 floating-point). The FP tier owns both 0x64/0x65 top bytes outright —
// every op0=2 instruction llvm-mc decodes there is floating-point (verified
// def-exhaustively against the tblgen catalogue: 478 defs, zero foreign
// classes) — plus four carve-out families that live at the integer top bytes
// 0x04/0x05/0x25 inside integer-looking encoding classes: FABS/FNEG (both
// `/M` and the SVE2p2 `/Z` forms), FTSSEL, FEXPA, FCPY, and FDUP. Each
// carve-out signature is the exact complement of the exclusion
// `isSVEIntegerEncoding` already applies (SVE-integer), so the two
// predicates partition their shared top bytes with no overlap and no gap
// beyond the architecturally-unallocated holes neither family claims.
// One predicate, three consumers: the SVEDecoder gate, the validator's
// exhaustiveSkip, and the real-corpus harvester's isInScope.

/// Whether `encoding` is an SVE/SVE2 floating-point instruction owned by
/// SVE-FP. Safe to call on any 32-bit word (it re-checks `op0`
/// itself). Out-of-scope op0=2 words — predicate/count/index, integer
/// , permute/memory/crypto, SME2 counter forms — return
/// `false`.
@inline(__always)
@_effects(readonly)
public func isSVEFloatingPointEncoding(_ encoding: UInt32) -> Bool {
    // op0 = bits[28:25] must be 0b0010 (the SVE tier).
    guard (encoding >> 25) & 0xF == 0b0010 else { return false }
    switch (encoding >> 24) & 0xFF {
    case 0x64, 0x65:
        return true // the whole FP region — every allocated encoding is SVE-FP's.
    case 0x04:
        // FABS/FNEG: predicated-unary group (bits[15:13]=101) with bit21=0,
        // bits[19:17]=110 — opc[18:16] ∈ {100, 101}, both `/M` (bit20=1) and
        // `/Z` (bit20=0). FTSSEL / FEXPA: the unpredicated bits[15:12]=1011
        // group at bit21=1, excluding SVE-predicate's unpredicated MOVPRFX
        // (bits[15:10]=101111): FTSSEL pins bits[15:10]=101100 with Zm free;
        // FEXPA pins bits[15:10]=101110 with bits[20:16]=00000.
        return (encoding & 0xFF2E_E000) == 0x040C_A000 // FABS/FNEG `/M` + `/Z`
            || (encoding & 0xFF20_FC00) == 0x0420_B000 // FTSSEL
            || (encoding & 0xFF3F_FC00) == 0x0420_B800 // FEXPA
    case 0x05:
        // FCPY (renders `fmov`): the bit15=1 half of the CPY-immediate region —
        // SVE-integer's `sve_int_dup_imm_pred` term pins bit15=0, so the two are
        // disjoint by that single bit.
        return (encoding & 0xFF30_E000) == 0x0510_C000
    case 0x25:
        // FDUP (renders `fmov`): the bit16=1 neighbor of SVE-integer's DUP-immediate
        // (`sve_int_dup_imm` pins bits[21:16]=111000; FDUP is 111001).
        return (encoding & 0xFF3F_E000) == 0x2539_C000
    default:
        return false // 0x24/0x44/0x45 integer; 0x84…0xE5 memory.
    }
}
