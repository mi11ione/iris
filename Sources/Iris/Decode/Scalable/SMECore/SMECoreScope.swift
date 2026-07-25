// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// the SME-core scope predicate. The single predicate with
// three consumers (the `SMEDecoder` gate, the validator's `exhaustiveSkip`,
// the harvester's `isInScope`), so decode / validate / harvest cannot drift
// from what SME-core owns.
//
// The SME region (op0=0b0000, bit31=1) is shared with SME2 (ZT0 /
// LUTI): they interleave inside the coarse encoding cells (bits[31:29] | bit24
// | bit23), but the partition is bit-separable (tblgen inventory).
// The pure-core cells — 100|1|1 (outer products) and 111|0|0 / 111|0|1 /
// 111|1|1 (LD1/ST1 tiles) — are claimed whole, so their holes are diffed
// against llvm-mc (decoder UNDEFINED ⇔ oracle invalid-encoding). The LDR/STR-ZA
// cell (111|1|0) is claimed whole minus the two ZT0 fill/spill patterns.
// The residue-bearing outer-product cells (100|0|1, 101|0|1, 101|1|1) and the
// MOVA/ZERO/ADDHA/ADDVA cells (110|0|0, 110|0|1) are claimed at exact
// core-encoding granularity, so the dense SME2 residue (F8 outer products,
// MOP4, 2-way integer MOPA, multi-vector MOVA/MOVAZ, LUTI) is excluded by
// construction — a residue word simply matches no core row. Everything else
// (100|x|0, 101|x|0, 110|1|x) is SME2's. A boundary mis-draw is falsifiable by
// the exhaustive sweep (our UNDEFINED vs an llvm rendering, or vice versa,
// gates loudly).

/// True iff `encoding` is an SME-core instruction owned by SME-core —
/// streaming-mode outer products, ZA tile/array load-store, MOVA, ZERO, and
/// horizontal/vertical accumulate. The complement inside the SME region
/// (SME2 multi-vector, ZT0, LUTI) is SME2's.
@inline(__always)
@_effects(readonly)
public func isSMECoreEncoding(_ encoding: UInt32) -> Bool {
    guard isSMEEncoding(encoding) else { return false } // op0=0b0000 ∧ bit31=1
    let bit24 = encoding & 0x0100_0000 != 0
    let bit23 = encoding & 0x0080_0000 != 0
    switch encoding & 0xE000_0000 {
    case 0x8000_0000: // 100 — FP outer products
        guard bit23 else { return false } // 100|x|0 → SME2
        // 100|1|1 is pure core (widening + F16F16/B16B16); claim whole cell.
        // 100|0|1 shares the cell with F8 outer products / MOP4 f64.
        return bit24 ? true : smeIsCoreOuterProduct(encoding)
    case 0xA000_0000: // 101 — integer outer products
        guard bit23 else { return false } // 101|x|0 → SME2
        return smeIsCoreOuterProduct(encoding) // both cells share SME2 residue
    case 0xC000_0000: // 110 — MOVA / ZERO / ADDHA / ADDVA (+ dense SME2)
        guard !bit24 else { return false } // 110|1|x multi-vector arithmetic → SME2
        return smeIsCoreMoveZero(encoding)
    default: // 111 — ZA load/store; the guard fixes bit31, so this is the
        // only remaining value of bits[31:29] (100/101/110 are above).
        // 111|1|0 = LDR/STR ZA (claim minus the two ZT0 fill/spill patterns);
        // 111|0|0, 111|0|1, 111|1|1 = LD1/ST1 tiles (pure core, holes claimed).
        if bit24, !bit23 { return !smeIsZT0FillSpill(encoding) }
        return true
    }
}

/// True iff `encoding` matches a SME-core core outer-product encoding
/// (FMOPA/FMOPS, BFMOPA/BFMOPS, S/U/SU/US-MOPA/MOPS, BMOPA/BMOPS) in the
/// cells that need a row-by-row claim; a residue word (2-way integer MOPA
/// with bit3=1, F8 sources, MOP4) matches none. Mirrors
/// ``SMEOuterProductDecode``'s dispatch for the `.s`- and `.d`-tile rows.
/// The `.h`-tile rows (the F16F16 / B16B16 quartet) are deliberately absent:
/// every one of them sits at bit24=1 in cell 100|1|1, which is claimed whole,
/// so they are already in scope and never reach this test.
@inline(__always)
@_effects(readonly)
func smeIsCoreOuterProduct(_ e: UInt32) -> Bool {
    switch e & 0xFFE0_001C { // .s tiles (ZAda = bits[1:0])
    case 0x8080_0000, 0x8080_0010, 0x8080_0008, 0x8080_0018, // fmopa/s bmopa/s
         0x8180_0000, 0x8180_0010, // bfmopa/s (widening bf16→f32)
         0x81A0_0000, 0x81A0_0010, // fmopa/s (widening f16→f32)
         0xA080_0000, 0xA080_0010, 0xA0A0_0000, 0xA0A0_0010, // smopa/s sumopa/s
         0xA180_0000, 0xA180_0010, 0xA1A0_0000, 0xA1A0_0010: // usmopa/s umopa/s
        return true
    default:
        break
    }
    switch e & 0xFFE0_0018 { // .d tiles (ZAda = bits[2:0])
    case 0x80C0_0000, 0x80C0_0010, // fmopa/s (f64f64)
         0xA0C0_0000, 0xA0C0_0010, 0xA0E0_0000, 0xA0E0_0010, // smopa/s sumopa/s
         0xA1C0_0000, 0xA1C0_0010, 0xA1E0_0000, 0xA1E0_0010: // usmopa/s umopa/s
        return true
    default:
        return false
    }
}

/// True iff `encoding` matches a SME-core core MOVA (insert or extract), ZERO, or
/// ADDHA/ADDVA block. Mirrors ``SMEMoveDecode``'s dispatch. The multi-vector
/// MOVA/MOVAZ (bit9=1 or a set byte2 opcode bit), ZERO_MXI, MOVT, and LUTI
/// residue in these cells match no block.
@inline(__always)
@_effects(readonly)
func smeIsCoreMoveZero(_ e: UInt32) -> Bool {
    switch e & 0xFFFF_0010 { // MOVA insert (vector → tile), V (bit15) free
    case 0xC000_0000, 0xC040_0000, 0xC080_0000, 0xC0C0_0000, 0xC0C1_0000:
        return true
    default:
        break
    }
    switch e & 0xFFFF_0200 { // MOVA extract (tile → vector), V free, bit9=0
    case 0xC002_0000, 0xC042_0000, 0xC082_0000, 0xC0C2_0000, 0xC0C3_0000:
        return true
    default:
        break
    }
    if e & 0xFFFF_FF00 == 0xC008_0000 { return true } // ZERO (imm8)
    let addS = e & 0xFFFF_001C
    if addS == 0xC090_0000 || addS == 0xC091_0000 { return true } // addha/addva .s
    let addD = e & 0xFFFF_0018
    if addD == 0xC0D0_0000 || addD == 0xC0D1_0000 { return true } // addha/addva .d
    return false
}

/// True iff `encoding` is an SME2 `ZT0` fill (`LDR ZT0`) or spill (`STR ZT0`)
/// — the two patterns inside the LDR/STR-ZA cell (111|1|0) that belong to
/// SME2, distinguished from `LDR`/`STR ZA` by `bits[20:16]=0b11111 ∧ bit15=1`.
@inline(__always)
@_effects(readonly)
func smeIsZT0FillSpill(_ e: UInt32) -> Bool {
    e & 0xFFFF_FC1F == 0xE11F_8000 || e & 0xFFFF_FC1F == 0xE13F_8000
}
