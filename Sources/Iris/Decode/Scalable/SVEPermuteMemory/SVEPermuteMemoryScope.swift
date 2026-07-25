// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// The precise encoding predicate that defines SVE-permute/memory's scope (SVE /
// SVE2 permute, memory, and crypto). SVE-permute/memory is the remainder of the op0=2 space
// after SVE-predicate (predicate/control), SVE-integer (integer), and SVE-FP (floating-point):
// - the entire memory region (bit31=1: top bytes 0x84/0x85/0xA4/0xA5/0xC4/
// 0xC5/0xE4/0xE5) — no sibling claims any word there;
// - the permute region at top byte 0x05, minus SVE-integer's DUP/CPY-move carve-out
// and SVE-FP's FCPY — composed as the exact complement of the three siblings
// at that shared byte, so soundness is structural, not sweep-dependent;
// - the SVE2p1 quadword-permute cluster at 0x44 (`sve2p1_permute_vec_elems_q`
// — TBLQ/UZPQ/ZIPQ), the exact complement of SVE-integer's exclusion there;
// - the crypto / LUT cluster at 0x45 (AES/SM4/RAX1/multi-vector-PMULL/LUTI),
// the exact complement of SVE-integer's crypto exclusion.
// One predicate, three consumers: the SVEDecoder gate, the validator's
// exhaustiveSkip, and the real-corpus harvester's isInScope.

/// Whether `encoding` is an SVE/SVE2 permute, memory, or crypto instruction
/// owned by SVE-permute/memory. Safe to call on any 32-bit word (it re-checks
/// `op0` itself). Out-of-scope op0=2 words — predicate/count/index,
/// integer, floating-point, SME2 counter forms — return
/// `false`.
@inline(__always)
@_effects(readonly)
public func isSVEPermuteMemoryCryptoEncoding(_ encoding: UInt32) -> Bool {
    // op0 = bits[28:25] must be 0b0010 (the SVE tier).
    guard (encoding >> 25) & 0xF == 0b0010 else { return false }
    // The whole memory region (bit31=1) is SVE-permute/memory's; no sibling claims it.
    if encoding & 0x8000_0000 != 0 { return true }
    switch (encoding >> 24) & 0xFF {
    case 0x05:
        // The permute region is shared with SVE-integer's move family (DUP/CPY/
        // logical-imm) and SVE-FP's FCPY. Compose the exact complement of the
        // three siblings so no word can be both-owner by construction —
        // `isSVEPredicateControlEncoding` is always false at 0x05 (it owns only
        // 0x25/0x04), so its term documents the complement at zero real cost.
        return !isSVEPredicateControlEncoding(encoding)
            && !isSVEIntegerEncoding(encoding)
            && !isSVEFloatingPointEncoding(encoding)
    case 0x44:
        // `sve2p1_permute_vec_elems_q` (TBLQ/UZPQ/ZIPQ) — the one permute
        // class at 0x44, the exact complement of SVE-integer's `isSVE2IntegerLowInScope`
        // exclusion (VAL 0x4400_E000, MASK 0xFF20_E000).
        return (encoding & 0xFF20_E000) == 0x4400_E000
    case 0x45:
        // The crypto / LUT cluster SVE-integer excludes: bits 21, 15, 13 all set AND
        // at least one of bits 22/14/12/11 — the exact complement of
        // `isSVE2IntegerHighInScope`.
        return isSVE2CryptoOrLUT(encoding)
    default:
        // 0x04 integer, 0x24 integer-compare, 0x25 predicate/
        // immediate (SVE-predicate/SVE-integer), 0x64/0x65 floating-point.
        return false
    }
}

/// The 0x45 crypto / LUT cluster (AES/SM4/RAX1/multi-vector-PMULL/LUTI2/4)
/// that SVE-integer excludes and SVE-permute/memory owns — the exact complement of the crypto test
/// in `isSVE2IntegerHighInScope`.
@inline(__always)
@_effects(readonly)
func isSVE2CryptoOrLUT(_ e: UInt32) -> Bool {
    (e >> 21) & 1 == 1 && (e >> 13) & 1 == 1 && (e >> 15) & 1 == 1
        && ((e >> 22) & 1 == 1 || (e >> 14) & 1 == 1 || (e >> 12) & 1 == 1 || (e >> 11) & 1 == 1)
}
