// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// The precise encoding predicate that defines SVE-integer's scope (SVE /
// SVE2 integer). SVE-integer spans six of the SVE top bytes (0x04, 0x05, 0x24,
// 0x25, 0x44, 0x45), interleaved with SVE-predicate (predicate/count/index), SVE-FP
// (floating-point), SVE-permute/memory (permute/memory/crypto), and SME2 (counter
// forms). The tier's `SVEDecoder.region(for:)` classifier is coarser than
// any family boundary, so ownership is a bit predicate. It was derived
// from LLVM's tblgen encodings and verified EXACT two ways: (1) against
// every one of the 1,207 in-scope + 1,540 out-of-scope per-instruction
// definitions (with all don't-care bits both cleared and set), and (2)
// exhaustively over all 2^14 values of bits[23:10] for each of the six top
// bytes — the pair (top byte, bits[23:10]) provably determines scope with
// zero ambiguity, so bits[9:0] are never consulted. One predicate, three
// consumers: the SVEDecoder gate, the validator's exhaustiveSkip, and the
// real-corpus harvester's isInScope.

/// Whether `encoding` is an SVE/SVE2 integer instruction owned by family
/// SVE-integer. Safe to call on any 32-bit word (it re-checks `op0` itself). Out-of-
/// scope op0=2 words — predicate/count/index, floating-point,
/// permute/memory/crypto, SME2 counter forms — return `false`.
@inline(__always)
@_effects(readonly)
public func isSVEIntegerEncoding(_ encoding: UInt32) -> Bool {
    // op0 = bits[28:25] must be 0b0010 (the SVE tier).
    guard (encoding >> 25) & 0xF == 0b0010 else { return false }
    switch (encoding >> 24) & 0xFF {
    case 0x24: return true // the whole top byte is integer compare (vector/wide) + ucmp-immediate.
    case 0x44: return isSVE2IntegerLowInScope(encoding)
    case 0x45: return isSVE2IntegerHighInScope(encoding)
    case 0x04: return isSVEIntegerComputeInScope(encoding)
    case 0x25: return isSVEIntegerImmediateInScope(encoding)
    case 0x05: return isSVEIntegerMoveInScope(encoding)
    default: return false // 0x64/0x65 FP; 0x84…0xE5 memory.
    }
}

/// 0x44 region (SVE2 integer: saturating, mla-long, complex, dot/matmul,
/// clamp, unary-sat). Everything is SVE-integer's except `sve2p1_permute_vec_elems_q`
/// (TBLQ/UZPQ/ZIPQ — SVE-permute/memory), which is the only permute class at 0x44.
@inline(__always)
@_effects(readonly)
func isSVE2IntegerLowInScope(_ e: UInt32) -> Bool {
    (e & 0xFF20_E000) != 0x4400_E000 // sve2p1_permute_vec_elems_q → SVE-permute/memory
}

/// 0x45 region (SVE2 integer: wide-arith, narrowing, shift-immediate, bit-
/// permute, MATCH, HISTCNT/HISTSEG, matmul). The crypto (AES/SM4/RAX1/PMULL-
/// 128) and LUT (LUTI2/4/6) classes SVE-permute/memory owns cluster where bits 15, 13, 21
/// are all set and at least one of bits 22/14/12/11 is set; everything else
/// is SVE-integer's. (Verified exact against the crypto/lut/narrow/match/hist defs.)
@inline(__always)
@_effects(readonly)
func isSVE2IntegerHighInScope(_ e: UInt32) -> Bool {
    let crypto = (e >> 21) & 1 == 1 && (e >> 13) & 1 == 1 && (e >> 15) & 1 == 1
        && ((e >> 22) & 1 == 1 || (e >> 14) & 1 == 1 || (e >> 12) & 1 == 1 || (e >> 11) & 1 == 1)
    return !crypto
}

/// 0x04 region (SVE/SVE2 integer compute: predicated arith/logical/shift/
/// unary/multiply-add and reductions when bit21=0; unpredicated arith/logical/
/// mul/shift/ADR, ternary/XAR when bit21=1). Excludes the SVE-predicate element-count/
/// index/stack-adjust/MOVPRFX carve-out and the SVE-FP FABS/FNEG/FTSSEL/FEXPA.
@inline(__always)
@_effects(readonly)
func isSVEIntegerComputeInScope(_ e: UInt32) -> Bool {
    if (e >> 21) & 1 == 0 {
        let group = (e >> 13) & 0b111
        // MOVPRFX predicated: b21:19=010, b18:17=00, b15:13=001.
        if (e >> 19) & 0b111 == 0b010, (e >> 17) & 0b11 == 0, group == 0b001 { return false }
        // Predicated unary (b15:13=101): exclude FABS/FNEG (b19=1, opc[18:16] ∈ {100,101}) → SVE-FP.
        if group == 0b101, (e >> 19) & 1 == 1, (e >> 16) & 0b111 == 0b100 || (e >> 16) & 0b111 == 0b101 {
            return false
        }
        return true
    }
    let group = (e >> 12) & 0b1111
    // SVE-predicate carve-out: INDEX (0100), ADDVL/ADDPL/RDVL (0101), element-count (1100/1110/1111).
    if group == 0b0100 || group == 0b0101 || group == 0b1100 || group == 0b1110 || group == 0b1111 {
        return false
    }
    // Group 1011 holds FTSSEL/FEXPA and unpredicated MOVPRFX — the
    // latter sits at bits[15:11]=10111, which is inside this group, so excluding
    // the group excludes both. A separate MOVPRFX test would never fire.
    if group == 0b1011 { return false }
    return true
}

/// 0x25 region: the integer immediate forms SVE-integer owns — signed-immediate
/// compare, wide-immediate arith (ADD/SUB/… and MUL/SMAX/SMIN/UMAX/UMIN by
/// immediate), and DUP-immediate — carved out of the SVE-predicate predicate/count/
/// break/WHILE bulk. SVE-FP's FDUP needs no carve-out: it sets bit 16, and the
/// DUP-immediate term pins bits[21:16], so FDUP is never claimed here.
@inline(__always)
@_effects(readonly)
func isSVEIntegerImmediateInScope(_ e: UInt32) -> Bool {
    (e & 0xFF20_4000) == 0x2500_0000 // sve_int_scmp_vi (signed immediate compare)
        || (e & 0xFF38_C000) == 0x2520_C000 // sve_int_arith_imm0 (add/sub/saturating by immediate)
        || (e & 0xFF38_C000) == 0x2528_C000 // sve_int_arith_imm (smax/umax/smin/umin by immediate)
        || (e & 0xFF38_8000) == 0x2530_8000 // sve_int_arith_imm (mul by immediate; b14 left free)
        || (e & 0xFF3F_C000) == 0x2538_C000 // sve_int_dup_imm
}

/// 0x05 region: the integer move/copy and bitwise-immediate forms SVE-integer owns —
/// DUP (scalar/indexed broadcast), CPY (predicated scalar/simd/immediate),
/// AND/EOR/ORR logical-immediate, DUPM — carved out of the SVE-permute/memory permute bulk.
/// Two terms the region does *not* need: SVE-FP's FCPY sets bit 15 while the
/// CPY-immediate term pins it clear, so FCPY is never claimed; and DUPM's own
/// mask is a strict subset of the `sve_int_log_imm` term (they share the same
/// class region, DUPM being its bits[23:22]=11 quadrant), so it never matches
/// alone. Both were verified dead over the predicate's entire input domain.
@inline(__always)
@_effects(readonly)
func isSVEIntegerMoveInScope(_ e: UInt32) -> Bool {
    (e & 0xFF3F_FC00) == 0x0520_3800 // sve_int_perm_dup_r (DUP scalar)
        || (e & 0xFF20_FC00) == 0x0520_2000 // sve_int_perm_dup_i (DUP indexed broadcast)
        || (e & 0xFF3F_E000) == 0x0528_A000 // sve_int_perm_cpy_r (CPY scalar)
        || (e & 0xFF3F_E000) == 0x0520_8000 // sve_int_perm_cpy_v (CPY simd)
        || (e & 0xFF30_8000) == 0x0510_0000 // sve_int_dup_imm_pred (CPY immediate)
        || (e & 0xFF3C_0000) == 0x0500_0000 // sve_int_log_imm + sve_int_dup_mask_imm (DUPM)
}
