// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// SVE / SVE2 floating-point decoder. Entry + top sub-dispatch
// the 0x65 and 0x64 top bytes split on bit21 and bits[15:13]
// (the structural selectors every FP class pins) into the 26 per-group
// decoders in sibling files; the 0x04/0x05/0x25 carve-outs (FABS/FNEG,
// FTSSEL/FEXPA, FCPY, FDUP) route directly. Called only from
// `SVEDecoder.decode` when `isSVEFloatingPointEncoding` holds, so `decode` is
// total over SVE-FP's domain: every path returns a real record or a well-formed
// UNDEFINED (`.undefined`, `.sve`) for the genuine in-scope holes (reserved
// size, reserved opc slot).
//
// Shared field extraction and draft-building helpers used by every group
// decoder live here.

/// The SVE / SVE2 floating-point decoder for SVE-FP.
enum SVEFloatingPointDecode {
    /// Decode an in-scope SVE floating-point word. Precondition (by
    /// construction, not asserted): `isSVEFloatingPointEncoding(encoding)`.
    @_optimize(speed)
    static func decode(encoding e: UInt32, address a: UInt64) -> DecodedDraft {
        switch (e >> 24) & 0xFF {
        case 0x65: decode65(e, a)
        case 0x64: decode64(e, a)
        case 0x04: decodeUnaryTrigCarveOut(e, a) // G25 FABS/FNEG + FTSSEL/FEXPA
        case 0x05: decodeFCopy(e, a) // G26 FCPY → fmov
        default: decodeFDup(e, a) // 0x25 — G26 FDUP → fmov
        }
    }

    // MARK: 0x65 sub-dispatch

    //
    // Group routing (verified against the tblgen catalogue). bit21=1:
    // b15 splits the two predicated FMA shapes. bit21=0, by bits[15:13]:
    // 000 unpredicated 3-op (G5); 001 the reduction/unary-unpredicated column,
    // sub-split below; 01x vector compares (G9, b14=1); 100 predicated binary /
    // immediate / FTMAD (G1/G2/G12 by bits[20:19]); 101 predicated unary `/M`
    // (G11); 110/111 unallocated.

    @inline(__always)
    static func decode65(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        if (e >> 21) & 1 == 1 {
            // sve_fp_3op_p_zds_a (b15=0) / _b (b15=1).
            return (e >> 15) & 1 == 0 ? decodeFMLAFamily(e, a) : decodeFMADFamily(e, a)
        }
        if (e >> 14) & 1 == 1 {
            // G9 — bit14 alone marks the vector-compare region: the compare
            // selector is (bit15, bit13, bit4), so FCMUO/FACGE/FACGT carry
            // bit15=1 and the class spans bits[15:14] ∈ {01, 11}.
            return decodeCompareVector(e, a)
        }
        switch (e >> 13) & 0b111 {
        case 0b000: return decodeUnpredicated3Op(e, a) // G5
        case 0b001: return decode65ReductionColumn(e, a) // G6/G7/G8/G10/G13
        case 0b100:
            // bits[20:19]: 00/01 → predicated binary (G1); 11 → immediate
            // (G2); 10 → FTMAD (G12).
            switch (e >> 19) & 0b11 {
            case 0b11: return decodeArithImmediate(e, a) // G2
            case 0b10: return decodeFTMAD(e, a) // G12
            default: return decodePredicatedBinary(e, a) // G1
            }
        // bits[15:13]==0b101 (G11 merging unary) is the only remaining value:
        // bit14 was intercepted above, so 0b01x/0b11x cannot reach this switch.
        default: return decodeUnaryMerging(e, a) // G11
        }
    }

    /// The `bits[15:13] == 001` column at 0x65, split on bits[20:19] (bit12
    /// is the governing predicate's top bit in the reduction classes, so it
    /// cannot discriminate): 00 → fast reductions, 10 → compare-with-zero,
    /// 11 → FADDA, and 01 → the unpredicated unary/convert cluster
    /// (bits[15:12]=0011 fixed there) — the FP8 single converts, pair
    /// down-converts, FP8 up-converts, pair int-converts, and
    /// FRECPE/FRSQRTE.
    @inline(__always)
    static func decode65ReductionColumn(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        if (e >> 19) & 0b11 != 0b01 {
            if (e >> 20) & 1 == 0 { return decodeFastReduction(e, a) } // G7
            return (e >> 19) & 1 == 0
                ? decodeCompareZero(e, a) // G10
                : decodeFADDA(e, a) // G8
        }
        // Class-mask chain (mutually disjoint patterns from the catalogue).
        if (e & 0xFFFE_F000) == 0x6508_3000 { return decodeFP8ConvertSingle(e, a) } // G13a
        if (e & 0xFFFF_F000) == 0x650A_3000 { return decodeFP8DownConvertPair(e, a) } // G13b/c
        if (e & 0xFF3F_F000) == 0x650C_3000 { return decodeFP8UpConvert(e, a) } // G13e
        if (e & 0xFF3F_F800) == 0x650D_3000 { return decodeIntConvertPair(e, a) } // G13d
        if (e & 0xFF3E_FC00) == 0x650E_3000 { return decodeReciprocalEstimate(e, a) } // G6
        return undefined(e, a)
    }

    // MARK: 0x64 sub-dispatch

    //
    // bit21=0: b15=0 → FCMLA vector (G17); b15=1 by bits[20:19] then
    // bits[15:13]: 00 → FCADD ([15:13]=100) / convert-precision ([15:13]=101);
    // 10 → pairwise ([15:13]=100) / quadword reductions ([15:13]=101); 11 →
    // zeroing unary `/Z` (G14, all of [15:13]=1xx). bit21=1: the indexed /
    // widening / dot / matrix cluster, split on bits[15:10] regions.

    @inline(__always)
    static func decode64(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        if (e >> 21) & 1 == 0 {
            if (e >> 15) & 1 == 0 {
                return decodeFCMLAVector(e, a) // G17 (rot at [14:13])
            }
            if (e >> 20) & 1 == 0 {
                // bit20=0: FCADD at bits[14:13]=00 (bit19 is part of its fixed
                // zero field, checked inside) or convert-precision at
                // bits[14:13]=01 (bit19 selects `/M` vs `/Z` there).
                return (e >> 13) & 0b11 == 0b00
                    ? decodeFCADD(e, a) // G17
                    : decodeConvertPrecision(e, a) // G15
            }
            if (e >> 19) & 1 == 1 {
                return decodeUnaryZeroing(e, a) // G14 (bits[20:19]=11)
            }
            return (e >> 13) & 0b11 == 0b00
                ? decodePairwise(e, a) // G16 (bits[20:19]=10)
                : decodeQuadReduction(e, a) // G24
        }
        // bit21=1 — the indexed / widening / dot / matrix cluster. The class
        // patterns interleave on bits[23:22] and bits[11:10] (e.g. the fp8 dot
        // and the bf16 widening MLA share bits[15:12] and split on bit23), so
        // routing is a chain of class-common mask tests taken verbatim from
        // the catalogue; every pair of patterns below is mask-disjoint, making
        // the chain order-free.
        if (e & 0xFF20_FC00) == 0x6420_2400 { return decodeClamp(e, a) } // G23
        if (e & 0xFFA0_F000) == 0x64A0_1000 { return decodeFCMLAIndexed(e, a) } // G17c
        if (e & 0xFF20_F400) == 0x6420_2000 { return decodeIndexedFMUL(e, a) } // G18b
        if (e & 0xFF20_F000) == 0x6420_0000 { return decodeIndexedFMA(e, a) } // G18a
        if (e & 0xFF60_F000) == 0x6420_5000 { return decodeFP8LongIndexed(e, a) } // G21b
        if (e & 0xFF20_F000) == 0x6420_C000 { return decodeFP8LongLongIndexed(e, a) } // G21c
        if (e & 0xFFA0_FC00) == 0x6420_4000 { return decodeDotIndexed(e, a) } // G20b
        if (e & 0xFFA0_F400) == 0x6420_4400 { return decodeFP8DotIndexed(e, a) } // G20c
        if (e & 0xFFA0_D000) == 0x64A0_4000 { return decodeWideningMLAIndexed(e, a) } // G19b
        if (e & 0xFF20_F800) == 0x6420_E000 { return decodeMatrixMLA(e, a) } // G21d+G22
        if (e & 0xFFA0_D800) == 0x64A0_8000 { return decodeWideningMLA(e, a) } // G19a
        if (e & 0xFFA0_F800) == 0x6420_8000 { return decodeDot(e, a) } // G20a
        if (e & 0xFF60_CC00) == 0x6420_8800 { return decodeFP8MLA(e, a) } // G21a
        return undefined(e, a)
    }

    // MARK: shared field extraction

    /// Element size from a 2-bit `sz` value (already shifted to the low 2 bits).
    /// Every caller consults this only after claiming `sz==0b00` as the bf16
    /// slot or a hole, so `sz` is 01/10/11 here — the byte element never occurs.
    @inline(__always)
    static func elementSize(_ sz: UInt32) -> ScalarSize {
        switch sz & 0b11 {
        case 1: .h
        case 2: .s
        default: .d
        }
    }

    /// The floating-point element size from bits[23:22], where `00` is
    /// reserved (or a bf16 opcode, which every caller claims explicitly before
    /// consulting this): `01` → .h, `10` → .s, `11` → .d.
    @inline(__always)
    static func fpSize(_ e: UInt32) -> ScalarSize? {
        switch (e >> 22) & 0b11 {
        case 0b01: .h
        case 0b10: .s
        case 0b11: .d
        default: nil
        }
    }

    /// The ``FloatImmediateKind`` matching an FP element size.
    @inline(__always)
    static func immediateKind(_ size: ScalarSize) -> FloatImmediateKind {
        switch size {
        case .h: .half
        case .d: .double
        default: .single
        }
    }

    @inline(__always) static func zd(_ e: UInt32) -> UInt8 {
        UInt8(e & 0x1F)
    }

    @inline(__always) static func zn(_ e: UInt32) -> UInt8 {
        UInt8((e >> 5) & 0x1F)
    }

    @inline(__always) static func zm(_ e: UInt32) -> UInt8 {
        UInt8((e >> 16) & 0x1F)
    }

    @inline(__always) static func pg3(_ e: UInt32) -> UInt8 {
        UInt8((e >> 10) & 0x7)
    }

    // MARK: shared operand + mask builders

    @inline(__always)
    static func vec(_ index: UInt8, _ element: ScalarSize) -> Operand {
        .scalableVector(ScalableVectorRef(registerIndex: index, element: element))
    }

    @inline(__always)
    static func vecIndexed(_ index: UInt8, _ element: ScalarSize, lane: UInt8) -> Operand {
        .scalableVector(ScalableVectorRef(registerIndex: index, element: element, elementIndex: lane))
    }

    @inline(__always)
    static func govern(_ index: UInt8, _ qualifier: PredicateQualifier) -> Operand {
        .scalablePredicate(ScalablePredicateRef(registerIndex: index, qualifier: qualifier, role: .governing))
    }

    @inline(__always)
    static func vecMask(_ index: UInt8) -> RegisterSet {
        RegisterSet.empty.inserting(ScalableVectorRef(registerIndex: index))
    }

    /// A consecutive two-register source group `{ Z(2n), Z(2n+1) }` — the
    /// multi-vector convert sources, whose 4-bit field at bits[9:6] carries
    /// the pair base divided by two (bit5 is fixed zero).
    @inline(__always)
    static func vecPair(_ e: UInt32, _ element: ScalarSize) -> Operand {
        .scalableVectorGroup(ScalableVectorGroup(
            firstIndex: UInt8((e >> 6) & 0xF) &* 2, count: 2,
            element: element, layout: .consecutive,
        ))
    }

    @inline(__always)
    static func vecPairMask(_ e: UInt32) -> RegisterSet {
        let first = UInt8((e >> 6) & 0xF) &* 2
        return RegisterSet.empty
            .inserting(ScalableVectorRef(registerIndex: first))
            .inserting(ScalableVectorRef(registerIndex: first &+ 1))
    }

    /// A well-formed in-scope UNDEFINED SVE record (`category = .sve`, raw
    /// encoding preserved), matching llvm-mc's empty output for rejected words.
    @inline(__always)
    static func undefined(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        DecodedDraft(address: a, encoding: e, mnemonic: .undefined, category: .sve)
    }
}
