// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// The SVE / SVE2 floating-point decoder for SVE-FP.
enum SVEFloatingPointDecode {
    /// Decode an in-scope SVE floating-point word.
    @_optimize(speed)
    static func decode(encoding e: UInt32, address a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        switch (e >> 24) & 0xFF {
        case 0x65: decode65(e, a, &sink)
        case 0x64: decode64(e, a, &sink)
        case 0x04: decodeUnaryTrigCarveOut(e, a, &sink)
        case 0x05: decodeFCopy(e, a, &sink)
        default: decodeFDup(e, a, &sink)
        }
    }

    @inline(__always)
    static func decode65(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 21) & 1 == 1 {
            return (e >> 15) & 1 == 0 ? decodeFMLAFamily(e, a, &sink) : decodeFMADFamily(e, a, &sink)
        }
        if (e >> 14) & 1 == 1 {
            return decodeCompareVector(e, a, &sink)
        }
        switch (e >> 13) & 0b111 {
        case 0b000: return decodeUnpredicated3Op(e, a, &sink)
        case 0b001: return decode65ReductionColumn(e, a, &sink)
        case 0b100:
            switch (e >> 19) & 0b11 {
            case 0b11: return decodeArithImmediate(e, a, &sink)
            case 0b10: return decodeFTMAD(e, a, &sink)
            default: return decodePredicatedBinary(e, a, &sink)
            }
        default: return decodeUnaryMerging(e, a, &sink)
        }
    }

    /// The `bits[15:13] == 001` column at 0x65, split on bits[20:19].
    @inline(__always)
    static func decode65ReductionColumn(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 19) & 0b11 != 0b01 {
            if (e >> 20) & 1 == 0 { return decodeFastReduction(e, a, &sink) }
            return (e >> 19) & 1 == 0
                ? decodeCompareZero(e, a, &sink)
                : decodeFADDA(e, a, &sink)
        }
        if (e & 0xFFFE_F000) == 0x6508_3000 { return decodeFP8ConvertSingle(e, a, &sink) }
        if (e & 0xFFFF_F000) == 0x650A_3000 { return decodeFP8DownConvertPair(e, a, &sink) }
        if (e & 0xFF3F_F000) == 0x650C_3000 { return decodeFP8UpConvert(e, a, &sink) }
        if (e & 0xFF3F_F800) == 0x650D_3000 { return decodeIntConvertPair(e, a, &sink) }
        if (e & 0xFF3E_FC00) == 0x650E_3000 { return decodeReciprocalEstimate(e, a, &sink) }
        return undefined(e, a)
    }

    @inline(__always)
    static func decode64(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 21) & 1 == 0 {
            if (e >> 15) & 1 == 0 {
                return decodeFCMLAVector(e, a, &sink)
            }
            if (e >> 20) & 1 == 0 {
                return (e >> 13) & 0b11 == 0b00
                    ? decodeFCADD(e, a, &sink)
                    : decodeConvertPrecision(e, a, &sink)
            }
            if (e >> 19) & 1 == 1 {
                return decodeUnaryZeroing(e, a, &sink)
            }
            return (e >> 13) & 0b11 == 0b00
                ? decodePairwise(e, a, &sink)
                : decodeQuadReduction(e, a, &sink)
        }
        if (e & 0xFF20_FC00) == 0x6420_2400 { return decodeClamp(e, a, &sink) }
        if (e & 0xFFA0_F000) == 0x64A0_1000 { return decodeFCMLAIndexed(e, a, &sink) }
        if (e & 0xFF20_F400) == 0x6420_2000 { return decodeIndexedFMUL(e, a, &sink) }
        if (e & 0xFF20_F000) == 0x6420_0000 { return decodeIndexedFMA(e, a, &sink) }
        if (e & 0xFF60_F000) == 0x6420_5000 { return decodeFP8LongIndexed(e, a, &sink) }
        if (e & 0xFF20_F000) == 0x6420_C000 { return decodeFP8LongLongIndexed(e, a, &sink) }
        if (e & 0xFFA0_FC00) == 0x6420_4000 { return decodeDotIndexed(e, a, &sink) }
        if (e & 0xFFA0_F400) == 0x6420_4400 { return decodeFP8DotIndexed(e, a, &sink) }
        if (e & 0xFFA0_D000) == 0x64A0_4000 { return decodeWideningMLAIndexed(e, a, &sink) }
        if (e & 0xFF20_F800) == 0x6420_E000 { return decodeMatrixMLA(e, a, &sink) }
        if (e & 0xFFA0_D800) == 0x64A0_8000 { return decodeWideningMLA(e, a, &sink) }
        if (e & 0xFFA0_F800) == 0x6420_8000 { return decodeDot(e, a, &sink) }
        if (e & 0xFF60_CC00) == 0x6420_8800 { return decodeFP8MLA(e, a, &sink) }
        return undefined(e, a)
    }

    /// Element size from a 2-bit `sz` value (already shifted to the low 2
    /// bits).
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
    /// consulting this).
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

    /// A consecutive two-register source group `{ Z(2n), Z(2n+1) }`.
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
    /// encoding preserved), matching llvm-mc's empty output for rejected
    /// words.
    @inline(__always)
    static func undefined(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        DecodedDraft(address: a, encoding: e, mnemonic: .undefined, category: .sve)
    }
}
