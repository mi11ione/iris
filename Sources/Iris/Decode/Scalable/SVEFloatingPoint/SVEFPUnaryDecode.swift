// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEFloatingPointDecode {
    @inline(__always)
    static func decodeUnaryMerging(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let (mnemonic, dest, src) = unaryMergingForm(UInt8((e >> 16) & 0xFF)) else {
            return undefined(e, a)
        }
        return unaryDraft(e, a, mnemonic, dest, src, .merging, partial: true, &sink)
    }

    /// bits[23:16] → (mnemonic, destination element, source element) for the
    /// merging-unary class; nil marks the reserved slots between forms.
    @inline(__always)
    static func unaryMergingForm(_ key: UInt8) -> (Mnemonic, ScalarSize, ScalarSize)? {
        switch key {
        case 0x0A: (.fcvtx, .s, .d)
        case 0x10: (.frint32z, .s, .s)
        case 0x11: (.frint32x, .s, .s)
        case 0x12: (.frint32z, .d, .d)
        case 0x13: (.frint32x, .d, .d)
        case 0x14: (.frint64z, .s, .s)
        case 0x15: (.frint64x, .s, .s)
        case 0x16: (.frint64z, .d, .d)
        case 0x17: (.frint64x, .d, .d)
        case 0x1A: (.flogb, .h, .h)
        case 0x1C: (.flogb, .s, .s)
        case 0x1E: (.flogb, .d, .d)
        case 0x40: (.frintn, .h, .h)
        case 0x41: (.frintp, .h, .h)
        case 0x42: (.frintm, .h, .h)
        case 0x43: (.frintz, .h, .h)
        case 0x44: (.frinta, .h, .h)
        case 0x46: (.frintx, .h, .h)
        case 0x47: (.frinti, .h, .h)
        case 0x4C: (.frecpx, .h, .h)
        case 0x4D: (.fsqrt, .h, .h)
        case 0x52: (.scvtf, .h, .h)
        case 0x53: (.ucvtf, .h, .h)
        case 0x54: (.scvtf, .h, .s)
        case 0x55: (.ucvtf, .h, .s)
        case 0x56: (.scvtf, .h, .d)
        case 0x57: (.ucvtf, .h, .d)
        case 0x5A: (.fcvtzs, .h, .h)
        case 0x5B: (.fcvtzu, .h, .h)
        case 0x5C: (.fcvtzs, .s, .h)
        case 0x5D: (.fcvtzu, .s, .h)
        case 0x5E: (.fcvtzs, .d, .h)
        case 0x5F: (.fcvtzu, .d, .h)
        case 0x80: (.frintn, .s, .s)
        case 0x81: (.frintp, .s, .s)
        case 0x82: (.frintm, .s, .s)
        case 0x83: (.frintz, .s, .s)
        case 0x84: (.frinta, .s, .s)
        case 0x86: (.frintx, .s, .s)
        case 0x87: (.frinti, .s, .s)
        case 0x88: (.fcvt, .h, .s)
        case 0x89: (.fcvt, .s, .h)
        case 0x8A: (.bfcvt, .h, .s)
        case 0x8C: (.frecpx, .s, .s)
        case 0x8D: (.fsqrt, .s, .s)
        case 0x94: (.scvtf, .s, .s)
        case 0x95: (.ucvtf, .s, .s)
        case 0x9C: (.fcvtzs, .s, .s)
        case 0x9D: (.fcvtzu, .s, .s)
        case 0xC0: (.frintn, .d, .d)
        case 0xC1: (.frintp, .d, .d)
        case 0xC2: (.frintm, .d, .d)
        case 0xC3: (.frintz, .d, .d)
        case 0xC4: (.frinta, .d, .d)
        case 0xC6: (.frintx, .d, .d)
        case 0xC7: (.frinti, .d, .d)
        case 0xC8: (.fcvt, .h, .d)
        case 0xC9: (.fcvt, .d, .h)
        case 0xCA: (.fcvt, .s, .d)
        case 0xCB: (.fcvt, .d, .s)
        case 0xCC: (.frecpx, .d, .d)
        case 0xCD: (.fsqrt, .d, .d)
        case 0xD0: (.scvtf, .d, .s)
        case 0xD1: (.ucvtf, .d, .s)
        case 0xD4: (.scvtf, .s, .d)
        case 0xD5: (.ucvtf, .s, .d)
        case 0xD6: (.scvtf, .d, .d)
        case 0xD7: (.ucvtf, .d, .d)
        case 0xD8: (.fcvtzs, .s, .d)
        case 0xD9: (.fcvtzu, .s, .d)
        case 0xDC: (.fcvtzs, .d, .s)
        case 0xDD: (.fcvtzu, .d, .s)
        case 0xDE: (.fcvtzs, .d, .d)
        case 0xDF: (.fcvtzu, .d, .d)
        default: nil
        }
    }

    @inline(__always)
    static func decodeUnaryZeroing(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let (mnemonic, dest, src) = unaryZeroingForm(
            UInt8((e >> 16) & 0xFF), UInt8((e >> 13) & 0b111),
        ) else {
            return undefined(e, a)
        }
        return unaryDraft(e, a, mnemonic, dest, src, .zeroing, partial: false, &sink)
    }

    /// (bits[23:16], bits[15:13]) → (mnemonic, destination, source) for the
    /// zeroing-unary class; nil marks the reserved slots.
    @inline(__always)
    static func unaryZeroingForm(_ key: UInt8, _ low: UInt8) -> (Mnemonic, ScalarSize, ScalarSize)? {
        switch (key, low) {
        case (0x1A, 0b110): (.fcvtx, .s, .d)
        case (0x1C, 0b100): (.frint32z, .s, .s)
        case (0x1C, 0b101): (.frint32x, .s, .s)
        case (0x1C, 0b110): (.frint32z, .d, .d)
        case (0x1C, 0b111): (.frint32x, .d, .d)
        case (0x1D, 0b100): (.frint64z, .s, .s)
        case (0x1D, 0b101): (.frint64x, .s, .s)
        case (0x1D, 0b110): (.frint64z, .d, .d)
        case (0x1D, 0b111): (.frint64x, .d, .d)
        case (0x1E, 0b101): (.flogb, .h, .h)
        case (0x1E, 0b110): (.flogb, .s, .s)
        case (0x1E, 0b111): (.flogb, .d, .d)
        case (0x58, 0b100): (.frintn, .h, .h)
        case (0x58, 0b101): (.frintp, .h, .h)
        case (0x58, 0b110): (.frintm, .h, .h)
        case (0x58, 0b111): (.frintz, .h, .h)
        case (0x59, 0b100): (.frinta, .h, .h)
        case (0x59, 0b110): (.frintx, .h, .h)
        case (0x59, 0b111): (.frinti, .h, .h)
        case (0x5B, 0b100): (.frecpx, .h, .h)
        case (0x5B, 0b101): (.fsqrt, .h, .h)
        case (0x5C, 0b110): (.scvtf, .h, .h)
        case (0x5C, 0b111): (.ucvtf, .h, .h)
        case (0x5D, 0b100): (.scvtf, .h, .s)
        case (0x5D, 0b101): (.ucvtf, .h, .s)
        case (0x5D, 0b110): (.scvtf, .h, .d)
        case (0x5D, 0b111): (.ucvtf, .h, .d)
        case (0x5E, 0b110): (.fcvtzs, .h, .h)
        case (0x5E, 0b111): (.fcvtzu, .h, .h)
        case (0x5F, 0b100): (.fcvtzs, .s, .h)
        case (0x5F, 0b101): (.fcvtzu, .s, .h)
        case (0x5F, 0b110): (.fcvtzs, .d, .h)
        case (0x5F, 0b111): (.fcvtzu, .d, .h)
        case (0x98, 0b100): (.frintn, .s, .s)
        case (0x98, 0b101): (.frintp, .s, .s)
        case (0x98, 0b110): (.frintm, .s, .s)
        case (0x98, 0b111): (.frintz, .s, .s)
        case (0x99, 0b100): (.frinta, .s, .s)
        case (0x99, 0b110): (.frintx, .s, .s)
        case (0x99, 0b111): (.frinti, .s, .s)
        case (0x9A, 0b100): (.fcvt, .h, .s)
        case (0x9A, 0b101): (.fcvt, .s, .h)
        case (0x9A, 0b110): (.bfcvt, .h, .s)
        case (0x9B, 0b100): (.frecpx, .s, .s)
        case (0x9B, 0b101): (.fsqrt, .s, .s)
        case (0x9D, 0b100): (.scvtf, .s, .s)
        case (0x9D, 0b101): (.ucvtf, .s, .s)
        case (0x9F, 0b100): (.fcvtzs, .s, .s)
        case (0x9F, 0b101): (.fcvtzu, .s, .s)
        case (0xD8, 0b100): (.frintn, .d, .d)
        case (0xD8, 0b101): (.frintp, .d, .d)
        case (0xD8, 0b110): (.frintm, .d, .d)
        case (0xD8, 0b111): (.frintz, .d, .d)
        case (0xD9, 0b100): (.frinta, .d, .d)
        case (0xD9, 0b110): (.frintx, .d, .d)
        case (0xD9, 0b111): (.frinti, .d, .d)
        case (0xDA, 0b100): (.fcvt, .h, .d)
        case (0xDA, 0b101): (.fcvt, .d, .h)
        case (0xDA, 0b110): (.fcvt, .s, .d)
        case (0xDA, 0b111): (.fcvt, .d, .s)
        case (0xDB, 0b100): (.frecpx, .d, .d)
        case (0xDB, 0b101): (.fsqrt, .d, .d)
        case (0xDC, 0b100): (.scvtf, .d, .s)
        case (0xDC, 0b101): (.ucvtf, .d, .s)
        case (0xDD, 0b100): (.scvtf, .s, .d)
        case (0xDD, 0b101): (.ucvtf, .s, .d)
        case (0xDD, 0b110): (.scvtf, .d, .d)
        case (0xDD, 0b111): (.ucvtf, .d, .d)
        case (0xDE, 0b100): (.fcvtzs, .s, .d)
        case (0xDE, 0b101): (.fcvtzu, .s, .d)
        case (0xDF, 0b100): (.fcvtzs, .d, .s)
        case (0xDF, 0b101): (.fcvtzu, .d, .s)
        case (0xDF, 0b110): (.fcvtzs, .d, .d)
        case (0xDF, 0b111): (.fcvtzu, .d, .d)
        default: nil
        }
    }

    @inline(__always)
    static func decodeConvertPrecision(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 13) & 0b11 != 0b01 { return undefined(e, a) }
        let merging = (e >> 19) & 1 == 1
        let mnemonic: Mnemonic
        let dest: ScalarSize
        let src: ScalarSize
        switch (e >> 16) & 0xF7 {
        case 0x02: (mnemonic, dest, src) = (.fcvtxnt, .s, .d)
        case 0x80: (mnemonic, dest, src) = (.fcvtnt, .h, .s)
        case 0x81: (mnemonic, dest, src) = (.fcvtlt, .s, .h)
        case 0x82: (mnemonic, dest, src) = (.bfcvtnt, .h, .s)
        case 0xC2: (mnemonic, dest, src) = (.fcvtnt, .s, .d)
        case 0xC3: (mnemonic, dest, src) = (.fcvtlt, .d, .s)
        default: return undefined(e, a)
        }
        let preserving = mnemonic != .fcvtlt
        return unaryDraft(
            e, a, mnemonic, dest, src,
            merging ? .merging : .zeroing,
            partial: preserving || merging, &sink,
        )
    }

    /// Build the `<Zd>.<T'>, <Pg>/{m,z}, <Zn>.<T>` unary draft shared by
    /// G11/G14/G15.
    @inline(__always)
    static func unaryDraft(
        _ e: UInt32, _ a: UInt64, _ mnemonic: Mnemonic,
        _ dest: ScalarSize, _ src: ScalarSize,
        _ qualifier: PredicateQualifier, partial: Bool, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let d = zd(e), n = zn(e), g = pg3(e)
        var reads = vecMask(n)
        var effect: ScalableEffect = .readsStreamingMode
        if partial {
            reads = reads.union(vecMask(d))
            effect.insert(.partialWrite)
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, dest), govern(g, qualifier), vec(n, src)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: effect,
        )
    }
}
