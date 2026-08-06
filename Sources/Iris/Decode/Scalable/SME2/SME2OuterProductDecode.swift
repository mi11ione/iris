// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// SME2 outer-product-extension decoders.
enum SME2OuterProductDecode {
    /// Decode an outer-product word in the cells SME2 owns.
    @_optimize(speed)
    static func decode(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if let base = mop4Base(e) { return decodeMop4(e, a, base, &sink) }
        if e & 0x0080_0000 == 0, e & 0x0040_0000 != 0 { return decodeTmop(e, a, &sink) }
        return decodeResidue(e, a, &sink)
    }

    /// Decode a residue inside SME-core's outer-product cells (bit23=1).
    @_optimize(speed)
    private static func decodeResidue(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        switch e & 0xFFE0_001C {
        case 0xA080_0008: return predicatedOuterProduct(e, a, .smopa, tile: .s, source: .h, &sink)
        case 0xA080_0018: return predicatedOuterProduct(e, a, .smops, tile: .s, source: .h, &sink)
        case 0xA180_0008: return predicatedOuterProduct(e, a, .umopa, tile: .s, source: .h, &sink)
        case 0xA180_0018: return predicatedOuterProduct(e, a, .umops, tile: .s, source: .h, &sink)
        default: break
        }
        if e & 0xFFE0_001C == 0x80A0_0000 {
            return predicatedOuterProduct(e, a, .fmopa, tile: .s, source: .b, &sink)
        }
        if e & 0xFFE0_001E == 0x80A0_0008 {
            return predicatedOuterProduct(e, a, .fmopa, tile: .h, source: .b, &sink)
        }
        return SME2Decode.undefined(e, a)
    }

    /// One MOP4 base (mnemonic + tile/source element + ZAda field width),
    /// keyed by the encoding with the M (Zm-pair) and N (Zn-pair) bits
    /// stripped.
    private struct Mop4Base {
        let mnemonic: Mnemonic
        let tile: ScalarSize
        let source: ScalarSize
        let zadaBits: UInt32
    }

    @_optimize(speed)
    private static func decodeMop4(_ e: UInt32, _ a: UInt64, _ base: Mop4Base, _ sink: inout OperandSink) -> DecodedDraft {
        let znPair = e & 0x200 != 0
        let zmPair = e & 0x0010_0000 != 0
        let znField = UInt8((e >> 6) & 0x7)
        let zmField = UInt8((e >> 17) & 0x7)
        let zn = znField &* 2
        let zm = zmField &* 2 &+ 16
        let zada = UInt8(e & base.zadaBits)

        let znOperand: Operand = znPair
            ? SME2Decode.group(zn, 2, base.source)
            : SME2Decode.vec(zn, base.source)
        let zmOperand: Operand = zmPair
            ? SME2Decode.group(zm, 2, base.source)
            : SME2Decode.vec(zm, base.source)
        var reads = znPair ? SME2Decode.groupMask(zn, 2) : SME2Decode.vecMask(zn)
        reads = reads.union(zmPair ? SME2Decode.groupMask(zm, 2) : SME2Decode.vecMask(zm))
        let za = ScalableRegisterSet.empty.inserting(ZATileMask(tile: zada, element: base.tile))
        return DecodedDraft(
            address: a, encoding: e, mnemonic: base.mnemonic,
            semanticReads: reads, category: .sme,
            operandCount: sink.emit(.zaTile(index: zada, element: base.tile), znOperand, zmOperand),
            scalableReads: za, scalableWrites: za,
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    /// Look up a MOP4 base by the M/N-stripped key.
    @inline(__always)
    private static func mop4Base(_ e: UInt32) -> Mop4Base? {
        switch e & 0xFFE1_FC38 {
        case 0x80C0_0008: return Mop4Base(mnemonic: .fmop4a, tile: .d, source: .d, zadaBits: 0x7)
        case 0x80C0_0018: return Mop4Base(mnemonic: .fmop4s, tile: .d, source: .d, zadaBits: 0x7)
        case 0xA0C0_0008: return Mop4Base(mnemonic: .smop4a, tile: .d, source: .h, zadaBits: 0x7)
        case 0xA0C0_0018: return Mop4Base(mnemonic: .smop4s, tile: .d, source: .h, zadaBits: 0x7)
        case 0xA0E0_0008: return Mop4Base(mnemonic: .sumop4a, tile: .d, source: .h, zadaBits: 0x7)
        case 0xA0E0_0018: return Mop4Base(mnemonic: .sumop4s, tile: .d, source: .h, zadaBits: 0x7)
        case 0xA1C0_0008: return Mop4Base(mnemonic: .usmop4a, tile: .d, source: .h, zadaBits: 0x7)
        case 0xA1C0_0018: return Mop4Base(mnemonic: .usmop4s, tile: .d, source: .h, zadaBits: 0x7)
        case 0xA1E0_0008: return Mop4Base(mnemonic: .umop4a, tile: .d, source: .h, zadaBits: 0x7)
        case 0xA1E0_0018: return Mop4Base(mnemonic: .umop4s, tile: .d, source: .h, zadaBits: 0x7)
        default: break
        }
        switch e & 0xFFE1_FC3E {
        case 0x8020_0008: return Mop4Base(mnemonic: .fmop4a, tile: .h, source: .b, zadaBits: 0x1)
        case 0x8100_0008: return Mop4Base(mnemonic: .fmop4a, tile: .h, source: .h, zadaBits: 0x1)
        case 0x8100_0018: return Mop4Base(mnemonic: .fmop4s, tile: .h, source: .h, zadaBits: 0x1)
        case 0x8120_0008: return Mop4Base(mnemonic: .bfmop4a, tile: .h, source: .h, zadaBits: 0x1)
        case 0x8120_0018: return Mop4Base(mnemonic: .bfmop4s, tile: .h, source: .h, zadaBits: 0x1)
        default: break
        }
        switch e & 0xFFE1_FC3C {
        case 0x8000_0000: return Mop4Base(mnemonic: .fmop4a, tile: .s, source: .s, zadaBits: 0x3)
        case 0x8000_0010: return Mop4Base(mnemonic: .fmop4s, tile: .s, source: .s, zadaBits: 0x3)
        case 0x8000_8000: return Mop4Base(mnemonic: .smop4a, tile: .s, source: .b, zadaBits: 0x3)
        case 0x8000_8008: return Mop4Base(mnemonic: .smop4a, tile: .s, source: .h, zadaBits: 0x3)
        case 0x8000_8010: return Mop4Base(mnemonic: .smop4s, tile: .s, source: .b, zadaBits: 0x3)
        case 0x8000_8018: return Mop4Base(mnemonic: .smop4s, tile: .s, source: .h, zadaBits: 0x3)
        case 0x8020_0000: return Mop4Base(mnemonic: .fmop4a, tile: .s, source: .b, zadaBits: 0x3)
        case 0x8020_8000: return Mop4Base(mnemonic: .sumop4a, tile: .s, source: .b, zadaBits: 0x3)
        case 0x8020_8010: return Mop4Base(mnemonic: .sumop4s, tile: .s, source: .b, zadaBits: 0x3)
        case 0x8100_0000: return Mop4Base(mnemonic: .bfmop4a, tile: .s, source: .h, zadaBits: 0x3)
        case 0x8100_0010: return Mop4Base(mnemonic: .bfmop4s, tile: .s, source: .h, zadaBits: 0x3)
        case 0x8100_8000: return Mop4Base(mnemonic: .usmop4a, tile: .s, source: .b, zadaBits: 0x3)
        case 0x8100_8008: return Mop4Base(mnemonic: .umop4a, tile: .s, source: .h, zadaBits: 0x3)
        case 0x8100_8010: return Mop4Base(mnemonic: .usmop4s, tile: .s, source: .b, zadaBits: 0x3)
        case 0x8100_8018: return Mop4Base(mnemonic: .umop4s, tile: .s, source: .h, zadaBits: 0x3)
        case 0x8120_0000: return Mop4Base(mnemonic: .fmop4a, tile: .s, source: .h, zadaBits: 0x3)
        case 0x8120_0010: return Mop4Base(mnemonic: .fmop4s, tile: .s, source: .h, zadaBits: 0x3)
        case 0x8120_8000: return Mop4Base(mnemonic: .umop4a, tile: .s, source: .b, zadaBits: 0x3)
        case 0x8120_8010: return Mop4Base(mnemonic: .umop4s, tile: .s, source: .b, zadaBits: 0x3)
        default: return nil
        }
    }

    @_optimize(speed)
    private static func decodeTmop(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let (mnemonic, tile, source): (Mnemonic, ScalarSize, ScalarSize)
        switch e & 0xFFE0_E00E {
        case 0x8140_0008: (mnemonic, tile, source) = (.ftmopa, .h, .h)
        case 0x8060_0008: (mnemonic, tile, source) = (.ftmopa, .h, .b)
        case 0x8160_0008: (mnemonic, tile, source) = (.bftmopa, .h, .h)
        default:
            switch e & 0xFFE0_E00C {
            case 0x8040_0000: (mnemonic, tile, source) = (.ftmopa, .s, .s)
            case 0x8060_0000: (mnemonic, tile, source) = (.ftmopa, .s, .b)
            case 0x8160_0000: (mnemonic, tile, source) = (.ftmopa, .s, .h)
            case 0x8140_0000: (mnemonic, tile, source) = (.bftmopa, .s, .h)
            case 0x8040_8000: (mnemonic, tile, source) = (.stmopa, .s, .b)
            case 0x8040_8008: (mnemonic, tile, source) = (.stmopa, .s, .h)
            case 0x8160_8000: (mnemonic, tile, source) = (.utmopa, .s, .b)
            case 0x8140_8008: (mnemonic, tile, source) = (.utmopa, .s, .h)
            case 0x8060_8000: (mnemonic, tile, source) = (.sutmopa, .s, .b)
            case 0x8140_8000: (mnemonic, tile, source) = (.ustmopa, .s, .b)
            default: return SME2Decode.undefined(e, a)
            }
        }
        let zmIndex = UInt8((e >> 16) & 0x1F)
        let znField = UInt8((e >> 6) & 0xF)
        let zn = znField &* 2
        let zkBase: UInt8 = e & 0x1000 != 0 ? 28 : 20
        let zk = zkBase &+ UInt8((e >> 10) & 0x3)
        let index = UInt8((e >> 4) & 0x3)
        let zadaBits: UInt32 = tile == .h ? 0x1 : 0x3
        let zada = UInt8(e & zadaBits)
        let za = ScalableRegisterSet.empty.inserting(ZATileMask(tile: zada, element: tile))
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: SME2Decode.groupMask(zn, 2)
                .union(SME2Decode.vecMask(zmIndex)).union(SME2Decode.vecMask(zk)),
            category: .sme,
            operandCount: sink.emit(.zaTile(index: zada, element: tile), SME2Decode.group(zn, 2, source), SME2Decode.vec(zmIndex, source), SME2Decode.vec(zk, nil, index: index)),
            scalableReads: za, scalableWrites: za,
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    /// A predicated outer product `<mnem> zada.<T>, Pn/m, Pm/m, Zn.<Ts>,
    /// Zm.<Ts>` (SME-core's shape, reused for the SME2 residues).
    @inline(__always)
    private static func predicatedOuterProduct(
        _ e: UInt32, _ a: UInt64, _ mnemonic: Mnemonic, tile: ScalarSize, source: ScalarSize, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let zada = UInt8(e & (tile == .h ? 0x1 : 0x3))
        let pn = UInt8((e >> 10) & 0x7)
        let pm = UInt8((e >> 13) & 0x7)
        let zn = UInt8((e >> 5) & 0x1F)
        let zm = UInt8((e >> 16) & 0x1F)
        let za = ScalableRegisterSet.empty.inserting(ZATileMask(tile: zada, element: tile))
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: SME2Decode.vecMask(zn).union(SME2Decode.vecMask(zm)),
            category: .sme,
            operandCount: sink.emit(.zaTile(index: zada, element: tile), .scalablePredicate(ScalablePredicateRef(registerIndex: pn, qualifier: .merging)), .scalablePredicate(ScalablePredicateRef(registerIndex: pm, qualifier: .merging)), SME2Decode.vec(zn, source), SME2Decode.vec(zm, source)),
            scalableReads: za.union(SME2Decode.predMask(pn)).union(SME2Decode.predMask(pm)),
            scalableWrites: za,
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }
}
