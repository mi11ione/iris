// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SMECoreDecode {
    /// One outer-product encoding's identity.
    struct OuterProductRow {
        let mnemonic: Mnemonic
        let tile: ScalarSize
        let source: ScalarSize
    }

    /// The core outer-product row for `e`, or `nil` for a residue word / hole.
    @inline(__always)
    static func outerProductRow(_ e: UInt32) -> OuterProductRow? {
        switch e & 0xFFE0_001C {
        case 0x8080_0000: return OuterProductRow(mnemonic: .fmopa, tile: .s, source: .s)
        case 0x8080_0010: return OuterProductRow(mnemonic: .fmops, tile: .s, source: .s)
        case 0x8080_0008: return OuterProductRow(mnemonic: .bmopa, tile: .s, source: .s)
        case 0x8080_0018: return OuterProductRow(mnemonic: .bmops, tile: .s, source: .s)
        case 0x8180_0000: return OuterProductRow(mnemonic: .bfmopa, tile: .s, source: .h)
        case 0x8180_0010: return OuterProductRow(mnemonic: .bfmops, tile: .s, source: .h)
        case 0x81A0_0000: return OuterProductRow(mnemonic: .fmopa, tile: .s, source: .h)
        case 0x81A0_0010: return OuterProductRow(mnemonic: .fmops, tile: .s, source: .h)
        case 0xA080_0000: return OuterProductRow(mnemonic: .smopa, tile: .s, source: .b)
        case 0xA080_0010: return OuterProductRow(mnemonic: .smops, tile: .s, source: .b)
        case 0xA0A0_0000: return OuterProductRow(mnemonic: .sumopa, tile: .s, source: .b)
        case 0xA0A0_0010: return OuterProductRow(mnemonic: .sumops, tile: .s, source: .b)
        case 0xA180_0000: return OuterProductRow(mnemonic: .usmopa, tile: .s, source: .b)
        case 0xA180_0010: return OuterProductRow(mnemonic: .usmops, tile: .s, source: .b)
        case 0xA1A0_0000: return OuterProductRow(mnemonic: .umopa, tile: .s, source: .b)
        case 0xA1A0_0010: return OuterProductRow(mnemonic: .umops, tile: .s, source: .b)
        default: break
        }
        switch e & 0xFFE0_0018 {
        case 0x80C0_0000: return OuterProductRow(mnemonic: .fmopa, tile: .d, source: .d)
        case 0x80C0_0010: return OuterProductRow(mnemonic: .fmops, tile: .d, source: .d)
        case 0xA0C0_0000: return OuterProductRow(mnemonic: .smopa, tile: .d, source: .h)
        case 0xA0C0_0010: return OuterProductRow(mnemonic: .smops, tile: .d, source: .h)
        case 0xA0E0_0000: return OuterProductRow(mnemonic: .sumopa, tile: .d, source: .h)
        case 0xA0E0_0010: return OuterProductRow(mnemonic: .sumops, tile: .d, source: .h)
        case 0xA1C0_0000: return OuterProductRow(mnemonic: .usmopa, tile: .d, source: .h)
        case 0xA1C0_0010: return OuterProductRow(mnemonic: .usmops, tile: .d, source: .h)
        case 0xA1E0_0000: return OuterProductRow(mnemonic: .umopa, tile: .d, source: .h)
        case 0xA1E0_0010: return OuterProductRow(mnemonic: .umops, tile: .d, source: .h)
        default: break
        }
        switch e & 0xFFE0_001E {
        case 0x8180_0008: return OuterProductRow(mnemonic: .fmopa, tile: .h, source: .h)
        case 0x8180_0018: return OuterProductRow(mnemonic: .fmops, tile: .h, source: .h)
        case 0x81A0_0008: return OuterProductRow(mnemonic: .bfmopa, tile: .h, source: .h)
        case 0x81A0_0018: return OuterProductRow(mnemonic: .bfmops, tile: .h, source: .h)
        default: return nil
        }
    }

    /// The `ZAda` tile index for a tile element.
    @inline(__always)
    static func zada(_ e: UInt32, _ tile: ScalarSize) -> UInt8 {
        switch tile {
        case .s: UInt8(e & 0x3)
        case .d: UInt8(e & 0x7)
        default: UInt8(e & 0x1)
        }
    }

    /// Decode an SME outer-product word into an accumulate/subtract-into-`ZA`
    /// record.
    @inline(__always)
    static func decodeOuterProduct(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let row = outerProductRow(e) else { return undefined(e, a) }
        let tileIndex = zada(e, row.tile)
        let znIndex = zn(e), zmIndex = zm(e)
        let pnIndex = pn3(e), pmIndex = pm3(e)
        let tileMask = ZATileMask(tile: tileIndex, element: row.tile)

        let operandCount = sink.emit(.zaTile(index: tileIndex, element: row.tile), govern(pnIndex, .merging), govern(pmIndex, .merging), vec(znIndex, row.source), vec(zmIndex, row.source))
        let reads = vecMask(znIndex).union(vecMask(zmIndex))
        let scalableReads = predRead(pnIndex).union(predRead(pmIndex)).inserting(tileMask)
        let scalableWrites = ScalableRegisterSet.empty.inserting(tileMask)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: row.mnemonic,
            semanticReads: reads,
            category: .sme,
            operandCount: operandCount,
            scalableReads: scalableReads,
            scalableWrites: scalableWrites,
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }
}
