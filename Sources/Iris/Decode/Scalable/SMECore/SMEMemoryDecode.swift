// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SMECoreDecode {
    /// Decode an SME `ZA` load/store word.
    @inline(__always)
    static func decodeMemory(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if let row = ld1st1Row(e) { return decodeTileMemory(e, a, row, &sink) }
        switch e & 0xFFFF_9C10 {
        case 0xE100_0000: return decodeLdrStrZA(e, a, .ldr, isStore: false, &sink)
        case 0xE120_0000: return decodeLdrStrZA(e, a, .str, isStore: true, &sink)
        default: return undefined(e, a)
        }
    }

    /// One LD1/ST1 tile encoding.
    struct TileMemoryRow {
        let mnemonic: Mnemonic
        let element: ScalarSize
        let isLoad: Bool
    }

    /// The LD1/ST1 tile row for `e`, or `nil` for a hole in the 111 cells.
    @inline(__always)
    static func ld1st1Row(_ e: UInt32) -> TileMemoryRow? {
        switch e & 0xFFE0_0010 {
        case 0xE000_0000: TileMemoryRow(mnemonic: .ld1b, element: .b, isLoad: true)
        case 0xE020_0000: TileMemoryRow(mnemonic: .st1b, element: .b, isLoad: false)
        case 0xE040_0000: TileMemoryRow(mnemonic: .ld1h, element: .h, isLoad: true)
        case 0xE060_0000: TileMemoryRow(mnemonic: .st1h, element: .h, isLoad: false)
        case 0xE080_0000: TileMemoryRow(mnemonic: .ld1w, element: .s, isLoad: true)
        case 0xE0A0_0000: TileMemoryRow(mnemonic: .st1w, element: .s, isLoad: false)
        case 0xE0C0_0000: TileMemoryRow(mnemonic: .ld1d, element: .d, isLoad: true)
        case 0xE0E0_0000: TileMemoryRow(mnemonic: .st1d, element: .d, isLoad: false)
        case 0xE1C0_0000: TileMemoryRow(mnemonic: .ld1q, element: .q, isLoad: true)
        case 0xE1E0_0000: TileMemoryRow(mnemonic: .st1q, element: .q, isLoad: false)
        default: nil
        }
    }

    /// Decode an LD1/ST1 tile-slice access.
    @inline(__always)
    static func decodeTileMemory(_ e: UInt32, _ a: UInt64, _ row: TileMemoryRow, _ sink: inout OperandSink) -> DecodedDraft {
        let slice = tileSlice(e, row.element, UInt8(e & 0xF))
        let pg = pn3(e)
        let rnIndex = rn(e), rmIndex = rm(e)
        let hasIndex = rmIndex != 31
        let memory = ScalableMemoryOperand(
            base: .gpr(rnIndex == 31 ? .sp() : .x(rnIndex)),
            scalarIndex: hasIndex ? .x(rmIndex) : nil,
            scaleShift: row.element.rawValue,
        )
        let operandCount = sink.emit(.zaTileSlice(slice), govern(pg, row.isLoad ? .zeroing : .none), .scalableMemory(memory))
        let tileMask = slice.zaMask
        var reads = gprMask(rnIndex).union(gprMask(12 &+ rv(e)))
        if hasIndex { reads = reads.union(gprMask(rmIndex)) }
        if row.isLoad {
            return DecodedDraft(
                address: a, encoding: e, mnemonic: row.mnemonic,
                semanticReads: reads,
                memoryAccess: .load,
                category: .sme,
                operandCount: operandCount,
                scalableReads: predRead(pg),
                scalableWrites: ScalableRegisterSet.empty.inserting(tileMask),
                scalableEffect: [.readsStreamingMode, .partialWrite],
            )
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: row.mnemonic,
            semanticReads: reads,
            memoryAccess: .store,
            category: .sme,
            operandCount: operandCount,
            scalableReads: predRead(pg).inserting(tileMask),
            scalableEffect: [.readsStreamingMode],
        )
    }

    /// Decode `LDR`/`STR ZA[Wv, imm], [Xn{, #imm, mul vl}]`.
    @inline(__always)
    static func decodeLdrStrZA(_ e: UInt32, _ a: UInt64, _ mnemonic: Mnemonic, isStore: Bool, _ sink: inout OperandSink) -> DecodedDraft {
        let selectIndex = 12 &+ rv(e)
        let rnIndex = rn(e)
        let imm4 = UInt8(e & 0xF)
        let arrayVector = ZAArrayVectorOperand(
            selectRegister: .w(selectIndex), offset: imm4,
        )
        let memory = ScalableMemoryOperand(
            base: .gpr(rnIndex == 31 ? .sp() : .x(rnIndex)),
            displacement: Int32(imm4),
            mulVL: true,
        )
        let operandCount = sink.emit(.zaArrayVector(arrayVector), .scalableMemory(memory))
        let reads = gprMask(rnIndex).union(gprMask(selectIndex))
        if isStore {
            return DecodedDraft(
                address: a, encoding: e, mnemonic: mnemonic,
                semanticReads: reads,
                memoryAccess: .store,
                category: .sme,
                operandCount: operandCount,
                scalableReads: ScalableRegisterSet.empty.inserting(.whole),
            )
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: reads,
            memoryAccess: .load,
            category: .sme,
            operandCount: operandCount,
            scalableWrites: ScalableRegisterSet.empty.inserting(.whole),
            scalableEffect: [.partialWrite],
        )
    }
}
