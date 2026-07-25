// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// SME ZA load/store decoder (cell 111). LD1B/H/W/D/Q and
// ST1B/H/W/D/Q move one predicated tile slice to/from memory at a
// register-offset address `[Xn{, Xm{, lsl #k}}]` (Rm=31 ⇒ no index; the shift
// is the access-element log2 size, so byte forms carry none). LDR/STR ZA fill
// and spill one `ZA` array vector at `[Xn{, #imm, mul vl}]`, where the single
// imm4 field is both the vector-select offset and the memory offset. Records
// operand structure only — computing the effective address is the caller's.

extension SMECoreDecode {
    /// Decode an SME `ZA` load/store word.
    @inline(__always)
    static func decodeMemory(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        if let row = ld1st1Row(e) { return decodeTileMemory(e, a, row) }
        switch e & 0xFFFF_9C10 {
        case 0xE100_0000: return decodeLdrStrZA(e, a, .ldr, isStore: false)
        case 0xE120_0000: return decodeLdrStrZA(e, a, .str, isStore: true)
        default: return undefined(e, a)
        }
    }

    // MARK: - LD1 / ST1 tile slices

    /// One LD1/ST1 tile encoding: mnemonic, tile element, and load-vs-store.
    struct TileMemoryRow {
        let mnemonic: Mnemonic
        let element: ScalarSize
        let isLoad: Bool
    }

    /// The LD1/ST1 tile row for `e`, or `nil` for a hole in the 111 cells.
    @inline(__always)
    static func ld1st1Row(_ e: UInt32) -> TileMemoryRow? {
        switch e & 0xFFE0_0010 { // Rm (bits[20:16]) and V (bit15) free
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

    /// Decode an LD1/ST1 tile-slice access. The register-offset `Rm` (bits
    /// [20:16]) is a GPR index unless 31 (no index); the shift is the access
    /// element's log2 byte size (0 for `.b`).
    @inline(__always)
    static func decodeTileMemory(_ e: UInt32, _ a: UInt64, _ row: TileMemoryRow) -> DecodedDraft {
        let slice = tileSlice(e, row.element, UInt8(e & 0xF))
        let pg = pn3(e)
        let rnIndex = rn(e), rmIndex = rm(e)
        let hasIndex = rmIndex != 31
        let memory = ScalableMemoryOperand(
            base: .gpr(rnIndex == 31 ? .sp() : .x(rnIndex)),
            scalarIndex: hasIndex ? .x(rmIndex) : nil,
            scaleShift: row.element.rawValue,
        )
        // Load: governing predicate is zeroing (`/z`); store: bare (`Pg`).
        let operands: [Operand] = [
            .zaTileSlice(slice),
            govern(pg, row.isLoad ? .zeroing : .none),
            .scalableMemory(memory),
        ]
        let tileMask = slice.zaMask
        var reads = gprMask(rnIndex).union(gprMask(12 &+ rv(e)))
        if hasIndex { reads = reads.union(gprMask(rmIndex)) }
        if row.isLoad {
            return DecodedDraft(
                address: a, encoding: e, mnemonic: row.mnemonic,
                semanticReads: reads,
                memoryAccess: .load,
                category: .sme,
                operands: operands,
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
            operands: operands,
            scalableReads: predRead(pg).inserting(tileMask),
            scalableEffect: [.readsStreamingMode],
        )
    }

    // MARK: - LDR / STR ZA (array vector fill / spill)

    /// Decode `LDR`/`STR ZA[Wv, imm], [Xn{, #imm, mul vl}]`. The imm4 field
    /// (bits[3:0]) is both the vector-select offset and the memory offset;
    /// non-streaming-safe (no `readsStreamingMode`).
    @inline(__always)
    static func decodeLdrStrZA(_ e: UInt32, _ a: UInt64, _ mnemonic: Mnemonic, isStore: Bool) -> DecodedDraft {
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
        let operands: [Operand] = [.zaArrayVector(arrayVector), .scalableMemory(memory)]
        let reads = gprMask(rnIndex).union(gprMask(selectIndex))
        if isStore {
            return DecodedDraft(
                address: a, encoding: e, mnemonic: mnemonic,
                semanticReads: reads,
                memoryAccess: .store,
                category: .sme,
                operands: operands,
                scalableReads: ScalableRegisterSet.empty.inserting(.whole),
            )
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: reads,
            memoryAccess: .load,
            category: .sme,
            operands: operands,
            scalableWrites: ScalableRegisterSet.empty.inserting(.whole),
            scalableEffect: [.partialWrite],
        )
    }
}
