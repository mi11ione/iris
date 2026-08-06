// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

private func text(_ encoding: UInt32) -> String {
    decode(encoding).text
}

private struct TileMemoryCase {
    let encoding: UInt32
    let mnemonic: Mnemonic
    let name: String
    let element: String
    let isLoad: Bool
    let shift: Int
}

private let tileMemory: [TileMemoryCase] = [
    TileMemoryCase(encoding: 0xE000_0000, mnemonic: .ld1b, name: "ld1b", element: "b", isLoad: true, shift: 0),
    TileMemoryCase(encoding: 0xE020_0000, mnemonic: .st1b, name: "st1b", element: "b", isLoad: false, shift: 0),
    TileMemoryCase(encoding: 0xE040_0000, mnemonic: .ld1h, name: "ld1h", element: "h", isLoad: true, shift: 1),
    TileMemoryCase(encoding: 0xE060_0000, mnemonic: .st1h, name: "st1h", element: "h", isLoad: false, shift: 1),
    TileMemoryCase(encoding: 0xE080_0000, mnemonic: .ld1w, name: "ld1w", element: "s", isLoad: true, shift: 2),
    TileMemoryCase(encoding: 0xE0A0_0000, mnemonic: .st1w, name: "st1w", element: "s", isLoad: false, shift: 2),
    TileMemoryCase(encoding: 0xE0C0_0000, mnemonic: .ld1d, name: "ld1d", element: "d", isLoad: true, shift: 3),
    TileMemoryCase(encoding: 0xE0E0_0000, mnemonic: .st1d, name: "st1d", element: "d", isLoad: false, shift: 3),
    TileMemoryCase(encoding: 0xE1C0_0000, mnemonic: .ld1q, name: "ld1q", element: "q", isLoad: true, shift: 4),
    TileMemoryCase(encoding: 0xE1E0_0000, mnemonic: .st1q, name: "st1q", element: "q", isLoad: false, shift: 4),
]

private func withIndex(_ base: UInt32, _ rm: UInt32) -> UInt32 {
    base | (rm << 16)
}

private let noIndex: UInt32 = 31 << 16

private func memoryOperand(_ draft: Instruction) -> ScalableMemoryOperand? {
    for operand in draft.operands {
        if case let .scalableMemory(memory) = operand { return memory }
    }
    return nil
}

private func arrayVectorOperand(_ draft: Instruction) -> ZAArrayVectorOperand? {
    for operand in draft.operands {
        if case let .zaArrayVector(vector) = operand { return vector }
    }
    return nil
}

private func element(of row: TileMemoryCase) -> ScalarSize {
    switch row.element {
    case "b": .b
    case "h": .h
    case "s": .s
    case "d": .d
    default: .q
    }
}

/// Validates the LD1/ST1 tile-slice decoder.
@Suite("SME core / LD1 and ST1 tile-slice decode")
struct SMETileMemoryDecodeTests {
    @Test func everyRowResolvesToItsMnemonicAndBracesItsSlice() {
        for row in tileMemory {
            let draft = decode(withIndex(row.encoding, 31))
            #expect(draft.mnemonic == row.mnemonic, "\(row.name)")
            #expect(draft.category == .sme, "\(row.name)")
            let qualifier = row.isLoad ? "p0/z" : "p0"
            #expect(
                text(withIndex(row.encoding, 31)) == "\(row.name) {za0h.\(row.element)[w12, 0]}, \(qualifier), [x0]",
                "\(row.name)",
            )
        }
    }

    @Test func aPresentIndexRegisterCarriesTheElementScaledShift() {
        for row in tileMemory {
            let shiftText = row.shift > 0 ? ", lsl #\(row.shift)" : ""
            let qualifier = row.isLoad ? "p0/z" : "p0"
            #expect(
                text(withIndex(row.encoding, 7))
                    == "\(row.name) {za0h.\(row.element)[w12, 0]}, \(qualifier), [x0, x7\(shiftText)]",
                "\(row.name)",
            )
        }
    }

    @Test func anIndexRegisterOfThirtyOneMeansNoIndexNotZeroRegister() {
        for rm in UInt32(0) ... 30 {
            #expect(text(withIndex(0xE000_0000, rm)) == "ld1b {za0h.b[w12, 0]}, p0/z, [x0, x\(rm)]", "rm \(rm)")
        }
        #expect(text(withIndex(0xE000_0000, 31)) == "ld1b {za0h.b[w12, 0]}, p0/z, [x0]")
    }

    @Test func aBaseRegisterOfThirtyOneRendersAsTheStackPointer() {
        #expect(text(0xE000_0000 | noIndex | (31 << 5)) == "ld1b {za0h.b[w12, 0]}, p0/z, [sp]")
        #expect(text(0xE1E0_0000 | (3 << 16) | (31 << 5)) == "st1q {za0h.q[w12, 0]}, p0, [sp, x3, lsl #4]")
    }

    @Test func theByteTileIsAlwaysZeroWhileWiderTilesUseTheNibble() {
        for nibble in UInt32(0) ... 15 {
            #expect(
                text(0xE000_0000 | noIndex | nibble) == "ld1b {za0h.b[w12, \(nibble)]}, p0/z, [x0]",
                "nibble \(nibble)",
            )
        }
        for nibble in UInt32(0) ... 15 {
            #expect(
                text(0xE1C0_0000 | noIndex | nibble) == "ld1q {za\(nibble)h.q[w12, 0]}, p0/z, [x0]",
                "nibble \(nibble)",
            )
        }
    }

    @Test func theVerticalBitSelectsAVerticalSlice() {
        for row in tileMemory {
            let qualifier = row.isLoad ? "p0/z" : "p0"
            #expect(
                text(withIndex(row.encoding, 31) | 0x8000)
                    == "\(row.name) {za0v.\(row.element)[w12, 0]}, \(qualifier), [x0]",
                "\(row.name)",
            )
        }
    }

    @Test func theSelectAndPredicateFieldsRender() {
        for rv in UInt32(0) ... 3 {
            #expect(text(0xE000_0000 | noIndex | (rv << 13)) == "ld1b {za0h.b[w\(12 + rv), 0]}, p0/z, [x0]")
        }
        for pg in UInt32(0) ... 7 {
            #expect(text(0xE000_0000 | noIndex | (pg << 10)) == "ld1b {za0h.b[w12, 0]}, p\(pg)/z, [x0]")
            #expect(text(0xE020_0000 | noIndex | (pg << 10)) == "st1b {za0h.b[w12, 0]}, p\(pg), [x0]")
        }
    }

    @Test func onlyTheArrayFormCarriesAnArrayVectorOperand() {
        for row in tileMemory {
            let draft = decode(withIndex(row.encoding, 31))
            #expect(memoryOperand(draft) != nil, "\(row.name)")
            #expect(arrayVectorOperand(draft) == nil, "\(row.name)")
        }
        let fill = decode(0xE100_0000)
        #expect(memoryOperand(fill) != nil)
        #expect(arrayVectorOperand(fill) != nil)
        let move = decode(0xC000_0000)
        #expect(memoryOperand(move) == nil)
        #expect(arrayVectorOperand(move) == nil)
    }

    @Test func aTileMemoryHoleFallsThroughToUndefined() {
        for encoding: UInt32 in [
            0xE000_0010, 0xE0C0_0010, 0xE180_0000, 0xE1A0_0000, 0xE140_0000, 0xE160_0000,
        ] {
            let draft = decode(encoding)
            #expect(draft.mnemonic == .undefined, "0x\(String(encoding, radix: 16))")
            #expect(draft.category == .sme)
            #expect(draft.operands.isEmpty)
            #expect(text(encoding) == ".long 0x\(String(encoding, radix: 16))")
        }
    }
}

/// Validates the LD1/ST1 tile-slice semantics.
@Suite("SME core / LD1 and ST1 tile-slice semantics")
struct SMETileMemorySemanticsTests {
    @Test func loadsWriteTheTileAndStoresReadIt() {
        for row in tileMemory {
            let draft = decode(withIndex(row.encoding, 31) | 0x8)
            let tileIndex: UInt8 = switch element(of: row) {
            case .b: 0
            case .h: 1
            case .s: 2
            case .d: 4
            case .q: 8
            }
            let tile = ZATileMask(tile: tileIndex, element: element(of: row))
            if row.isLoad {
                #expect(draft.memoryAccess == .load, "\(row.name)")
                #expect(draft.scalableWrites.zaMask == tile, "\(row.name)")
                #expect(draft.scalableReads.zaMask == .none, "\(row.name)")
                #expect(draft.scalableEffect == [.readsStreamingMode, .partialWrite], "\(row.name)")
            } else {
                #expect(draft.memoryAccess == .store, "\(row.name)")
                #expect(draft.scalableReads.zaMask == tile, "\(row.name)")
                #expect(draft.scalableWrites.zaMask == .none, "\(row.name)")
                #expect(draft.scalableEffect == [.readsStreamingMode], "\(row.name)")
            }
        }
    }

    @Test func theBaseAndSelectRegistersAreAlwaysRead() {
        let draft = decode(0xE000_0000 | noIndex | (3 << 13) | (19 << 5))
        #expect(draft.semanticReads.contains(RegisterRef.x(19)))
        #expect(draft.semanticReads.contains(RegisterRef.w(15)))
        #expect(draft.semanticReads.count == 2)
    }

    @Test func theIndexRegisterIsReadOnlyWhenPresent() {
        let indexed = decode(withIndex(0xE000_0000, 7) | (19 << 5))
        #expect(indexed.semanticReads.contains(RegisterRef.x(7)))
        #expect(indexed.semanticReads.count == 3)
        let unindexed = decode(withIndex(0xE000_0000, 31) | (19 << 5))
        #expect(!unindexed.semanticReads.contains(RegisterRef.sp()))
        #expect(unindexed.semanticReads.count == 2)
    }

    @Test func aStackPointerBaseIsReadAtItsOwnSlot() {
        let draft = decode(0xE000_0000 | noIndex | (31 << 5))
        #expect(draft.semanticReads.contains(RegisterRef.sp()))
    }

    @Test func theGoverningPredicateIsAScalableReadInBothDirections() {
        for pg in UInt32(0) ... 7 {
            #expect(decode(0xE000_0000 | noIndex | (pg << 10)).scalableReads.containsPredicate(UInt8(pg)))
            #expect(decode(0xE020_0000 | noIndex | (pg << 10)).scalableReads.containsPredicate(UInt8(pg)))
        }
    }

    @Test func theMemoryOperandCarriesTheStructureNotTheAddress() {
        let memory = memoryOperand(decode(withIndex(0xE0C0_0000, 5) | (9 << 5)))
        #expect(memory?.base == .gpr(.x(9)))
        #expect(memory?.scalarIndex == RegisterRef.x(5))
        #expect(memory?.scaleShift == 3)
        #expect(memory?.displacement == 0)
        #expect(memory?.mulVL == false)
        #expect(memory?.index == nil)
        #expect(memory?.indexExtend == ExtendKind.none)
    }
}

/// Validates the LDR/STR ZA array fill and spill.
@Suite("SME core / LDR and STR ZA decode")
struct SMELdrStrZADecodeTests {
    @Test func bothDirectionsResolveAndRenderTheSuffixLessArrayVector() {
        #expect(decode(0xE100_0000).mnemonic == .ldr)
        #expect(decode(0xE120_0000).mnemonic == .str)
        #expect(text(0xE100_0000) == "ldr za[w12, 0], [x0]")
        #expect(text(0xE120_0000) == "str za[w12, 0], [x0]")
    }

    @Test func theSingleImmediateFillsBothPositions() {
        for imm in UInt32(1) ... 15 {
            #expect(text(0xE100_0000 | imm) == "ldr za[w12, \(imm)], [x0, #\(imm), mul vl]", "imm \(imm)")
            #expect(text(0xE120_0000 | imm) == "str za[w12, \(imm)], [x0, #\(imm), mul vl]", "imm \(imm)")
        }
    }

    @Test func aZeroDisplacementIsSuppressedButTheVectorSelectIsNot() {
        #expect(text(0xE100_0000) == "ldr za[w12, 0], [x0]")
        #expect(text(0xE100_0001) == "ldr za[w12, 1], [x0, #1, mul vl]")
    }

    @Test func theSelectAndBaseRegistersRender() {
        for rv in UInt32(0) ... 3 {
            #expect(text(0xE100_0000 | (rv << 13)) == "ldr za[w\(12 + rv), 0], [x0]")
        }
        for rn in UInt32(0) ... 30 {
            #expect(text(0xE100_0000 | (rn << 5)) == "ldr za[w12, 0], [x\(rn)]", "rn \(rn)")
        }
        #expect(text(0xE100_0000 | (31 << 5)) == "ldr za[w12, 0], [sp]")
        #expect(text(0xE120_0000 | (3 << 13) | (31 << 5) | 7) == "str za[w15, 7], [sp, #7, mul vl]")
    }

    @Test func theArrayVectorOperandHasNoElementSize() {
        let vector = arrayVectorOperand(decode(0xE100_0000 | (2 << 13) | 5))
        #expect(vector?.element == nil)
        #expect(vector?.selectRegister == RegisterRef.w(14))
        #expect(vector?.offset == 5)
        #expect(vector?.offsetHigh == nil)
        #expect(vector?.group == ZAArrayVectorOperand.VectorGroup.none)
        #expect(vector?.zaMask == .whole)
    }

    @Test func theWholeArrayIsTouchedInTheCorrespondingDirection() {
        let fill = decode(0xE100_0000)
        #expect(fill.memoryAccess == .load)
        #expect(fill.scalableWrites.zaMask == .whole)
        #expect(fill.scalableReads.zaMask == .none)
        let spill = decode(0xE120_0000)
        #expect(spill.memoryAccess == .store)
        #expect(spill.scalableReads.zaMask == .whole)
        #expect(spill.scalableWrites.zaMask == .none)
    }

    @Test func neitherDirectionIsStreamingGated() {
        #expect(decode(0xE100_0000).scalableEffect == [.partialWrite])
        #expect(decode(0xE120_0000).scalableEffect == .none)
    }

    @Test func theBaseAndSelectRegistersAreSemanticReads() {
        let draft = decode(0xE100_0000 | (3 << 13) | (19 << 5))
        #expect(draft.semanticReads.contains(RegisterRef.x(19)))
        #expect(draft.semanticReads.contains(RegisterRef.w(15)))
        #expect(draft.semanticReads.count == 2)
        #expect(draft.semanticWrites.isEmpty)
    }

    @Test func theMemoryOperandIsVectorLengthScaled() {
        let memory = memoryOperand(decode(0xE100_0000 | (31 << 5) | 9))
        #expect(memory?.base == .gpr(.sp()))
        #expect(memory?.scalarIndex == nil)
        #expect(memory?.displacement == 9)
        #expect(memory?.mulVL == true)
        #expect(memory?.scaleShift == 0)
    }

    @Test func theZT0FillAndSpillDecodeAsZT0NotAsZA() {
        for (encoding, mnemonic, label) in [
            (UInt32(0xE11F_8000), Mnemonic.ldr, "ldr zt0"),
            (0xE13F_8000, .str, "str zt0"),
        ] {
            let d = Iris.decode(encoding)
            #expect(d.mnemonic == mnemonic, "\(label)")
            #expect(d.text.contains("zt0"), "\(label) rendered `\(d.text)`")
        }
    }

    @Test func anArrayMemoryHoleFallsThroughToUndefined() {
        for encoding: UInt32 in [0xE100_0010, 0xE100_0400, 0xE100_8000, 0xE140_0000] {
            #expect(decode(encoding).mnemonic == .undefined, "0x\(String(encoding, radix: 16))")
        }
    }
}
