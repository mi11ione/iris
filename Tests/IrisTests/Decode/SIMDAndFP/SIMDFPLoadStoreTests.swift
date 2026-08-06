// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

/// Validates AdvSIMD load/store multiple-structures (LD1/LD2/LD3/LD4 and ST1-4
/// with selem × rpt layouts and no-offset/post-index variants).
@Suite("SIMD/FP / AdvSIMD LD/ST multi-structure")
struct AdvSIMDLoadStoreMultipleStructuresTests {
    @Test func st4MultiStructure_8B_NoOffset() {
        let d = decode(0x0C00_0000)
        #expect(d.mnemonic == .st4)
        #expect(d.memoryAccess == .store)
    }

    @Test func ld4MultiStructure_8B_NoOffset() {
        let d = decode(0x0C40_0000)
        #expect(d.mnemonic == .ld4)
        #expect(d.memoryAccess == .load)
    }

    @Test func st1MultiStructureFourRegs() {
        let d = decode(0x0C00_2000)
        #expect(d.mnemonic == .st1)
    }

    @Test func st3MultiStructure() {
        let d = decode(0x0C00_4000)
        #expect(d.mnemonic == .st3)
    }

    @Test func st1MultiStructureThreeRegs() {
        let d = decode(0x0C00_6000)
        #expect(d.mnemonic == .st1)
    }

    @Test func st1MultiStructureOneReg() {
        let d = decode(0x0C00_7000)
        #expect(d.mnemonic == .st1)
    }

    @Test func st2MultiStructure() {
        let d = decode(0x0C00_8000)
        #expect(d.mnemonic == .st2)
    }

    @Test func st1MultiStructureTwoRegs() {
        let d = decode(0x0C00_A000)
        #expect(d.mnemonic == .st1)
    }

    @Test func st4PostIndexedImmediate() {
        let d = decode(0x0C9F_0000)
        #expect(d.mnemonic == .st4)
    }

    @Test func st4PostIndexedRegister() {
        let d = decode(0x0C83_0000)
        #expect(d.mnemonic == .st4)
    }

    @Test func ld2MultiStructure() {
        let d = decode(0x0C40_8000)
        #expect(d.mnemonic == .ld2)
    }

    @Test func ld3MultiStructure() {
        let d = decode(0x0C40_4000)
        #expect(d.mnemonic == .ld3)
    }

    @Test func reservedOpcodeReturnsUndefined() {
        let d = decode(0x0C00_1000)
        #expect(d.mnemonic == .undefined)
    }

    @Test func ld2WithReservedSize_1D_QZeroIsUndefined() {
        let d = decode(0x0C40_8C00)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD load/store single-structure (LD1/LD2/LD3/LD4 with element
/// subscript) and replicate (LDxR) forms.
@Suite("SIMD/FP / AdvSIMD LD/ST single-structure")
struct AdvSIMDLoadStoreSingleStructureTests {
    @Test func st1SingleStructureByteElement() {
        let d = decode(0x0D00_0000)
        #expect(d.mnemonic == .st1)
    }

    @Test func ld1SingleStructureByteElement() {
        let d = decode(0x0D40_0000)
        #expect(d.mnemonic == .ld1)
    }

    @Test func st2SingleStructureByte() {
        let d = decode(0x0D20_0000)
        #expect(d.mnemonic == .st2)
    }

    @Test func st3SingleStructureByte() {
        let d = decode(0x0D00_2000)
        #expect(d.mnemonic == .st3)
    }

    @Test func st4SingleStructureByte() {
        let d = decode(0x0D20_2000)
        #expect(d.mnemonic == .st4)
    }

    @Test func st1SingleStructureHalfword() {
        let d = decode(0x0D00_4000)
        #expect(d.mnemonic == .st1)
    }

    @Test func st1SingleStructureWord() {
        let d = decode(0x0D00_8000)
        #expect(d.mnemonic == .st1)
    }

    @Test func st1SingleStructureDoubleword() {
        let d = decode(0x0D00_8400)
        #expect(d.mnemonic == .st1)
    }

    @Test func ld1ReplicateByteElement() {
        let d = decode(0x0D40_C000)
        #expect(d.mnemonic == .ld1r)
    }

    @Test func ld2ReplicateByteElement() {
        let d = decode(0x0D60_C000)
        #expect(d.mnemonic == .ld2r)
    }

    @Test func ld3ReplicateByteElement() {
        let d = decode(0x0D40_E000)
        #expect(d.mnemonic == .ld3r)
    }

    @Test func ld4ReplicateByteElement() {
        let d = decode(0x0D60_E000)
        #expect(d.mnemonic == .ld4r)
    }

    @Test func replicateStoreIsUndefined() {
        let d = decode(0x0D00_C000)
        #expect(d.mnemonic == .undefined)
    }

    @Test func singleStructurePostIndexed() {
        let d = decode(0x0D9F_0000)
        #expect(d.mnemonic == .st1)
    }

    @Test func reservedSizeForHalfwordReturnsUndefined() {
        let d = decode(0x0D00_4400)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedSDForDoublewordSEqualsOneReturnsUndefined() {
        let d = decode(0x0D00_9400)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates Scalar SIMD LDR-literal (PC-relative loads).
@Suite("SIMD/FP / Scalar SIMD LDR-literal")
struct ScalarSIMDLoadLiteralTests {
    @Test func ldrSingleLiteral() {
        let d = decode(0x1C00_0000)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands.count == 2)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .scalar(size: .s)),
        ))
    }

    @Test func ldrDoubleLiteral() {
        let d = decode(0x5C00_0000)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .scalar(size: .d)),
        ))
    }

    @Test func ldrQuadLiteral() {
        let d = decode(0x9C00_0000)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .scalar(size: .q)),
        ))
    }

    @Test func reservedOpcReturnsUndefined() {
        let d = decode(0xDC00_0000)
        #expect(d.mnemonic == .undefined)
    }

    @Test func memoryOperandUsesPCBase() {
        let d = decode(0x1C00_0000)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .pc)))
    }

    @Test func memoryAccessIsLoad() {
        let d = decode(0x1C00_0000)
        #expect(d.memoryAccess == .load)
    }
}

/// Validates Scalar SIMD LDP/STP/LDNP/STNP (V=1).
@Suite("SIMD/FP / Scalar SIMD LDP / STP")
struct ScalarSIMDLoadStorePairTests {
    @Test func stnpSinglePair() {
        let d = decode(0x2C00_0400)
        #expect(d.mnemonic == .stnp)
    }

    @Test func ldnpDoublePair() {
        let d = decode(0x6C40_0400)
        #expect(d.mnemonic == .ldnp)
    }

    @Test func stnpQuadPair() {
        let d = decode(0xAC00_0400)
        #expect(d.mnemonic == .stnp)
    }

    @Test func ldpSinglePostIndexed() {
        let d = decode(0x2CC0_0400)
        #expect(d.mnemonic == .ldp)
    }

    @Test func stpDoubleSignedOffset() {
        let d = decode(0x6D00_0400)
        #expect(d.mnemonic == .stp)
    }

    @Test func ldpQuadPreIndexed() {
        let d = decode(0xADC0_0400)
        #expect(d.mnemonic == .ldp)
    }

    @Test func opcElevenNoAllocateDecodesSttnp() {
        let d = decode(0xEC00_0400)
        #expect(d.mnemonic == .sttnp)
    }
}

/// Validates Scalar SIMD LDR/STR (unsigned offset, V=1).
@Suite("SIMD/FP / Scalar SIMD LDR / STR unsigned offset")
struct ScalarSIMDLoadStoreUnsignedOffsetTests {
    @Test func strSingleUnsignedOffset() {
        let d = decode(0xBD00_0000)
        #expect(d.mnemonic == .str)
    }

    @Test func ldrSingleUnsignedOffset() {
        let d = decode(0xBD40_0000)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrDoubleUnsignedOffset() {
        let d = decode(0xFD40_0000)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrByteUnsignedOffset() {
        let d = decode(0x3D40_0000)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrHalfUnsignedOffset() {
        let d = decode(0x7D40_0000)
        #expect(d.mnemonic == .ldr)
    }

    @Test func strQuadUnsignedOffset() {
        let d = decode(0x3D80_0000)
        #expect(d.mnemonic == .str)
    }

    @Test func ldrQuadUnsignedOffset() {
        let d = decode(0x3DC0_0000)
        #expect(d.mnemonic == .ldr)
    }

    @Test func reservedSizeOpcCombinationReturnsUndefined() {
        let d = decode(0x7D80_0000)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates Scalar SIMD LDR/STR/LDUR/STUR (indexed forms.
@Suite("SIMD/FP / Scalar SIMD LDR / STR indexed")
struct ScalarSIMDLoadStoreIndexedTests {
    @Test func sturSingleZeroOffset() {
        let d = decode(0xBC00_0000)
        #expect(d.mnemonic == .stur)
    }

    @Test func ldurSingleZeroOffset() {
        let d = decode(0xBC40_0000)
        #expect(d.mnemonic == .ldur)
    }

    @Test func ldurDoubleZeroOffset() {
        let d = decode(0xFC40_0000)
        #expect(d.mnemonic == .ldur)
    }

    @Test func sturByte() {
        let d = decode(0x3C00_0000)
        #expect(d.mnemonic == .stur)
    }

    @Test func sturQuad() {
        let d = decode(0x3C80_0000)
        #expect(d.mnemonic == .stur)
    }

    @Test func ldrPostIndexed() {
        let d = decode(0xBC40_0400)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrPreIndexed() {
        let d = decode(0xBC40_0C00)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrRegisterOffset() {
        let d = decode(0xBC61_6800)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrRegisterOffsetWithUXTW() {
        let d = decode(0xBC61_4800)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrRegisterOffsetWithSXTW() {
        let d = decode(0xBC61_C800)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrRegisterOffsetWithSXTX() {
        let d = decode(0xBC61_E800)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrRegisterOffsetWithReservedOptionReturnsUndefined() {
        let d = decode(0xBC61_0800)
        #expect(d.mnemonic == .undefined)
    }

    @Test func ldrRegisterOffsetSBitSetScalesShift() {
        let d = decode(0xBC61_7800)
        #expect(d.mnemonic == .ldr)
    }

    @Test func reservedSizeOpcCombinationReturnsUndefined() {
        let d = decode(0x7C80_0000)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates the FEAT_LSUI unprivileged SIMD pair forms (LDTP/STTP/
/// LDTNP/STTNP of Q registers) across all four indexing variants.
@Suite("SIMD/FP / FEAT_LSUI SIMD pair forms")
struct ScalarSIMDLSUIPairTests {
    @Test func unprivilegedPairsDecodeEveryIndexingVariant() {
        let rows: [(word: UInt32, mnemonic: Mnemonic, text: String)] = [
            (0xEC40_0440, .ldtnp, "ldtnp q0, q1, [x2]"),
            (0xEC00_0440, .sttnp, "sttnp q0, q1, [x2]"),
            (0xECC1_0440, .ldtp, "ldtp q0, q1, [x2], #32"),
            (0xEC81_0440, .sttp, "sttp q0, q1, [x2], #32"),
            (0xED41_0440, .ldtp, "ldtp q0, q1, [x2, #32]"),
            (0xED00_0440, .sttp, "sttp q0, q1, [x2]"),
            (0xEDC1_0440, .ldtp, "ldtp q0, q1, [x2, #32]!"),
            (0xED81_0440, .sttp, "sttp q0, q1, [x2, #32]!"),
        ]
        for row in rows {
            let d = decode(row.word)
            #expect(d.mnemonic == row.mnemonic, "0x\(String(row.word, radix: 16))")
            #expect(d.category == .simdAndFP)
            #expect(d.text == row.text)
        }
    }
}
