// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

private func decodeLS(_ encoding: UInt32) -> Instruction {
    decode(encoding, at: 0)
}

/// Validates that malformed and reserved encodings produce UNDEFINED across
/// every SIMD/FP sub-decoder, each test hitting one guard.
@Suite("SIMD/FP / Reserved encoding behaviour")
struct SIMDFPReservedEncodingTests {
    @Test func extractOp2NonZeroIsUndefined() {
        let d = decode(0x2E42_0820)
        #expect(d.mnemonic == .undefined)
    }

    @Test func permuteWithD1ArrangementIsUndefined() {
        let d = decode(0x0EC2_1820)
        #expect(d.mnemonic == .undefined)
    }

    @Test func dupGeneralDElementQZeroIsUndefined() {
        let d = decode(0x0E08_0C20)
        #expect(d.mnemonic == .undefined)
    }

    @Test func dupElementWithImm5Bit4OnlyIsUndefined() {
        let d = decode(0x0E10_0420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func dupScalarWithImm5Bit4OnlyIsUndefined() {
        let d = decode(0x5E10_0420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func scalarTierTwoRegMiscReservedBits20_17IsUndefined() {
        let d = decode(0x5EE2_8820)
        #expect(d.mnemonic == .undefined)
    }

    @Test func vectorThreeSameU1Opcode10111IsUndefined() {
        let d = decode(0x2E22_BC20)
        #expect(d.mnemonic == .undefined)
    }

    @Test func vectorNonThreeArgBit15OneBit10ZeroReserved() {
        let d = decode(0x0E00_8000)
        #expect(d.mnemonic == .undefined)
    }

    @Test func singleStructureReplicateStore111IsUndefined() {
        let d = decodeLS(0x0D00_E000)
        #expect(d.mnemonic == .undefined)
    }

    @Test func vectorTwoRegMiscFrint32xDecodes() {
        let d = decode(0x2E21_E820)
        #expect(d.mnemonic == .frint32x)
    }

    @Test func shaddOf_2DIsReserved() {
        let d = decode(0x4EE2_0420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func singleStructurePostIndexedRegisterRm() {
        let d = decodeLS(0x0D83_0000)
        #expect(d.mnemonic == .st1)
        #expect(d.semanticReads.contains(.x(3)))
    }

    @Test func ld3SingleStructureHalfwordElement() {
        let d = decodeLS(0x0D40_6000)
        #expect(d.mnemonic == .ld3)
    }

    @Test func ld4SingleStructureHalfwordElement() {
        let d = decodeLS(0x0D60_6000)
        #expect(d.mnemonic == .ld4)
    }

    @Test func st3SingleStructureWordElement() {
        let d = decodeLS(0x0D00_A000)
        #expect(d.mnemonic == .st3)
    }

    @Test func st4SingleStructureWordElement() {
        let d = decodeLS(0x0D20_A000)
        #expect(d.mnemonic == .st4)
    }

    @Test func ld4ReplicateAllLanes() {
        let d = decodeLS(0x0D60_E000)
        #expect(d.mnemonic == .ld4r)
    }

    @Test func shiftByImmediateHalfElement() {
        let d = decode(0x0F17_0420)
        #expect(d.mnemonic == .sshr)
    }

    @Test func fmovImmediate2DWithQZeroIsUndefined() {
        let d = decode(0x2F00_F400)
        #expect(d.mnemonic == .undefined)
    }

    @Test func fpIntegerConversionUnmatchedReturnsUndefined() {
        let d = decode(0x9EEC_0020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func fpScalarBits1110Zero00WithoutCompareOrImmediateIsUndefined() {
        let d = decode(0x1E60_6020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedShapeWordsAcrossTheFamilyDecodeUndefined() {
        let words: [UInt32] = [
            0x0F00_9C20,
            0x5FC0_0420,
            0x5F08_E420,
            0x5F48_9420,
            0x5E20_8820,
            0x5EE1_4820,
            0x5F42_1020,
            0x5FE2_1020,
            0x0F88_0420,
            0x0F48_9420,
            0x0F08_E420,
            0x0EE0_B820,
            0x2EE2_3C20,
            0x6F42_B020,
            0x6FA2_3020,
            0x0E70_C820,
            0x2E30_C820,
            0x9F02_0C20,
            0x1E66_0020,
            0x3E21_2020,
            0x9E21_2020,
            0x1EE8_4020,
            0xBCC0_0420,
            0x8C40_7000,
            0x0C60_7000,
            0x0C41_7000,
            0x0C00_1000,
            0x8D40_8420,
            0x0D42_0000,
            0x0D40_D000,
            0x0D40_8800,
            0x0D00_C000,
            0x6F03_FE00,
            0x5E22_3420,
            0x0EA2_E420,
            0x3C40_0820,
        ]
        for word in words {
            let d = decode(word)
            #expect(d.isUndefined, "0x\(String(word, radix: 16))")
            #expect(d.encoding == word)
        }
    }

    @Test func vectorNonThreeArgBit15SetBit10ClearReservedIsUndefined() {
        let d = decode(0x0E00_8000)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
        #expect(d.encoding == 0x0E00_8000)
    }
}

/// Validates sign extension via negative imm immediates in V=1 L/S classes.
@Suite("SIMD/FP / V=1 L/S negative immediates")
struct SIMDFPNegativeImmediateTests {
    @Test func ldrLiteralNegativeOffset() {
        let d = decode(0x1CFF_FFE0, at: 0)
        #expect(d.mnemonic == .ldr)
    }

    @Test func sturNegativeImm9() {
        let d = decode(0xBC1F_F000, at: 0)
        #expect(d.mnemonic == .stur)
    }

    @Test func stpNegativeImm7() {
        let d = decode(0x2D3F_8400, at: 0)
        #expect(d.mnemonic == .stp)
    }
}

/// Validates simdfpGprOperand with encoding=31.
@Suite("SIMD/FP / GPR encoding 31 mapping")
struct SIMDFPGprEncoding31Tests {
    @Test func ldrWithSPBase() {
        let d = decode(0xBD40_03E0, at: 0)
        #expect(d.mnemonic == .ldr)
    }

    @Test func scvtfFixedWithWZRSource() {
        let d = decode(0x1E02_843E)
        #expect(d.mnemonic == .scvtf)
    }
}
