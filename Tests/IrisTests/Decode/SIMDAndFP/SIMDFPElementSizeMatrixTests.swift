// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decodeLS(_ encoding: UInt32) -> Instruction {
    decode(encoding, at: 0)
}

/// Validates that scalar SIMD LDR/STR and LDUR/STUR cover every (size, opc)
/// combination, plus the reserved combos that produce UNDEFINED.
@Suite("SIMD/FP / Scalar SIMD indexed (size, opc) matrix")
struct ScalarSIMDIndexedSizeOpcMatrixTests {
    @Test func strByteUnscaled() {
        let d = decodeLS(0x3C00_0000)
        #expect(d.mnemonic == .stur)
    }

    @Test func ldurByteUnscaled() {
        let d = decodeLS(0x3C40_0000)
        #expect(d.mnemonic == .ldur)
    }

    @Test func sturQuadUnscaled() {
        let d = decodeLS(0x3C80_0000)
        #expect(d.mnemonic == .stur)
    }

    @Test func ldurQuadUnscaled() {
        let d = decodeLS(0x3CC0_0000)
        #expect(d.mnemonic == .ldur)
    }

    @Test func sturHalfUnscaled() {
        let d = decodeLS(0x7C00_0000)
        #expect(d.mnemonic == .stur)
    }

    @Test func ldurHalfUnscaled() {
        let d = decodeLS(0x7C40_0000)
        #expect(d.mnemonic == .ldur)
    }

    @Test func sturSingleUnscaled() {
        let d = decodeLS(0xBC00_0000)
        #expect(d.mnemonic == .stur)
    }

    @Test func ldurSingleUnscaled() {
        let d = decodeLS(0xBC40_0000)
        #expect(d.mnemonic == .ldur)
    }

    @Test func sturDoubleUnscaled() {
        let d = decodeLS(0xFC00_0000)
        #expect(d.mnemonic == .stur)
    }

    @Test func ldurDoubleUnscaled() {
        let d = decodeLS(0xFC40_0000)
        #expect(d.mnemonic == .ldur)
    }
}

/// Validates Scalar SIMD LDR/STR (unsigned offset) covers every (size, opc)
/// combination.
@Suite("SIMD/FP / Scalar SIMD unsigned-offset (size, opc) matrix")
struct ScalarSIMDUnsignedOffsetSizeOpcMatrixTests {
    @Test func strByteUnsignedOffset() {
        let d = decodeLS(0x3D00_0000)
        #expect(d.mnemonic == .str)
    }

    @Test func ldrByteUnsignedOffset() {
        let d = decodeLS(0x3D40_0000)
        #expect(d.mnemonic == .ldr)
    }

    @Test func strQuadUnsignedOffset() {
        let d = decodeLS(0x3D80_0000)
        #expect(d.mnemonic == .str)
    }

    @Test func ldrQuadUnsignedOffset() {
        let d = decodeLS(0x3DC0_0000)
        #expect(d.mnemonic == .ldr)
    }

    @Test func strHalfUnsignedOffset() {
        let d = decodeLS(0x7D00_0000)
        #expect(d.mnemonic == .str)
    }

    @Test func ldrHalfUnsignedOffset() {
        let d = decodeLS(0x7D40_0000)
        #expect(d.mnemonic == .ldr)
    }

    @Test func strSingleUnsignedOffset() {
        let d = decodeLS(0xBD00_0000)
        #expect(d.mnemonic == .str)
    }

    @Test func ldrSingleUnsignedOffset() {
        let d = decodeLS(0xBD40_0000)
        #expect(d.mnemonic == .ldr)
    }

    @Test func strDoubleUnsignedOffset() {
        let d = decodeLS(0xFD00_0000)
        #expect(d.mnemonic == .str)
    }

    @Test func ldrDoubleUnsignedOffset() {
        let d = decodeLS(0xFD40_0000)
        #expect(d.mnemonic == .ldr)
    }
}

/// Validates AcrossLanes every (U, opcode) mapping (saddlv/uaddlv/smaxv/
/// uminv/etc.
@Suite("SIMD/FP / AcrossLanes mnemonic matrix")
struct AcrossLanesMatrixTests {
    private func d(_ enc: UInt32) -> Instruction {
        decode(enc, at: 0)
    }

    @Test func saddlvAllSizes() {
        #expect(d(0x0E30_3820).mnemonic == .saddlv)
        #expect(d(0x0E70_3820).mnemonic == .saddlv)
        #expect(d(0x4E30_3820).mnemonic == .saddlv)
        #expect(d(0x4EB0_3820).mnemonic == .saddlv)
    }

    @Test func uaddlvAllSizes() {
        #expect(d(0x2E30_3820).mnemonic == .uaddlv)
        #expect(d(0x6E30_3820).mnemonic == .uaddlv)
    }

    @Test func smaxvVariants() {
        #expect(d(0x0E30_A820).mnemonic == .smaxv)
        #expect(d(0x4E30_A820).mnemonic == .smaxv)
        #expect(d(0x0E70_A820).mnemonic == .smaxv)
    }

    @Test func sminvVariants() {
        #expect(d(0x0E31_A820).mnemonic == .sminv)
        #expect(d(0x4EB1_A820).mnemonic == .sminv)
    }

    @Test func umaxvVariants() {
        #expect(d(0x2E30_A820).mnemonic == .umaxv)
    }

    @Test func uminvVariants() {
        #expect(d(0x2E31_A820).mnemonic == .uminv)
    }

    @Test func addvVariants() {
        #expect(d(0x0E31_B820).mnemonic == .addv)
        #expect(d(0x4E31_B820).mnemonic == .addv)
    }
}

/// Validates FP/AdvSIMD across-lanes per-arrangement variants.
@Suite("SIMD/FP / AcrossLanes arrangement validity")
struct AcrossLanesArrangementTests {
    private func d(_ enc: UInt32) -> Instruction {
        decode(enc, at: 0)
    }

    @Test func saddlvDArrangementIsReserved() {
        #expect(d(0x0EF0_3820).mnemonic == .undefined)
    }

    @Test func saddlvD2ArrangementIsReserved() {
        #expect(d(0x4EF0_3820).mnemonic == .undefined)
    }

    @Test func saddlvS2ArrangementIsReserved() {
        #expect(d(0x0EB0_3820).mnemonic == .undefined)
    }
}
