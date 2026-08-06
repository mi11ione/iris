// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

/// Validates FP fixed-point conversion (SCVTF / UCVTF / FCVTZS / FCVTZU with
/// fbits).
@Suite("SIMD/FP / FP fixed-point conversion")
struct FPFixedPointConversionTests {
    @Test func scvtfFromX64FixedSingle() {
        let d = decode(0x9E02_FC20)
        #expect(d.mnemonic == .scvtf)
        #expect(d.operands.count == 3)
    }

    @Test func ucvtfFromX64FixedDouble() {
        let d = decode(0x9E43_FC20)
        #expect(d.mnemonic == .ucvtf)
    }

    @Test func fcvtzsToX64FixedSingle() {
        let d = decode(0x9E18_FC20)
        #expect(d.mnemonic == .fcvtzs)
    }

    @Test func fcvtzuToX64FixedDouble() {
        let d = decode(0x9E59_FC20)
        #expect(d.mnemonic == .fcvtzu)
    }

    @Test func sf0WithScale32IsReserved() {
        let d = decode(0x1E02_0020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func sf0WithValidScale33Passes() {
        let d = decode(0x1E02_8420)
        #expect(d.mnemonic == .scvtf)
    }

    @Test func unknownOpcodeReturnsUndefined() {
        let d = decode(0x9E04_FC20)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedRmodeReturnsUndefined() {
        let d = decode(0x9E08_FC20)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedFtype10() {
        let d = decode(0x9E82_FC20)
        #expect(d.mnemonic == .undefined)
    }

    @Test func semanticReadsAndWritesForGprToFp() {
        let d = decode(0x9E02_FC20)
        #expect(d.semanticReads.contains(.x(1)))
        #expect(d.semanticWrites.contains(.simd(0)))
    }

    @Test func semanticReadsAndWritesForFpToGpr() {
        let d = decode(0x9E18_FC20)
        #expect(d.semanticReads.contains(.simd(1)))
        #expect(d.semanticWrites.contains(.x(0)))
    }
}

/// Validates FP integer conversion.
@Suite("SIMD/FP / FP integer conversion")
struct FPIntegerConversionTests {
    @Test func fcvtnsXFromS() {
        let d = decode(0x9E20_0020)
        #expect(d.mnemonic == .fcvtns)
    }

    @Test func fcvtnuXFromS() {
        let d = decode(0x9E21_0020)
        #expect(d.mnemonic == .fcvtnu)
    }

    @Test func fcvtpsXFromS() {
        let d = decode(0x9E28_0020)
        #expect(d.mnemonic == .fcvtps)
    }

    @Test func fcvtpuXFromS() {
        let d = decode(0x9E29_0020)
        #expect(d.mnemonic == .fcvtpu)
    }

    @Test func fcvtmsXFromS() {
        let d = decode(0x9E30_0020)
        #expect(d.mnemonic == .fcvtms)
    }

    @Test func fcvtmuXFromS() {
        let d = decode(0x9E31_0020)
        #expect(d.mnemonic == .fcvtmu)
    }

    @Test func fcvtzsXFromS() {
        let d = decode(0x9E38_0020)
        #expect(d.mnemonic == .fcvtzs)
    }

    @Test func fcvtzuXFromS() {
        let d = decode(0x9E39_0020)
        #expect(d.mnemonic == .fcvtzu)
    }

    @Test func fcvtasXFromS() {
        let d = decode(0x9E24_0020)
        #expect(d.mnemonic == .fcvtas)
    }

    @Test func fcvtauXFromS() {
        let d = decode(0x9E25_0020)
        #expect(d.mnemonic == .fcvtau)
    }

    @Test func fjcvtzsWFromD() {
        let d = decode(0x1E7E_0020)
        #expect(d.mnemonic == .fjcvtzs)
    }

    @Test func fjcvtzsRequiresSpecificFtypeAndSf() {
        let d = decode(0x9E7E_0020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func scvtfSFromX() {
        let d = decode(0x9E22_0020)
        #expect(d.mnemonic == .scvtf)
    }

    @Test func ucvtfSFromX() {
        let d = decode(0x9E23_0020)
        #expect(d.mnemonic == .ucvtf)
    }

    @Test func fmovWFromS() {
        let d = decode(0x1E26_0020)
        #expect(d.mnemonic == .fmov)
        #expect(d.operands[0] == .register(.w(0)))
    }

    @Test func fmovSFromW() {
        let d = decode(0x1E27_0020)
        #expect(d.mnemonic == .fmov)
        if case let .vectorRegister(vr) = d.operands[0] {
            if case let .scalar(size) = vr.view {
                #expect(size == .s)
            }
        }
    }

    @Test func fmovXFromD() {
        let d = decode(0x9E66_0020)
        #expect(d.mnemonic == .fmov)
    }

    @Test func fmovDFromX() {
        let d = decode(0x9E67_0020)
        #expect(d.mnemonic == .fmov)
    }

    @Test func fmovXToVD1() {
        let d = decode(0x9EAF_0020)
        #expect(d.mnemonic == .fmov)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .element(arrangement: .d2, index: 1)),
        ))
    }

    @Test func fmovXFromVD1() {
        let d = decode(0x9EAE_0020)
        #expect(d.mnemonic == .fmov)
    }

    @Test func fmovTopHalfRequiresSf1() {
        let d = decode(0x1EAE_0020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func fmovTopHalfRequiresRmode01() {
        let d = decode(0x9EAC_0020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedFtype10Outside_FMovTopHalf() {
        let d = decode(0x9EA8_0020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func fmovWidthMismatchReserved() {
        let d = decode(0x9E27_0020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func unrecognizedRmodeOpcodeReturnsUndefined() {
        let d = decode(0x9E2C_0020)
        #expect(d.mnemonic == .undefined)
    }
}
