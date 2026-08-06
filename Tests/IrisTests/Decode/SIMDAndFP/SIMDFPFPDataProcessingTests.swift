// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

/// Validates FP data-processing 2-source at scalar precision S/D/H.
@Suite("SIMD/FP / FP DP 2-source")
struct FPDataProcessing2SourceTests {
    @Test func fmulDouble() {
        let d = decode(0x1E62_0820)
        #expect(d.mnemonic == .fmul)
        #expect(d.operands.count == 3)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .scalar(size: .d)),
        ))
        #expect(d.operands[1] == .vectorRegister(
            VectorRegisterRef(registerIndex: 1, view: .scalar(size: .d)),
        ))
        #expect(d.operands[2] == .vectorRegister(
            VectorRegisterRef(registerIndex: 2, view: .scalar(size: .d)),
        ))
    }

    @Test func fdivSingle() {
        let d = decode(0x1E22_1820)
        #expect(d.mnemonic == .fdiv)
    }

    @Test func faddHalf() {
        let d = decode(0x1EE2_2820)
        #expect(d.mnemonic == .fadd)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .scalar(size: .h)),
        ))
    }

    @Test func fsubDouble() {
        let d = decode(0x1E62_3820)
        #expect(d.mnemonic == .fsub)
    }

    @Test func fmaxSingle() {
        let d = decode(0x1E22_4820)
        #expect(d.mnemonic == .fmax)
    }

    @Test func fminSingle() {
        let d = decode(0x1E22_5820)
        #expect(d.mnemonic == .fmin)
    }

    @Test func fmaxnmDouble() {
        let d = decode(0x1E62_6820)
        #expect(d.mnemonic == .fmaxnm)
    }

    @Test func fminnmDouble() {
        let d = decode(0x1E62_7820)
        #expect(d.mnemonic == .fminnm)
    }

    @Test func fnmulSingle() {
        let d = decode(0x1E22_8820)
        #expect(d.mnemonic == .fnmul)
    }

    @Test func reservedFtype10Returnsundefined() {
        let d = decode(0x1EA2_0820)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedOpcodeReturnsUndefined() {
        let d = decode(0x1E62_9820)
        #expect(d.mnemonic == .undefined)
    }

    @Test func semanticReadsContainBothSources() {
        let d = decode(0x1E62_0820)
        #expect(d.semanticReads.contains(.simd(1)))
        #expect(d.semanticReads.contains(.simd(2)))
        #expect(d.semanticWrites.contains(.simd(0)))
    }

    @Test func categoryAndFlagEffectAreSIMDFPAndNone() {
        let d = decode(0x1E62_0820)
        #expect(d.category == .simdAndFP)
        #expect(d.flagEffect == .none)
    }
}

/// Validates FP DP 1-source.
@Suite("SIMD/FP / FP DP 1-source")
struct FPDataProcessing1SourceTests {
    @Test func fmovScalarDouble() {
        let d = decode(0x1E60_4020)
        #expect(d.mnemonic == .fmov)
        #expect(d.operands.count == 2)
    }

    @Test func fabsScalarSingle() {
        let d = decode(0x1E20_C020)
        #expect(d.mnemonic == .fabs)
    }

    @Test func fnegScalarHalf() {
        let d = decode(0x1EE1_4020)
        #expect(d.mnemonic == .fneg)
    }

    @Test func fsqrtScalarDouble() {
        let d = decode(0x1E61_C020)
        #expect(d.mnemonic == .fsqrt)
    }

    @Test func bfcvtSingleToBF16() {
        let d = decode(0x1E63_4020)
        #expect(d.mnemonic == .bfcvt)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .scalar(size: .h)),
        ))
        #expect(d.operands[1] == .vectorRegister(
            VectorRegisterRef(registerIndex: 1, view: .scalar(size: .s)),
        ))
    }

    @Test func bfcvtRejectsNonSingleSource() {
        let d = decode(0x1E23_4020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func fcvtSingleToDouble() {
        let d = decode(0x1E22_C020)
        #expect(d.mnemonic == .fcvt)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .scalar(size: .d)),
        ))
        #expect(d.operands[1] == .vectorRegister(
            VectorRegisterRef(registerIndex: 1, view: .scalar(size: .s)),
        ))
    }

    @Test func fcvtDoubleToSingle() {
        let d = decode(0x1E62_4020)
        #expect(d.mnemonic == .fcvt)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .scalar(size: .s)),
        ))
        #expect(d.operands[1] == .vectorRegister(
            VectorRegisterRef(registerIndex: 1, view: .scalar(size: .d)),
        ))
    }

    @Test func fcvtHalfToSingle() {
        let d = decode(0x1EE2_4020)
        #expect(d.mnemonic == .fcvt)
    }

    @Test func fcvtHalfToDouble() {
        let d = decode(0x1EE2_C020)
        #expect(d.mnemonic == .fcvt)
    }

    @Test func fcvtSingleToHalf() {
        let d = decode(0x1E23_C020)
        #expect(d.mnemonic == .fcvt)
    }

    @Test func fcvtReservedSameFtypeAndOpc() {
        let d = decode(0x1E22_4020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func fcvtReservedFtype10() {
        let d = decode(0x1EA2_C020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func fcvtReservedOpcEqualsTwo() {
        let d = decode(0x1E62_4020)
        #expect(d.mnemonic == .fcvt)
    }

    @Test func frintnSingle() {
        let d = decode(0x1E24_4020)
        #expect(d.mnemonic == .frintn)
    }

    @Test func frintpSingle() {
        let d = decode(0x1E24_C020)
        #expect(d.mnemonic == .frintp)
    }

    @Test func frintmSingle() {
        let d = decode(0x1E25_4020)
        #expect(d.mnemonic == .frintm)
    }

    @Test func frintzSingle() {
        let d = decode(0x1E25_C020)
        #expect(d.mnemonic == .frintz)
    }

    @Test func frintaSingle() {
        let d = decode(0x1E26_4020)
        #expect(d.mnemonic == .frinta)
    }

    @Test func frintxSingle() {
        let d = decode(0x1E27_4020)
        #expect(d.mnemonic == .frintx)
    }

    @Test func frintiSingle() {
        let d = decode(0x1E27_C020)
        #expect(d.mnemonic == .frinti)
    }

    @Test func frint32zSingle() {
        let d = decode(0x1E28_4020)
        #expect(d.mnemonic == .frint32z)
    }

    @Test func frint32xSingle() {
        let d = decode(0x1E28_C020)
        #expect(d.mnemonic == .frint32x)
    }

    @Test func frint64zSingle() {
        let d = decode(0x1E29_4020)
        #expect(d.mnemonic == .frint64z)
    }

    @Test func frint64xSingle() {
        let d = decode(0x1E29_C020)
        #expect(d.mnemonic == .frint64x)
    }

    @Test func reservedOpcodeReturnsUndefined() {
        let d = decode(0x1E26_C020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedFtypeForFMov() {
        let d = decode(0x1EA0_4020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func semanticReadsAndWrites() {
        let d = decode(0x1E60_4020)
        #expect(d.semanticReads.contains(.simd(1)))
        #expect(d.semanticWrites.contains(.simd(0)))
    }
}

/// Validates FP DP 3-source.
@Suite("SIMD/FP / FP DP 3-source")
struct FPDataProcessing3SourceTests {
    @Test func fmaddDouble() {
        let d = decode(0x1F42_0C20)
        #expect(d.mnemonic == .fmadd)
        #expect(d.operands.count == 4)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .scalar(size: .d)),
        ))
        #expect(d.operands[3] == .vectorRegister(
            VectorRegisterRef(registerIndex: 3, view: .scalar(size: .d)),
        ))
    }

    @Test func fmsubSingle() {
        let d = decode(0x1F02_8C20)
        #expect(d.mnemonic == .fmsub)
    }

    @Test func fnmaddHalf() {
        let d = decode(0x1FE2_0C20)
        #expect(d.mnemonic == .fnmadd)
    }

    @Test func fnmsubDouble() {
        let d = decode(0x1F62_8C20)
        #expect(d.mnemonic == .fnmsub)
    }

    @Test func reservedFtype10() {
        let d = decode(0x1FA2_0C20)
        #expect(d.mnemonic == .undefined)
    }

    @Test func semanticReadsContainAllSources() {
        let d = decode(0x1F42_0C20)
        #expect(d.semanticReads.contains(.simd(1)))
        #expect(d.semanticReads.contains(.simd(2)))
        #expect(d.semanticReads.contains(.simd(3)))
        #expect(!d.semanticReads.contains(.simd(0)))
        #expect(d.semanticWrites.contains(.simd(0)))
    }
}

/// Validates FP compare (FCMP / FCMPE) with register and zero forms.
@Suite("SIMD/FP / FP compare")
struct FPCompareTests {
    @Test func fcmpDoubleRegister() {
        let d = decode(0x1E62_2020)
        #expect(d.mnemonic == .fcmp)
        #expect(d.operands.count == 2)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 1, view: .scalar(size: .d)),
        ))
        #expect(d.operands[1] == .vectorRegister(
            VectorRegisterRef(registerIndex: 2, view: .scalar(size: .d)),
        ))
        #expect(d.flagEffect == .nzcv)
    }

    @Test func fcmpSingleRegister() {
        let d = decode(0x1E22_2020)
        #expect(d.mnemonic == .fcmp)
    }

    @Test func fcmpHalfRegister() {
        let d = decode(0x1EE2_2020)
        #expect(d.mnemonic == .fcmp)
    }

    @Test func fcmpeDoubleRegister() {
        let d = decode(0x1E62_2030)
        #expect(d.mnemonic == .fcmpe)
        #expect(d.operands.count == 2)
    }

    @Test func fcmpDoubleZeroForm() {
        let d = decode(0x1E60_2028)
        #expect(d.mnemonic == .fcmp)
        #expect(d.operands[1] == .floatImmediate(bits: 0, kind: .double))
    }

    @Test func fcmpeDoubleZeroForm() {
        let d = decode(0x1E60_2038)
        #expect(d.mnemonic == .fcmpe)
    }

    @Test func fcmpZeroWithNonZeroRmReserved() {
        let d = decode(0x1E62_2028)
        #expect(d.mnemonic == .fcmp)
    }

    @Test func reservedFtype10() {
        let d = decode(0x1EA2_2020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedNonZeroLowBits() {
        let d = decode(0x1E62_2021)
        #expect(d.mnemonic == .undefined)
    }

    @Test func fcmpSingleZeroFormProducesFloatImmediateSinglePrecision() {
        let d = decode(0x1E20_2028)
        #expect(d.mnemonic == .fcmp)
        if case let .floatImmediate(_, kind) = d.operands[1] {
            #expect(kind == .single)
        }
    }

    @Test func fcmpHalfZeroFormProducesFloatImmediateHalfPrecision() {
        let d = decode(0x1EE0_2028)
        #expect(d.mnemonic == .fcmp)
        if case let .floatImmediate(_, kind) = d.operands[1] {
            #expect(kind == .half)
        }
    }
}

/// Validates FP conditional compare (FCCMP / FCCMPE).
@Suite("SIMD/FP / FP conditional compare")
struct FPConditionalCompareTests {
    @Test func fccmpDoubleEQ() {
        let d = decode(0x1E62_0420)
        #expect(d.mnemonic == .fccmp)
        #expect(d.operands.count == 4)
        #expect(d.operands[3] == .conditionCode(.eq))
        #expect(d.flagEffect == [.nzcv, .readsNZCV])
    }

    @Test func fccmpeWithOpBit() {
        let d = decode(0x1E62_0430)
        #expect(d.mnemonic == .fccmpe)
    }

    @Test func fccmpNzcvFieldIsPreserved() {
        let d = decode(0x1E62_042F)
        if case let .unsignedImmediate(value, width) = d.operands[2] {
            #expect(value == 0xF)
            #expect(width == 4)
        }
    }

    @Test func fccmpConditionCodeIsParsed() {
        let d = decode(0x1E62_1420)
        #expect(d.operands[3] == .conditionCode(.ne))
    }

    @Test func fccmpAllConditionCodes() throws {
        for cond: UInt8 in 0 ... 15 {
            let enc = (UInt32(0x1E62_0420) & ~(0xF << 12)) | (UInt32(cond) << 12)
            let d = decode(enc)
            #expect(d.mnemonic == .fccmp)
            #expect(try d.operands[3] == .conditionCode(#require(ConditionCode(rawValue: cond))))
        }
    }

    @Test func reservedFtype10() {
        let d = decode(0x1EA2_0420)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates FP conditional select (FCSEL).
@Suite("SIMD/FP / FP conditional select")
struct FPConditionalSelectTests {
    @Test func fcselDoubleEQ() {
        let d = decode(0x1E62_0C20)
        #expect(d.mnemonic == .fcsel)
        #expect(d.operands.count == 4)
        #expect(d.operands[3] == .conditionCode(.eq))
        #expect(d.flagEffect == .readsNZCV)
    }

    @Test func fcselSinglePL() {
        let d = decode(0x1E22_5C20)
        #expect(d.mnemonic == .fcsel)
        #expect(d.operands[3] == .conditionCode(.pl))
    }

    @Test func fcselHalfNV() {
        let d = decode(0x1EE2_FC20)
        #expect(d.mnemonic == .fcsel)
        #expect(d.operands[3] == .conditionCode(.nv))
    }

    @Test func reservedFtype10() {
        let d = decode(0x1EA2_0C20)
        #expect(d.mnemonic == .undefined)
    }

    @Test func semanticReadsContainBothSources() {
        let d = decode(0x1E62_0C20)
        #expect(d.semanticReads.contains(.simd(1)))
        #expect(d.semanticReads.contains(.simd(2)))
        #expect(d.semanticWrites.contains(.simd(0)))
    }
}

/// Validates FP immediate (FMOV scalar immediate).
@Suite("SIMD/FP / FP immediate")
struct FPImmediateTests {
    @Test func fmovDoubleOnePointZero() {
        let d = decode(0x1E6E_1000)
        #expect(d.mnemonic == .fmov)
        #expect(d.operands.count == 2)
        if case let .floatImmediate(bits, kind) = d.operands[1] {
            #expect(kind == .double)
            #expect(bits == 0x3FF0_0000_0000_0000)
        }
    }

    @Test func fmovSingleOnePointZero() {
        let d = decode(0x1E2E_1000)
        #expect(d.mnemonic == .fmov)
        if case let .floatImmediate(bits, kind) = d.operands[1] {
            #expect(kind == .single)
            #expect(bits == 0x3F80_0000)
        }
    }

    @Test func fmovHalfOnePointZero() {
        let d = decode(0x1EEE_1000)
        #expect(d.mnemonic == .fmov)
        if case let .floatImmediate(_, kind) = d.operands[1] {
            #expect(kind == .half)
        }
    }

    @Test func nonZeroImm5IsReserved() {
        let d = decode(0x1E6E_1020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedFtype10() {
        let d = decode(0x1EAE_1000)
        #expect(d.mnemonic == .undefined)
    }
}
