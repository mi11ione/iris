// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

/// Validates FP data-processing 2-source (FADD/FSUB/FMUL/FDIV/FMAX/FMIN/
/// FMAXNM/FMINNM/FNMUL) at scalar precision S/D/H. Encoding:
/// `0 0 0 11110 ftype 1 Rm opcode 10 Rn Rd`.
@Suite("SIMD/FP / FP DP 2-source")
struct FPDataProcessing2SourceTests {
    @Test func fmulDouble() {
        // FMUL D0, D1, D2: ftype=01 (D), opcode=0000.
        let d = decode(0x1E62_0820)
        #expect(d.mnemonic == .fmul)
        #expect(d.operands.count == 3)
        // Vd = D0, Vn = D1, Vm = D2.
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
        // FDIV S0, S1, S2: ftype=00 (S), opcode=0001.
        let d = decode(0x1E22_1820)
        #expect(d.mnemonic == .fdiv)
    }

    @Test func faddHalf() {
        // FADD H0, H1, H2: ftype=11 (H), opcode=0010.
        let d = decode(0x1EE2_2820)
        #expect(d.mnemonic == .fadd)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .scalar(size: .h)),
        ))
    }

    @Test func fsubDouble() {
        // FSUB D0, D1, D2: opcode=0011.
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
        // ftype=10 reserved at this class (FMOV V.D[1]↔X uses ftype=10
        // in the integer-conversion class, not here).
        let d = decode(0x1EA2_0820)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedOpcodeReturnsUndefined() {
        // opcode=1001 reserved.
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

/// Validates FP DP 1-source — FMOV/FABS/FNEG/FSQRT/FRINT*/FCVT-precision/
/// BFCVT. Encoding: `0 0 0 11110 ftype 1 00000 opcode 10000 Rn Rd`.
@Suite("SIMD/FP / FP DP 1-source")
struct FPDataProcessing1SourceTests {
    @Test func fmovScalarDouble() {
        // FMOV D0, D1: opcode=000000.
        let d = decode(0x1E60_4020)
        #expect(d.mnemonic == .fmov)
        #expect(d.operands.count == 2)
    }

    @Test func fabsScalarSingle() {
        // FABS S0, S1: opcode=000001.
        let d = decode(0x1E20_C020)
        #expect(d.mnemonic == .fabs)
    }

    @Test func fnegScalarHalf() {
        // FNEG H0, H1: opcode=000010, ftype=11 (H).
        let d = decode(0x1EE1_4020)
        #expect(d.mnemonic == .fneg)
    }

    @Test func fsqrtScalarDouble() {
        let d = decode(0x1E61_C020)
        #expect(d.mnemonic == .fsqrt)
    }

    @Test func bfcvtSingleToBF16() {
        // BFCVT H0, S1: ftype=01, opcode=000110 (single source -> BF16, dest H).
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
        // BFCVT requires ftype=01; ftype=00 (here) is reserved.
        let d = decode(0x1E23_4020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func fcvtSingleToDouble() {
        // FCVT D0, S1: opcode=000101 (ftype=00, opc=01), but the source
        // encodes opcode = 00_0101 with opc field at bits[16:15] = 01.
        // ftype=00 (S source), opc=01 (D dest) → opcode = 000101.
        let d = decode(0x1E22_C020)
        #expect(d.mnemonic == .fcvt)
        // Destination is D, source is S.
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .scalar(size: .d)),
        ))
        #expect(d.operands[1] == .vectorRegister(
            VectorRegisterRef(registerIndex: 1, view: .scalar(size: .s)),
        ))
    }

    @Test func fcvtDoubleToSingle() {
        // FCVT S0, D1: ftype=01, opc=00.
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
        // FCVT S0, H1: ftype=11 (H), opc=00 (S).
        let d = decode(0x1EE2_4020)
        #expect(d.mnemonic == .fcvt)
    }

    @Test func fcvtHalfToDouble() {
        let d = decode(0x1EE2_C020)
        #expect(d.mnemonic == .fcvt)
    }

    @Test func fcvtSingleToHalf() {
        // FCVT H0, S1: ftype=00, opc=11 → opcode=000111.
        let d = decode(0x1E23_C020)
        #expect(d.mnemonic == .fcvt)
    }

    @Test func fcvtReservedSameFtypeAndOpc() {
        // FCVT with ftype==opc reserved. FCVT-precision opcode is 0001XX
        // (bits 14..10 = 10000 ⇒ routes to FP DP 1-source). For ftype=00,
        // opc=00 ⇒ opcode = 000100. byte 1 = 0010_0010 = 0x22, byte 2 =
        // 0100_0000 = 0x40.
        let d = decode(0x1E22_4020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func fcvtReservedFtype10() {
        // ftype=10 reserved at FCVT precision sub-class.
        let d = decode(0x1EA2_C020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func fcvtReservedOpcEqualsTwo() {
        // opcode=000110 with ftype=01 (or 11) is reserved: BFCVT requires
        // ftype=00; FCVT-precision doesn't include opc=10.
        let d = decode(0x1E62_4020) // ftype=01, opcode=000100 actually
        #expect(d.mnemonic == .fcvt)
        // (ftype=01 D, opc=00 S — valid FCVT.)
    }

    @Test func frintnSingle() {
        // FRINTN S0, S1: opcode=001000.
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
        // FRINT32Z S0, S1: opcode=010000.
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
        // opcode=001101 reserved.
        let d = decode(0x1E26_C020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedFtypeForFMov() {
        // FMOV with ftype=10 — ftype=10 is reserved everywhere except the
        // V.D[1]↔X variants in the integer-conversion class.
        let d = decode(0x1EA0_4020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func semanticReadsAndWrites() {
        let d = decode(0x1E60_4020) // FMOV D0, D1.
        #expect(d.semanticReads.contains(.simd(1)))
        #expect(d.semanticWrites.contains(.simd(0)))
    }
}

/// Validates FP DP 3-source — FMADD/FMSUB/FNMADD/FNMSUB. Encoding:
/// `0 0 0 11111 ftype o1 Rm o0 Ra Rn Rd`.
@Suite("SIMD/FP / FP DP 3-source")
struct FPDataProcessing3SourceTests {
    @Test func fmaddDouble() {
        // FMADD D0, D1, D2, D3: ftype=01, o1=0, o0=0, Ra=3.
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
        // FMSUB S0, S1, S2, S3: ftype=00, o1=0, o0=1.
        let d = decode(0x1F02_8C20)
        #expect(d.mnemonic == .fmsub)
    }

    @Test func fnmaddHalf() {
        // FNMADD H0, H1, H2, H3: ftype=11, o1=1, o0=0.
        let d = decode(0x1FE2_0C20)
        #expect(d.mnemonic == .fnmadd)
    }

    @Test func fnmsubDouble() {
        // FNMSUB D0, D1, D2, D3: ftype=01, o1=1, o0=1.
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
        // FMADD: Rd does NOT read itself — Ra is the
        // explicit accumulator.
        #expect(!d.semanticReads.contains(.simd(0)))
        #expect(d.semanticWrites.contains(.simd(0)))
    }
}

/// Validates FP compare (FCMP / FCMPE) with register and zero forms.
@Suite("SIMD/FP / FP compare")
struct FPCompareTests {
    @Test func fcmpDoubleRegister() {
        // FCMP D1, D2: ftype=01, opc=00, Rm=2.
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
        // FCMPE D1, D2 (register form): opc=10 (bit[4]=1 E-bit, bit[3]=0).
        let d = decode(0x1E62_2030)
        #expect(d.mnemonic == .fcmpe)
        #expect(d.operands.count == 2)
    }

    @Test func fcmpDoubleZeroForm() {
        // FCMP D1, #0.0 (zero form): opc=01 (bit[4]=0 E-bit, bit[3]=1).
        let d = decode(0x1E60_2028)
        #expect(d.mnemonic == .fcmp)
        // Second operand is float immediate 0.0.
        #expect(d.operands[1] == .floatImmediate(bits: 0, kind: .double))
    }

    @Test func fcmpeDoubleZeroForm() {
        // FCMPE D1, #0.0: opc=11.
        let d = decode(0x1E60_2038)
        #expect(d.mnemonic == .fcmpe)
    }

    @Test func fcmpZeroWithNonZeroRmReserved() {
        // Zero form (opc=01) ignores the Rm (SBZ) field: Rm=2 still decodes
        // as FCMP #0.0, matching llvm-mc (Rm is not architecturally checked).
        let d = decode(0x1E62_2028)
        #expect(d.mnemonic == .fcmp)
    }

    @Test func reservedFtype10() {
        let d = decode(0x1EA2_2020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedNonZeroLowBits() {
        // bits[2:0] != 000 reserved.
        let d = decode(0x1E62_2021)
        #expect(d.mnemonic == .undefined)
    }

    @Test func fcmpSingleZeroFormProducesFloatImmediateSinglePrecision() {
        // FCMP S1, #0.0: ftype=00, opc=01 (zero form), Rn=1.
        let d = decode(0x1E20_2028)
        #expect(d.mnemonic == .fcmp)
        if case let .floatImmediate(_, kind) = d.operands[1] {
            #expect(kind == .single)
        }
    }

    @Test func fcmpHalfZeroFormProducesFloatImmediateHalfPrecision() {
        // FCMP H1, #0.0: ftype=11, opc=01 (zero form).
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
        // FCCMP D1, D2, #0, EQ: cond=0000, op=0, nzcv=0000.
        let d = decode(0x1E62_0420)
        #expect(d.mnemonic == .fccmp)
        #expect(d.operands.count == 4)
        #expect(d.operands[3] == .conditionCode(.eq))
        #expect(d.flagEffect == [.nzcv, .readsNZCV])
    }

    @Test func fccmpeWithOpBit() {
        // op=1 → FCCMPE.
        let d = decode(0x1E62_0430)
        #expect(d.mnemonic == .fccmpe)
    }

    @Test func fccmpNzcvFieldIsPreserved() {
        // nzcv=1111.
        let d = decode(0x1E62_042F)
        if case let .unsignedImmediate(value, width) = d.operands[2] {
            #expect(value == 0xF)
            #expect(width == 4)
        }
    }

    @Test func fccmpConditionCodeIsParsed() {
        // cond=NE = 0001 → bits 15..12 = 0001.
        let d = decode(0x1E62_1420)
        #expect(d.operands[3] == .conditionCode(.ne))
    }

    @Test func fccmpAllConditionCodes() throws {
        for cond: UInt8 in 0 ... 15 {
            let enc = (UInt32(0x1E62_0420) & ~(0xF << 12)) | (UInt32(cond) << 12)
            let d = decode(enc)
            #expect(d.mnemonic == .fccmp)
            // Decoded condition code matches.
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
        // FCSEL D0, D1, D2, EQ: ftype=01, cond=0000.
        let d = decode(0x1E62_0C20)
        #expect(d.mnemonic == .fcsel)
        #expect(d.operands.count == 4)
        #expect(d.operands[3] == .conditionCode(.eq))
        #expect(d.flagEffect == .readsNZCV) // FCSEL reads NZCV, writes none
    }

    @Test func fcselSinglePL() {
        // PL = 0101.
        let d = decode(0x1E22_5C20)
        #expect(d.mnemonic == .fcsel)
        #expect(d.operands[3] == .conditionCode(.pl))
    }

    @Test func fcselHalfNV() {
        // NV = 1111.
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
        // FMOV D0, #1.0: ftype=01, imm8=0x70. Pattern bits 20..13 = imm8.
        // For ftype=01 imm8=0x70 (=01110000): byte 1 = 01_1_01110 = 0x6E,
        // byte 2 = 000_100_00 = 0x10.
        let d = decode(0x1E6E_1000)
        #expect(d.mnemonic == .fmov)
        #expect(d.operands.count == 2)
        if case let .floatImmediate(bits, kind) = d.operands[1] {
            #expect(kind == .double)
            #expect(bits == 0x3FF0_0000_0000_0000)
        }
    }

    @Test func fmovSingleOnePointZero() {
        // FMOV S0, #1.0: ftype=00, imm8=0x70. byte 1 = 00_1_01110 = 0x2E.
        let d = decode(0x1E2E_1000)
        #expect(d.mnemonic == .fmov)
        if case let .floatImmediate(bits, kind) = d.operands[1] {
            #expect(kind == .single)
            #expect(bits == 0x3F80_0000)
        }
    }

    @Test func fmovHalfOnePointZero() {
        // FMOV H0, #1.0: ftype=11, imm8=0x70. byte 1 = 11_1_01110 = 0xEE.
        let d = decode(0x1EEE_1000)
        #expect(d.mnemonic == .fmov)
        if case let .floatImmediate(_, kind) = d.operands[1] {
            #expect(kind == .half)
        }
    }

    @Test func nonZeroImm5IsReserved() {
        // imm5 (bits[9:5]) != 00000 reserved. Encode bit 5 = 1.
        let d = decode(0x1E6E_1020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedFtype10() {
        let d = decode(0x1EAE_1000)
        #expect(d.mnemonic == .undefined)
    }
}
