// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

/// Validates FP fixed-point conversion (SCVTF / UCVTF / FCVTZS / FCVTZU
/// with fbits). Encoding: `sf 0 0 11110 ftype 0 0 rmode opcode scale Rn Rd`.
@Suite("SIMD/FP / FP fixed-point conversion")
struct FPFixedPointConversionTests {
    @Test func scvtfFromX64FixedSingle() {
        // SCVTF S0, X1, #1: sf=1, ftype=00 (S), rmode=00, opcode=010,
        // scale=63 (fbits=1). bit[21] = 0 (fixed-point class).
        // Top byte: sf=1, then 00111110 = 1001_1110 = 0x9E.
        // Field layout (as FPFixedPointConversionDecode reads it):
        // ftype bits[23:22], bit 21 = 0, rmode bits[20:19],
        // opcode bits[18:16], scale bits[15:10].
        // Byte 1 (bits 23..16): ftype(2) + 0 + 0 + rmode(2) + opcode(3) = 8 bits.
        // For SCVTF S0, X1, #1 sf=1 ftype=00 rmode=00 opcode=010 scale=63:
        // byte 1 = 00_0_0_00_010 = 0000_0010 = 0x02.
        // byte 2 (bits 15..8) = scale(6) + Rn[4:3](2). scale=63=111111. Rn=1 ⇒ Rn[4:3]=00.
        // byte 2 = 111111_00 = 1111_1100 = 0xFC.
        // byte 3 (bits 7..0) = Rn[2:0](3) + Rd(5). Rn=1 ⇒ 001. Rd=0 ⇒ 00000.
        // byte 3 = 001_00000 = 0010_0000 = 0x20.
        // encoding = 0x9E02_FC20.
        let d = decode(0x9E02_FC20)
        #expect(d.mnemonic == .scvtf)
        // Destination is V (vector scalar) S0.
        #expect(d.operands.count == 3)
    }

    @Test func ucvtfFromX64FixedDouble() {
        // UCVTF D0, X1, #1: opcode=011, ftype=01 (D).
        // byte 1: 01_0_0_00_011 = 0100_0011 = 0x43.
        let d = decode(0x9E43_FC20)
        #expect(d.mnemonic == .ucvtf)
    }

    @Test func fcvtzsToX64FixedSingle() {
        // FCVTZS X0, S1, #1: rmode=11, opcode=000, ftype=00.
        // byte 1: 00_0_0_11_000 = 0001_1000 = 0x18.
        let d = decode(0x9E18_FC20)
        #expect(d.mnemonic == .fcvtzs)
    }

    @Test func fcvtzuToX64FixedDouble() {
        // FCVTZU X0, D1, #1: rmode=11, opcode=001, ftype=01.
        // byte 1: 01_0_0_11_001 = 0101_1001 = 0x59.
        let d = decode(0x9E59_FC20)
        #expect(d.mnemonic == .fcvtzu)
    }

    @Test func sf0WithScale32IsReserved() {
        // sf=0 with scale=0 (fbits=64, far above the 32-bit max of 32) is
        // reserved. scale=32 (fbits=32) is the valid boundary — it decodes
        // `scvtf … #32` — so the reserved case needs scale=0.
        let d = decode(0x1E02_0020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func sf0WithValidScale33Passes() {
        // sf=0 with scale=33 (fbits=31) is valid.
        // byte 2 = 100001_00 = 1000_0100 = 0x84.
        let d = decode(0x1E02_8420)
        #expect(d.mnemonic == .scvtf)
    }

    @Test func unknownOpcodeReturnsUndefined() {
        // opcode=100 (rmode=00) reserved.
        // byte 1: 00_0_0_00_100 = 0000_0100 = 0x04.
        let d = decode(0x9E04_FC20)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedRmodeReturnsUndefined() {
        // rmode=01 with opcode=000 reserved (rmode ∈ {00, 11} only).
        let d = decode(0x9E08_FC20) // byte 1 = 0000_1000 = 0x08 → rmode=01 opcode=000.
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedFtype10() {
        let d = decode(0x9E82_FC20) // ftype=10.
        #expect(d.mnemonic == .undefined)
    }

    @Test func semanticReadsAndWritesForGprToFp() {
        // SCVTF: GPR Xn → FP Vd. Reads Xn (GPR), writes Vd (SIMD).
        let d = decode(0x9E02_FC20)
        #expect(d.semanticReads.contains(.x(1)))
        #expect(d.semanticWrites.contains(.simd(0)))
    }

    @Test func semanticReadsAndWritesForFpToGpr() {
        // FCVTZS: FP Vn → GPR Xd. Reads Vn (SIMD), writes Xd (GPR).
        let d = decode(0x9E18_FC20)
        #expect(d.semanticReads.contains(.simd(1)))
        #expect(d.semanticWrites.contains(.x(0)))
    }
}

/// Validates FP integer conversion — FCVT family + FJCVTZS + SCVTF /
/// UCVTF (int) + FMOV (FP↔GPR + V.D[1]↔X).
@Suite("SIMD/FP / FP integer conversion")
struct FPIntegerConversionTests {
    @Test func fcvtnsXFromS() {
        // FCVTNS X0, S1: sf=1, ftype=00, rmode=00, opcode=000.
        // bits[14:10]=00000 → routes to FP integer conv.
        // Top byte: 1001_1110 = 0x9E. byte 1: ftype 00, 1, rmode 00, opcode 000 = 00_1_00_000 = 0x20.
        // byte 2: bits[15:10]=000000 ⇒ low bits of byte 2 = 00. byte 2 high = bits 9..8 (Rn high).
        // For Rn=1: bits 9..8 = 00. byte 2 = 0000_0000 = 0x00.
        // byte 3: bits 7..5 (Rn low 3) + Rd = 001_00000 = 0x20.
        let d = decode(0x9E20_0020)
        #expect(d.mnemonic == .fcvtns)
    }

    @Test func fcvtnuXFromS() {
        // opcode=001.
        let d = decode(0x9E21_0020)
        #expect(d.mnemonic == .fcvtnu)
    }

    @Test func fcvtpsXFromS() {
        // rmode=01, opcode=000.
        let d = decode(0x9E28_0020)
        #expect(d.mnemonic == .fcvtps)
    }

    @Test func fcvtpuXFromS() {
        let d = decode(0x9E29_0020)
        #expect(d.mnemonic == .fcvtpu)
    }

    @Test func fcvtmsXFromS() {
        // rmode=10, opcode=000.
        let d = decode(0x9E30_0020)
        #expect(d.mnemonic == .fcvtms)
    }

    @Test func fcvtmuXFromS() {
        let d = decode(0x9E31_0020)
        #expect(d.mnemonic == .fcvtmu)
    }

    @Test func fcvtzsXFromS() {
        // rmode=11, opcode=000.
        let d = decode(0x9E38_0020)
        #expect(d.mnemonic == .fcvtzs)
    }

    @Test func fcvtzuXFromS() {
        let d = decode(0x9E39_0020)
        #expect(d.mnemonic == .fcvtzu)
    }

    @Test func fcvtasXFromS() {
        // rmode=00, opcode=100.
        let d = decode(0x9E24_0020)
        #expect(d.mnemonic == .fcvtas)
    }

    @Test func fcvtauXFromS() {
        let d = decode(0x9E25_0020)
        #expect(d.mnemonic == .fcvtau)
    }

    @Test func fjcvtzsWFromD() {
        // FJCVTZS W0, D1: sf=0, ftype=01, rmode=11, opcode=110.
        // Top byte 0x1E. byte 1: ftype=01, 1, rmode=11, opcode=110.
        // = 01_1_11_110 = 0111_1110 = 0x7E.
        let d = decode(0x1E7E_0020)
        #expect(d.mnemonic == .fjcvtzs)
    }

    @Test func fjcvtzsRequiresSpecificFtypeAndSf() {
        // FJCVTZS only valid with sf=0, ftype=01.
        let d = decode(0x9E7E_0020) // sf=1.
        #expect(d.mnemonic == .undefined)
    }

    @Test func scvtfSFromX() {
        // SCVTF S0, X1: sf=1, ftype=00, rmode=00, opcode=010.
        let d = decode(0x9E22_0020)
        #expect(d.mnemonic == .scvtf)
    }

    @Test func ucvtfSFromX() {
        let d = decode(0x9E23_0020)
        #expect(d.mnemonic == .ucvtf)
    }

    @Test func fmovWFromS() {
        // FMOV W0, S1: sf=0, ftype=00, rmode=00, opcode=110.
        let d = decode(0x1E26_0020)
        #expect(d.mnemonic == .fmov)
        // Destination is W register.
        #expect(d.operands[0] == .register(.w(0)))
    }

    @Test func fmovSFromW() {
        // FMOV S0, W1: opcode=111.
        let d = decode(0x1E27_0020)
        #expect(d.mnemonic == .fmov)
        if case let .vectorRegister(vr) = d.operands[0] {
            if case let .scalar(size) = vr.view {
                #expect(size == .s)
            }
        }
    }

    @Test func fmovXFromD() {
        // FMOV X0, D1: sf=1, ftype=01.
        let d = decode(0x9E66_0020)
        #expect(d.mnemonic == .fmov)
    }

    @Test func fmovDFromX() {
        let d = decode(0x9E67_0020)
        #expect(d.mnemonic == .fmov)
    }

    @Test func fmovXToVD1() {
        // FMOV V0.D[1], X1: sf=1, ftype=10, rmode=01, opcode=111.
        // byte 1: ftype=10, 1, rmode=01, opcode=111 = 10_1_01_111 = 1010_1111 = 0xAF.
        let d = decode(0x9EAF_0020)
        #expect(d.mnemonic == .fmov)
        // Destination is V0.D[1] (element).
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .element(arrangement: .d2, index: 1)),
        ))
    }

    @Test func fmovXFromVD1() {
        // FMOV X0, V1.D[1]: opcode=110.
        let d = decode(0x9EAE_0020)
        #expect(d.mnemonic == .fmov)
    }

    @Test func fmovTopHalfRequiresSf1() {
        // ftype=10 with sf=0 reserved.
        let d = decode(0x1EAE_0020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func fmovTopHalfRequiresRmode01() {
        // ftype=10 with rmode != 01 reserved.
        let d = decode(0x9EAC_0020) // rmode=00.
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedFtype10Outside_FMovTopHalf() {
        // ftype=10 with opcode not in {110, 111} reserved.
        let d = decode(0x9EA8_0020) // opcode=000, rmode=01.
        #expect(d.mnemonic == .undefined)
    }

    @Test func fmovWidthMismatchReserved() {
        // FMOV S, X (ftype=00 requires sf=0) but sf=1 reserved.
        let d = decode(0x9E27_0020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func unrecognizedRmodeOpcodeReturnsUndefined() {
        // rmode=01 opcode=000 not in FCVT table (FCVTPS uses rmode=01 ✓);
        // but rmode=10 opcode=100 unused.
        let d = decode(0x9E34_0020)
        #expect(d.mnemonic == .undefined)
    }
}
