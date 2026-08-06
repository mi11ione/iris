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

private func z(_ n: UInt8, _ element: ScalarSize) -> Operand {
    .scalableVector(ScalableVectorRef(registerIndex: n, element: element))
}

private func governing(_ n: UInt8, _ qualifier: PredicateQualifier) -> Operand {
    .scalablePredicate(ScalablePredicateRef(registerIndex: n, qualifier: qualifier, role: .governing))
}

private func canonicalIndices(_ set: RegisterSet) -> [Int] {
    (0 ..< 64).filter { (set.mask >> UInt64($0)) & 1 == 1 }
}

/// Validates the predicated integer groups at 0x04.
@Suite("SVE integer / predicated arithmetic, shifts, unary, multiply-add")
struct SVEIntPredicatedDecodeTests {
    private static let arithLogical: [(UInt32, Mnemonic, String)] = [
        (0x0400_0443, .add, "add z3.b, p1/m, z3.b, z2.b"),
        (0x0401_0443, .sub, "sub z3.b, p1/m, z3.b, z2.b"),
        (0x0403_0443, .subr, "subr z3.b, p1/m, z3.b, z2.b"),
        (0x04C4_0443, .addpt, "addpt z3.d, p1/m, z3.d, z2.d"),
        (0x04C5_0443, .subpt, "subpt z3.d, p1/m, z3.d, z2.d"),
        (0x0408_0443, .smax, "smax z3.b, p1/m, z3.b, z2.b"),
        (0x0409_0443, .umax, "umax z3.b, p1/m, z3.b, z2.b"),
        (0x040A_0443, .smin, "smin z3.b, p1/m, z3.b, z2.b"),
        (0x040B_0443, .umin, "umin z3.b, p1/m, z3.b, z2.b"),
        (0x040C_0443, .sabd, "sabd z3.b, p1/m, z3.b, z2.b"),
        (0x040D_0443, .uabd, "uabd z3.b, p1/m, z3.b, z2.b"),
        (0x0410_0443, .mul, "mul z3.b, p1/m, z3.b, z2.b"),
        (0x0412_0443, .smulh, "smulh z3.b, p1/m, z3.b, z2.b"),
        (0x0413_0443, .umulh, "umulh z3.b, p1/m, z3.b, z2.b"),
        (0x0494_0443, .sdiv, "sdiv z3.s, p1/m, z3.s, z2.s"),
        (0x04D5_0443, .udiv, "udiv z3.d, p1/m, z3.d, z2.d"),
        (0x0496_0443, .sdivr, "sdivr z3.s, p1/m, z3.s, z2.s"),
        (0x0497_0443, .udivr, "udivr z3.s, p1/m, z3.s, z2.s"),
        (0x0418_0443, .orr, "orr z3.b, p1/m, z3.b, z2.b"),
        (0x0419_0443, .eor, "eor z3.b, p1/m, z3.b, z2.b"),
        (0x041A_0443, .and, "and z3.b, p1/m, z3.b, z2.b"),
        (0x041B_0443, .bic, "bic z3.b, p1/m, z3.b, z2.b"),
    ]

    @Test func everyArithmeticLogicalOpcodeDecodesDestructively() {
        for (encoding, mnemonic, expected) in Self.arithLogical {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.flagEffect == .none)
            #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite])
            #expect(canonicalIndices(d.semanticReads) == [34, 35], "\(expected) reads Zm and Zdn")
            #expect(canonicalIndices(d.semanticWrites) == [35], "\(expected) writes Zdn")
            #expect(d.scalableReads.containsPredicate(1))
            #expect(d.scalableWrites == .empty)
        }
    }

    @Test func theSizeGatedArithmeticOpcodesRejectTheirIllegalSizes() {
        for encoding: UInt32 in [
            0x0414_0443,
            0x0455_0443,
            0x0404_0443,
            0x0402_0443, 0x0406_0443, 0x0407_0443,
            0x040E_0443, 0x040F_0443, 0x0411_0443,
        ] {
            #expect(decode(encoding).mnemonic == .undefined, "0x\(String(encoding, radix: 16))")
        }
    }

    private static let unary: [(UInt32, Mnemonic, String)] = [
        (0x0450_A820, .sxtb, "sxtb z0.h, p2/m, z1.h"),
        (0x0451_A820, .uxtb, "uxtb z0.h, p2/m, z1.h"),
        (0x0492_A820, .sxth, "sxth z0.s, p2/m, z1.s"),
        (0x0493_A820, .uxth, "uxth z0.s, p2/m, z1.s"),
        (0x04D4_A820, .sxtw, "sxtw z0.d, p2/m, z1.d"),
        (0x04D5_A820, .uxtw, "uxtw z0.d, p2/m, z1.d"),
        (0x0456_A820, .abs, "abs z0.h, p2/m, z1.h"),
        (0x0457_A820, .neg, "neg z0.h, p2/m, z1.h"),
        (0x0458_A820, .cls, "cls z0.h, p2/m, z1.h"),
        (0x0459_A820, .clz, "clz z0.h, p2/m, z1.h"),
        (0x045A_A820, .cnt, "cnt z0.h, p2/m, z1.h"),
        (0x045B_A820, .cnot, "cnot z0.h, p2/m, z1.h"),
        (0x045E_A820, .not, "not z0.h, p2/m, z1.h"),
    ]

    @Test func everyMergingUnaryOpcodeReadsItsDestination() {
        for (encoding, mnemonic, expected) in Self.unary {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite])
            #expect(canonicalIndices(d.semanticReads) == [32, 33], "\(expected) reads Zn and the merged Zd")
            #expect(canonicalIndices(d.semanticWrites) == [32])
        }
    }

    @Test func theZeroingUnaryFormWritesFreshAndSkipsTheDestinationRead() {
        let d = decode(0x0446_A820)
        #expect(d.mnemonic == .abs)
        #expect(text(0x0446_A820) == "abs z0.h, p2/z, z1.h")
        #expect(d.scalableEffect == .readsStreamingMode)
        #expect(canonicalIndices(d.semanticReads) == [33])
        #expect(canonicalIndices(d.semanticWrites) == [32])
        #expect(Array(d.operands) == [z(0, .h), governing(2, .zeroing), z(1, .h)])
    }

    @Test func theExtendOpcodesRejectElementsTheyCannotWiden() {
        for encoding: UInt32 in [
            0x0410_A020,
            0x0452_A820,
            0x0494_A820,
            0x045F_A820,
        ] {
            #expect(decode(encoding).mnemonic == .undefined, "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func multiplyAccumulateOrdersItsOperandsAccumulatorFirst() {
        let d = decode(0x0482_4020)
        #expect(d.mnemonic == .mla)
        #expect(text(0x0482_4020) == "mla z0.s, p0/m, z1.s, z2.s")
        #expect(Array(d.operands) == [z(0, .s), governing(0, .merging), z(1, .s), z(2, .s)])
        #expect(canonicalIndices(d.semanticReads) == [32, 33, 34], "Zda, Zn and Zm are all read")
        #expect(canonicalIndices(d.semanticWrites) == [32])
        #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite])
        #expect(decode(0x0482_6020).mnemonic == .mls)
        #expect(text(0x0482_6020) == "mls z0.s, p0/m, z1.s, z2.s")
    }

    @Test func multiplyAddOrdersItsOperandsMultiplicandFirst() {
        let d = decode(0x0442_D420)
        #expect(d.mnemonic == .mad)
        #expect(text(0x0442_D420) == "mad z0.h, p5/m, z2.h, z1.h")
        #expect(Array(d.operands) == [z(0, .h), governing(5, .merging), z(2, .h), z(1, .h)])
        #expect(canonicalIndices(d.semanticReads) == [32, 33, 34])
        #expect(canonicalIndices(d.semanticWrites) == [32])
        #expect(decode(0x0481_C040).mnemonic == .mad)
        #expect(decode(0x0481_E040).mnemonic == .msb)
        #expect(text(0x0481_E040) == "msb z0.s, p0/m, z1.s, z2.s")
    }

    private static let reductions: [(UInt32, Mnemonic, String)] = [
        (0x0400_2443, .saddv, "saddv d3, p1, z2.b"),
        (0x04C1_2443, .uaddv, "uaddv d3, p1, z2.d"),
        (0x0408_2443, .smaxv, "smaxv b3, p1, z2.b"),
        (0x0409_2443, .umaxv, "umaxv b3, p1, z2.b"),
        (0x040A_2443, .sminv, "sminv b3, p1, z2.b"),
        (0x040B_2443, .uminv, "uminv b3, p1, z2.b"),
        (0x0418_2443, .orv, "orv b3, p1, z2.b"),
        (0x0419_2443, .eorv, "eorv b3, p1, z2.b"),
        (0x041A_2443, .andv, "andv b3, p1, z2.b"),
    ]

    @Test func everyScalarReductionWritesASIMDScalarDestination() {
        for (encoding, mnemonic, expected) in Self.reductions {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticReads) == [34], "\(expected) reads only Zn")
            #expect(canonicalIndices(d.semanticWrites) == [35], "\(expected) writes V3")
            #expect(d.scalableEffect == .readsStreamingMode, "\(expected) is a full write")
            #expect(d.scalableReads.containsPredicate(1))
        }
    }

    @Test func theAdditiveReductionsAreAsymmetricAtDoubleword() {
        #expect(decode(0x04C0_2443).mnemonic == .undefined)
        #expect(decode(0x04C1_2443).mnemonic == .uaddv)
        #expect(decode(0x0402_2443).mnemonic == .undefined)
    }

    private static let quadwordReductions: [(UInt32, Mnemonic, String)] = [
        (0x0405_2443, .addqv, "addqv v3.16b, p1, z2.b"),
        (0x0445_2443, .addqv, "addqv v3.8h, p1, z2.h"),
        (0x0485_2443, .addqv, "addqv v3.4s, p1, z2.s"),
        (0x04C5_2443, .addqv, "addqv v3.2d, p1, z2.d"),
        (0x040C_2443, .smaxqv, "smaxqv v3.16b, p1, z2.b"),
        (0x040D_2443, .umaxqv, "umaxqv v3.16b, p1, z2.b"),
        (0x040E_2443, .sminqv, "sminqv v3.16b, p1, z2.b"),
        (0x040F_2443, .uminqv, "uminqv v3.16b, p1, z2.b"),
        (0x041C_2443, .orqv, "orqv v3.16b, p1, z2.b"),
        (0x041D_2443, .eorqv, "eorqv v3.16b, p1, z2.b"),
        (0x041E_2443, .andqv, "andqv v3.16b, p1, z2.b"),
    ]

    @Test func everyQuadwordReductionWritesAFullNEONVector() {
        for (encoding, mnemonic, expected) in Self.quadwordReductions {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticWrites) == [35])
            #expect(d.scalableEffect == .readsStreamingMode)
        }
        #expect(decode(0x0404_2443).mnemonic == .undefined, "reserved quadword opcode")
    }

    private static let shiftImmediates: [(UInt32, Mnemonic, String)] = [
        (0x0400_8100, .asr, "asr z0.b, p0/m, z0.b, #8"),
        (0x0401_8100, .lsr, "lsr z0.b, p0/m, z0.b, #8"),
        (0x0403_8100, .lsl, "lsl z0.b, p0/m, z0.b, #0"),
        (0x0404_8100, .asrd, "asrd z0.b, p0/m, z0.b, #8"),
        (0x0406_8100, .sqshl, "sqshl z0.b, p0/m, z0.b, #0"),
        (0x0407_8100, .uqshl, "uqshl z0.b, p0/m, z0.b, #0"),
        (0x040C_8100, .srshr, "srshr z0.b, p0/m, z0.b, #8"),
        (0x040D_8100, .urshr, "urshr z0.b, p0/m, z0.b, #8"),
        (0x040F_8100, .sqshlu, "sqshlu z0.b, p0/m, z0.b, #0"),
        (0x0400_8200, .asr, "asr z0.h, p0/m, z0.h, #16"),
        (0x0440_8000, .asr, "asr z0.s, p0/m, z0.s, #32"),
        (0x0480_8000, .asr, "asr z0.d, p0/m, z0.d, #64"),
    ]

    @Test func theShiftImmediateSchemeDecodesElementAndAmountJointly() {
        for (encoding, mnemonic, expected) in Self.shiftImmediates {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite])
            #expect(canonicalIndices(d.semanticReads) == [32])
            #expect(canonicalIndices(d.semanticWrites) == [32])
        }
    }

    @Test func theShiftImmediateRejectsItsReservedSlots() {
        for encoding: UInt32 in [
            0x0400_8000,
            0x0402_8100, 0x0405_8100,
            0x0408_8100, 0x040E_8100,
        ] {
            #expect(decode(encoding).mnemonic == .undefined, "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func theRegisterShiftsIncludeTheReversedForms() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x0490_8020, .asr, "asr z0.s, p0/m, z0.s, z1.s"),
            (0x0491_8020, .lsr, "lsr z0.s, p0/m, z0.s, z1.s"),
            (0x0493_8020, .lsl, "lsl z0.s, p0/m, z0.s, z1.s"),
            (0x0494_8020, .asrr, "asrr z0.s, p0/m, z0.s, z1.s"),
            (0x0495_8020, .lsrr, "lsrr z0.s, p0/m, z0.s, z1.s"),
            (0x0497_8020, .lslr, "lslr z0.s, p0/m, z0.s, z1.s"),
        ]
        for (encoding, mnemonic, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(Array(d.operands) == [z(0, .s), governing(0, .merging), z(0, .s), z(1, .s)])
        }
        #expect(decode(0x0496_8020).mnemonic == .undefined, "reserved register-shift opcode")
    }

    @Test func theWideShiftsTakeADoublewordShiftVectorAndStopBelowDoubleword() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x0418_8020, .asr, "asr z0.b, p0/m, z0.b, z1.d"),
            (0x0419_8020, .lsr, "lsr z0.b, p0/m, z0.b, z1.d"),
            (0x041B_8020, .lsl, "lsl z0.b, p0/m, z0.b, z1.d"),
        ]
        for (encoding, mnemonic, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(Array(d.operands) == [z(0, .b), governing(0, .merging), z(0, .b), z(1, .d)])
        }
        #expect(decode(0x04D8_8020).mnemonic == .undefined, "wide shift at doubleword")
        #expect(decode(0x041A_8020).mnemonic == .undefined, "reserved wide-shift opcode")
    }
}
