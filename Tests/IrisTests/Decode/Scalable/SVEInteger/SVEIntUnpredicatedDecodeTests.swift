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

private func canonicalIndices(_ set: RegisterSet) -> [Int] {
    (0 ..< 64).filter { (set.mask >> UInt64($0)) & 1 == 1 }
}

/// Validates the unpredicated region at top byte 0x04 (bit21 set): the plain
/// three-register arithmetic and saturating adds, the always-doubleword
/// logical family with its ORR-of-itself `mov` alias, the SVE2 multiplies,
/// shifts by wide element and by immediate, the ADR vector address
/// generation, and G17's four-operand bitwise ternary plus XAR. G6 writes a
/// fresh destination; G17 is destructive (the destination is read, but every
/// lane is recomputed, so the write stays full).
@Suite("SVE integer / unpredicated arithmetic, ADR, ternary")
struct SVEIntUnpredicatedDecodeTests {
    /// The unpredicated arithmetic block, opc at bits 12:10, Zd=0 Zn=1 Zm=2.
    private static let arithmetic: [(UInt32, Mnemonic, String)] = [
        (0x0422_0020, .add, "add z0.b, z1.b, z2.b"),
        (0x0422_0420, .sub, "sub z0.b, z1.b, z2.b"),
        (0x04E2_0820, .addpt, "addpt z0.d, z1.d, z2.d"),
        (0x04E2_0C20, .subpt, "subpt z0.d, z1.d, z2.d"),
        (0x0422_1020, .sqadd, "sqadd z0.b, z1.b, z2.b"),
        (0x0422_1420, .uqadd, "uqadd z0.b, z1.b, z2.b"),
        (0x0422_1820, .sqsub, "sqsub z0.b, z1.b, z2.b"),
        (0x0422_1C20, .uqsub, "uqsub z0.b, z1.b, z2.b"),
    ]

    @Test func everyArithmeticOpcodeWritesAFreshDestination() {
        for (encoding, mnemonic, expected) in Self.arithmetic {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.scalableEffect == .readsStreamingMode)
            #expect(canonicalIndices(d.semanticReads) == [33, 34], "\(expected) reads Zn and Zm only")
            #expect(canonicalIndices(d.semanticWrites) == [32])
            #expect(d.scalableReads == .empty)
        }
        #expect(decode(0x0422_0820).mnemonic == .undefined, "addpt below doubleword")
    }

    @Test func everyMultiplyOpcodeDecodesAndPMULStaysByte() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x0422_6020, .mul, "mul z0.b, z1.b, z2.b"),
            (0x0422_6420, .pmul, "pmul z0.b, z1.b, z2.b"),
            (0x0422_6820, .smulh, "smulh z0.b, z1.b, z2.b"),
            (0x0422_6C20, .umulh, "umulh z0.b, z1.b, z2.b"),
            (0x0422_7020, .sqdmulh, "sqdmulh z0.b, z1.b, z2.b"),
            (0x0422_7420, .sqrdmulh, "sqrdmulh z0.b, z1.b, z2.b"),
            (0x0422_7820, .addqp, "addqp z0.b, z1.b, z2.b"),
            (0x0422_7C20, .addsubp, "addsubp z0.b, z1.b, z2.b"),
        ]
        for (encoding, mnemonic, expected) in rows {
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
        }
        #expect(decode(0x0462_6420).mnemonic == .undefined, "pmul above byte")
    }

    @Test func theLogicalFamilyIsAlwaysDoubleword() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x0422_3020, .and, "and z0.d, z1.d, z2.d"),
            (0x0462_3020, .orr, "orr z0.d, z1.d, z2.d"),
            (0x04A2_3020, .eor, "eor z0.d, z1.d, z2.d"),
            (0x04E2_3020, .bic, "bic z0.d, z1.d, z2.d"),
        ]
        for (encoding, mnemonic, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(Array(d.operands) == [z(0, .d), z(1, .d), z(2, .d)])
        }
    }

    @Test func orrOfARegisterWithItselfIsTheVectorMove() {
        let d = decode(0x0461_3020) // mov z0.d, z1.d
        #expect(d.mnemonic == .mov)
        #expect(text(0x0461_3020) == "mov z0.d, z1.d")
        #expect(Array(d.operands) == [z(0, .d), z(1, .d)])
        #expect(canonicalIndices(d.semanticReads) == [33])
        #expect(canonicalIndices(d.semanticWrites) == [32])
        // One register apart, the alias must not fire — and EOR with equal
        // sources has no alias at all.
        #expect(decode(0x0462_3020).mnemonic == .orr)
        #expect(decode(0x04A0_3020).mnemonic == .eor)
        #expect(text(0x04A0_3020) == "eor z0.d, z1.d, z0.d")
    }

    @Test func theWideShiftsReadADoublewordShiftVector() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x0422_8020, .asr, "asr z0.b, z1.b, z2.d"),
            (0x0422_8420, .lsr, "lsr z0.b, z1.b, z2.d"),
            (0x0422_8C20, .lsl, "lsl z0.b, z1.b, z2.d"),
            (0x04A0_8000, .asr, "asr z0.s, z0.s, z0.d"),
        ]
        for (encoding, mnemonic, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
        }
        #expect(decode(0x04E2_8020).mnemonic == .undefined, "wide shift at doubleword")
        #expect(decode(0x0422_8820).mnemonic == .undefined, "reserved wide-shift opcode")
    }

    @Test func theImmediateShiftsDecodeTheJointElementAndAmount() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x0428_9020, .asr, "asr z0.b, z1.b, #8"),
            (0x0428_9420, .lsr, "lsr z0.b, z1.b, #8"),
            (0x0428_9C20, .lsl, "lsl z0.b, z1.b, #0"),
            (0x042F_9020, .asr, "asr z0.b, z1.b, #1"),
        ]
        for (encoding, mnemonic, expected) in rows {
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
        }
        #expect(decode(0x0428_9820).mnemonic == .undefined, "reserved immediate-shift opcode")
        #expect(decode(0x0420_9020).mnemonic == .undefined, "immediate shift with a zero tsz")
    }

    @Test func addressGenerationRendersItsFourExtendShapes() {
        // Bits 23:22 select unpacked sxtw/uxtw doubleword and packed word/
        // doubleword; the packed forms elide `lsl #0` and print it otherwise.
        let rows: [(UInt32, String)] = [
            (0x0422_A020, "adr z0.d, [z1.d, z2.d, sxtw]"),
            (0x0422_A820, "adr z0.d, [z1.d, z2.d, sxtw #2]"),
            (0x0462_A020, "adr z0.d, [z1.d, z2.d, uxtw]"),
            (0x0462_A420, "adr z0.d, [z1.d, z2.d, uxtw #1]"),
            (0x04A2_A020, "adr z0.s, [z1.s, z2.s]"),
            (0x04A2_AC20, "adr z0.s, [z1.s, z2.s, lsl #3]"),
            (0x04E2_A020, "adr z0.d, [z1.d, z2.d]"),
        ]
        for (encoding, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == .adr, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticReads) == [33, 34], "\(expected) reads base and index")
            #expect(canonicalIndices(d.semanticWrites) == [32])
            #expect(d.memoryAccess == .none, "ADR computes an address, it never touches memory")
        }
    }

    @Test func everyTernaryOpcodeIsDoublewordAndDestructive() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x0421_3840, .eor3, "eor3 z0.d, z0.d, z1.d, z2.d"),
            (0x0421_3C40, .bsl, "bsl z0.d, z0.d, z1.d, z2.d"),
            (0x0461_3840, .bcax, "bcax z0.d, z0.d, z1.d, z2.d"),
            (0x0461_3C40, .bsl1n, "bsl1n z0.d, z0.d, z1.d, z2.d"),
            (0x04A1_3C40, .bsl2n, "bsl2n z0.d, z0.d, z1.d, z2.d"),
            (0x04E1_3C40, .nbsl, "nbsl z0.d, z0.d, z1.d, z2.d"),
        ]
        for (encoding, mnemonic, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticReads) == [32, 33, 34], "\(expected) reads Zdn, Zk and Zm")
            #expect(canonicalIndices(d.semanticWrites) == [32])
            #expect(d.scalableEffect == .readsStreamingMode, "\(expected) recomputes every lane")
        }
        #expect(decode(0x04A1_3840).mnemonic == .undefined, "reserved ternary opcode 100")
        #expect(decode(0x04E1_3840).mnemonic == .undefined, "reserved ternary opcode 110")
    }

    @Test func rotateXorDecodesTheTszRotationAtEverySize() {
        let d = decode(0x042F_3420) // xar z0.b, z0.b, z1.b, #1
        #expect(d.mnemonic == .xar)
        #expect(text(0x042F_3420) == "xar z0.b, z0.b, z1.b, #1")
        #expect(Array(d.operands) == [z(0, .b), z(0, .b), z(1, .b), .immediate(value: 1, width: 8)])
        #expect(canonicalIndices(d.semanticReads) == [32, 33], "XAR reads Zdn and Zm")
        #expect(canonicalIndices(d.semanticWrites) == [32])
        #expect(text(0x04A0_3420) == "xar z0.d, z0.d, z1.d, #64")
        #expect(decode(0x0420_3420).mnemonic == .undefined, "xar with a zero tsz")
    }
}
