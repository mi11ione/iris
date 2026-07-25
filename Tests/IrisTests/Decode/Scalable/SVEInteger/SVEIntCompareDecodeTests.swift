// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0, features: .scalable)
}

private func text(_ encoding: UInt32) -> String {
    decode(encoding).text
}

private func predicates(_ set: ScalableRegisterSet) -> [UInt8] {
    (0 ..< 16).filter { set.containsPredicate(UInt8($0)) }.map(UInt8.init)
}

private func canonicalIndices(_ set: RegisterSet) -> [Int] {
    (0 ..< 64).filter { (set.mask >> UInt64($0)) & 1 == 1 }
}

/// Validates the integer compare-to-predicate group: the vector and wide
/// forms at top byte 0x24, the unsigned-immediate form (bit21), and the
/// signed-immediate form at 0x25. Every compare writes its destination
/// predicate AND NZCV — the load-bearing contrast with the FP compares, which
/// write a predicate but no flags. The vector CMPLE/CMPLT/CMPLO/CMPLS are
/// assembler-only swap aliases: the bit patterns that would spell them are
/// the wide (Zm.d) encodings, so a narrow cmple/cmplt/cmplo/cmpls must never
/// be emitted, while the wide and immediate ones are real and must be.
@Suite("SVE integer / compare to predicate")
struct SVEIntCompareDecodeTests {
    /// Every vector/wide compare slot: bits 15:13 select the pair, bit 4 the
    /// second member; the wide rows read Zm at doubleword.
    private static let vectorAndWide: [(UInt32, Mnemonic, Bool, String)] = [
        (0x2402_0020, .cmphs, false, "cmphs p0.b, p0/z, z1.b, z2.b"),
        (0x2402_0030, .cmphi, false, "cmphi p0.b, p0/z, z1.b, z2.b"),
        (0x2402_2020, .cmpeq, true, "cmpeq p0.b, p0/z, z1.b, z2.d"),
        (0x2402_8020, .cmpge, false, "cmpge p0.b, p0/z, z1.b, z2.b"),
        (0x2402_8030, .cmpgt, false, "cmpgt p0.b, p0/z, z1.b, z2.b"),
        (0x2402_A020, .cmpeq, false, "cmpeq p0.b, p0/z, z1.b, z2.b"),
        (0x2402_6020, .cmplt, true, "cmplt p0.b, p0/z, z1.b, z2.d"),
        (0x2402_6030, .cmple, true, "cmple p0.b, p0/z, z1.b, z2.d"),
        (0x2402_C020, .cmphs, true, "cmphs p0.b, p0/z, z1.b, z2.d"),
        (0x2402_C030, .cmphi, true, "cmphi p0.b, p0/z, z1.b, z2.d"),
        (0x2402_E020, .cmplo, true, "cmplo p0.b, p0/z, z1.b, z2.d"),
        (0x2402_E030, .cmpls, true, "cmpls p0.b, p0/z, z1.b, z2.d"),
    ]

    @Test func everyCompareSlotDecodesWithItsWideness() {
        for (encoding, mnemonic, wide, expected) in Self.vectorAndWide {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            let zm = d.operands[3]
            #expect(
                zm == .scalableVector(ScalableVectorRef(registerIndex: 2, element: wide ? .d : .b)),
                "\(expected) second source width",
            )
        }
    }

    @Test func everyCompareWritesItsPredicateAndNZCV() {
        for (encoding, _, _, expected) in Self.vectorAndWide {
            let d = decode(encoding)
            #expect(d.flagEffect == .nzcv, "\(expected) must set NZCV")
            #expect(predicates(d.scalableReads) == [0], "\(expected) reads its governing predicate")
            #expect(predicates(d.scalableWrites) == [0], "\(expected) writes Pd")
            #expect(canonicalIndices(d.semanticReads) == [33, 34])
            #expect(canonicalIndices(d.semanticWrites) == [], "\(expected) writes no Z register")
            #expect(d.scalableEffect == .readsStreamingMode)
        }
    }

    @Test func aNarrowLessThanCompareIsNeverEmitted() {
        // The four "swapped" spellings exist only in the assembler. Every
        // vector-form encoding decodes to cmpeq/ne/ge/gt/hi/hs; cmple, cmplt,
        // cmplo and cmpls appear only with a doubleword (wide) or immediate
        // second operand. Sweep every vector/wide slot to prove it.
        for sel: UInt32 in 0 ... 7 {
            for second: UInt32 in 0 ... 1 {
                let encoding = 0x2402_0020 | (sel << 13) | (second << 4)
                let d = decode(encoding)
                guard d.mnemonic == .cmple || d.mnemonic == .cmplt
                    || d.mnemonic == .cmplo || d.mnemonic == .cmpls
                else { continue }
                #expect(
                    d.operands[3] == .scalableVector(ScalableVectorRef(registerIndex: 2, element: .d)),
                    "0x\(String(encoding, radix: 16)) emitted a narrow swapped compare",
                )
            }
        }
    }

    @Test func theWideFormsRejectADoublewordSource() {
        // A wide compare reads Zm.d against elements narrower than doubleword;
        // sz=11 leaves nothing narrower, so the slot is reserved.
        #expect(decode(0x24C2_2020).mnemonic == .undefined)
        #expect(decode(0x24C2_A020).mnemonic == .cmpeq, "the non-wide slot still decodes at doubleword")
        #expect(text(0x24C2_A020) == "cmpeq p0.d, p0/z, z1.d, z2.d")
    }

    @Test func theUnsignedImmediateCompareCarriesASevenBitImmediate() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x2420_0020, .cmphs, "cmphs p0.b, p0/z, z1.b, #0"),
            (0x2420_0030, .cmphi, "cmphi p0.b, p0/z, z1.b, #0"),
            (0x243F_C020, .cmphs, "cmphs p0.b, p0/z, z1.b, #127"),
            (0x2420_2020, .cmplo, "cmplo p0.b, p0/z, z1.b, #0"),
            (0x2420_2030, .cmpls, "cmpls p0.b, p0/z, z1.b, #0"),
            (0x24E0_0020, .cmphs, "cmphs p0.d, p0/z, z1.d, #0"),
        ]
        for (encoding, mnemonic, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.flagEffect == .nzcv)
            #expect(canonicalIndices(d.semanticReads) == [33], "\(expected) reads only Zn")
        }
        let imm = decode(0x243F_C020).operands[3]
        #expect(imm == .unsignedImmediate(value: 127, width: 7))
    }

    @Test func theSignedImmediateCompareSignExtendsItsFiveBits() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x2510_0020, .cmpge, "cmpge p0.b, p0/z, z1.b, #-16"),
            (0x2510_0030, .cmpgt, "cmpgt p0.b, p0/z, z1.b, #-16"),
            (0x2510_2020, .cmplt, "cmplt p0.b, p0/z, z1.b, #-16"),
            (0x2510_2030, .cmple, "cmple p0.b, p0/z, z1.b, #-16"),
            (0x2510_8020, .cmpeq, "cmpeq p0.b, p0/z, z1.b, #-16"),
            (0x2510_8030, .cmpne, "cmpne p0.b, p0/z, z1.b, #-16"),
            (0x250F_8020, .cmpeq, "cmpeq p0.b, p0/z, z1.b, #15"),
            (0x2550_0020, .cmpge, "cmpge p0.h, p0/z, z1.h, #-16"),
        ]
        for (encoding, mnemonic, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.flagEffect == .nzcv)
        }
        #expect(decode(0x2510_0020).operands[3] == .immediate(value: -16, width: 5))
        #expect(decode(0x250F_8020).operands[3] == .immediate(value: 15, width: 5))
        #expect(decode(0x2510_A020).mnemonic == .undefined, "reserved signed-compare opcode")
    }

    @Test func theResultPredicateCarriesItsElementAndTheGoverningStaysBare() {
        let d = decode(0x2482_A020) // cmpeq p0.s, p0/z, z1.s, z2.s
        #expect(text(0x2482_A020) == "cmpeq p0.s, p0/z, z1.s, z2.s")
        #expect(d.operands[0] == .scalablePredicate(
            ScalablePredicateRef(registerIndex: 0, element: .s, role: .result),
        ))
        #expect(d.operands[1] == .scalablePredicate(
            ScalablePredicateRef(registerIndex: 0, qualifier: .zeroing, role: .governing),
        ))
    }
}
