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

private func canonicalIndices(_ set: RegisterSet) -> [Int] {
    (0 ..< 64).filter { (set.mask >> UInt64($0)) & 1 == 1 }
}

private func indexedZm(_ d: Instruction) -> ScalableVectorRef? {
    for op in d.operands {
        if case let .scalableVector(v) = op, v.elementIndex != nil { return v }
    }
    return nil
}

/// Validates the indexed SVE2 integer forms, where the second multiplicand is
/// one broadcast element of Zm.
@Suite("SVE integer / indexed multiplies and multiply-adds")
struct SVEIntIndexedDecodeTests {
    @Test func theIndexedDotProductsScaleTheirIndexWithTheDestination() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x44A2_0020, .sdot, "sdot z0.s, z1.b, z2.b[0]"),
            (0x44A2_0420, .udot, "udot z0.s, z1.b, z2.b[0]"),
            (0x44BA_0020, .sdot, "sdot z0.s, z1.b, z2.b[3]"),
            (0x44E2_0020, .sdot, "sdot z0.d, z1.h, z2.h[0]"),
            (0x44F2_0020, .sdot, "sdot z0.d, z1.h, z2.h[1]"),
            (0x4422_0020, .sdot, "sdot z0.h, z1.b, z2.b[0]"),
        ]
        for (encoding, mnemonic, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticReads) == [32, 33, 34], "\(expected) accumulates")
            #expect(canonicalIndices(d.semanticWrites) == [32])
        }
    }

    @Test func theMixedSignDotsExistOnlyAtWordDestinations() {
        #expect(text(0x44A2_1820) == "usdot z0.s, z1.b, z2.b[0]")
        #expect(text(0x44A2_1C20) == "sudot z0.s, z1.b, z2.b[0]")
        #expect(decode(0x4422_1820).mnemonic == .undefined, "usdot indexed at halfword")
        #expect(decode(0x44E2_1820).mnemonic == .undefined, "usdot indexed at doubleword")
        #expect(indexedZm(decode(0x4422_1820)) == nil, "a hole carries no indexed operand")
    }

    @Test func theSameWidthMultiplyAddsCoverAllThreeWidths() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x4422_0820, .mla, "mla z0.h, z1.h, z2.h[0]"),
            (0x4422_0C20, .mls, "mls z0.h, z1.h, z2.h[0]"),
            (0x4422_1020, .sqrdmlah, "sqrdmlah z0.h, z1.h, z2.h[0]"),
            (0x4422_1420, .sqrdmlsh, "sqrdmlsh z0.h, z1.h, z2.h[0]"),
        ]
        for (encoding, mnemonic, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
        }
    }

    @Test func theWideningMultiplyAddsFoldTheExtraIndexBitAndRejectHalfword() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x44A2_2020, .sqdmlalb, "sqdmlalb z0.s, z1.h, z2.h[0]"),
            (0x44A2_2420, .sqdmlalt, "sqdmlalt z0.s, z1.h, z2.h[0]"),
            (0x44A2_3020, .sqdmlslb, "sqdmlslb z0.s, z1.h, z2.h[0]"),
            (0x44A2_3420, .sqdmlslt, "sqdmlslt z0.s, z1.h, z2.h[0]"),
            (0x44A2_8020, .smlalb, "smlalb z0.s, z1.h, z2.h[0]"),
            (0x44A2_9020, .umlalb, "umlalb z0.s, z1.h, z2.h[0]"),
            (0x44A2_A020, .smlslb, "smlslb z0.s, z1.h, z2.h[0]"),
            (0x44A2_B020, .umlslb, "umlslb z0.s, z1.h, z2.h[0]"),
        ]
        for (encoding, mnemonic, expected) in rows {
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
        }
        #expect(decode(0x4422_2020).mnemonic == .undefined, "widening at a halfword destination")
    }

    @Test func theIndexedMultipliesIncludeTheWideningAndSameWidthForms() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x44A2_C020, .smullb, "smullb z0.s, z1.h, z2.h[0]"),
            (0x44A2_C420, .smullt, "smullt z0.s, z1.h, z2.h[0]"),
            (0x44A2_C820, .smullb, "smullb z0.s, z1.h, z2.h[1]"),
            (0x44A2_D020, .umullb, "umullb z0.s, z1.h, z2.h[0]"),
            (0x44A2_E020, .sqdmullb, "sqdmullb z0.s, z1.h, z2.h[0]"),
            (0x44A2_F020, .sqdmulh, "sqdmulh z0.s, z1.s, z2.s[0]"),
            (0x44A2_F420, .sqrdmulh, "sqrdmulh z0.s, z1.s, z2.s[0]"),
            (0x44A2_F820, .mul, "mul z0.s, z1.s, z2.s[0]"),
            (0x4422_F820, .mul, "mul z0.h, z1.h, z2.h[0]"),
        ]
        for (encoding, mnemonic, expected) in rows {
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
        }
        #expect(canonicalIndices(decode(0x44A2_F820).semanticReads) == [33, 34])
        #expect(decode(0x44A2_FC20).mnemonic == .undefined, "reserved same-width-multiply opcode")
        #expect(decode(0x4422_C020).mnemonic == .undefined, "smullb at a halfword destination")
    }

    @Test func theIndexedComplexFormsKeepTheRotationBelowTheIndex() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x44A2_4020, .cdot, "cdot z0.s, z1.b, z2.b[0], #0"),
            (0x44A2_4C20, .cdot, "cdot z0.s, z1.b, z2.b[0], #270"),
            (0x44E2_4020, .cdot, "cdot z0.d, z1.h, z2.h[0], #0"),
            (0x44A2_6020, .cmla, "cmla z0.h, z1.h, z2.h[0], #0"),
            (0x44E2_6020, .cmla, "cmla z0.s, z1.s, z2.s[0], #0"),
            (0x44A2_7020, .sqrdcmlah, "sqrdcmlah z0.h, z1.h, z2.h[0], #0"),
        ]
        for (encoding, mnemonic, expected) in rows {
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
        }
        #expect(decode(0x44A2_5020).mnemonic == .undefined, "reserved complex-indexed opcode")
        #expect(decode(0x4422_6020).mnemonic == .undefined, "complex-indexed with b23 clear")
    }

    @Test func theRegisterFieldNarrowsAsTheIndexWidens() {
        let halfword = decode(0x44A7_0020)
        #expect(indexedZm(halfword) == ScalableVectorRef(registerIndex: 7, element: .b, elementIndex: 0))
        let doubleword = decode(0x44EA_0020)
        #expect(indexedZm(doubleword) == ScalableVectorRef(registerIndex: 10, element: .h, elementIndex: 0))
        #expect(text(0x44EA_0020) == "sdot z0.d, z1.h, z10.h[0]")
    }

    @Test func theHalfwordIndexAssemblesFromItsThreeScatteredBits() {
        let d = decode(0x447A_0820)
        #expect(text(0x447A_0820) == "mla z0.h, z1.h, z2.h[7]")
        #expect(indexedZm(d) == ScalableVectorRef(registerIndex: 2, element: .h, elementIndex: 7))
    }
}
