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

/// Validates the SVE2 crypto cluster at 0x45.
@Suite("SVE crypto / AES, SM4, RAX1, polynomial multiply")
struct SVECryptoDecodeTests {
    private static let destructive: [(UInt32, Mnemonic, String)] = [
        (0x4522_E020, .aese, "aese z0.b, z0.b, z1.b"),
        (0x4522_E420, .aesd, "aesd z0.b, z0.b, z1.b"),
        (0x4523_E020, .sm4e, "sm4e z0.s, z0.s, z1.s"),
    ]

    @Test func everyDestructiveRoundReadsItsAccumulator() {
        for (encoding, mnemonic, expected) in Self.destructive {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.memoryAccess == .none)
            #expect(d.scalableEffect == .readsStreamingMode)
            #expect(canonicalIndices(d.semanticReads) == [32, 33])
            #expect(canonicalIndices(d.semanticWrites) == [32])
        }
    }

    @Test func unaryMixColumnsIsAByteToByteDestructiveMove() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x4520_E000, .aesmc, "aesmc z0.b, z0.b"),
            (0x4520_E400, .aesimc, "aesimc z0.b, z0.b"),
        ]
        for (encoding, mnemonic, expected) in rows {
            #expect(decode(encoding).mnemonic == mnemonic)
            #expect(text(encoding) == expected)
        }
    }

    private static let constructive: [(UInt32, Mnemonic, String)] = [
        (0x4522_F020, .sm4ekey, "sm4ekey z0.s, z1.s, z2.s"),
        (0x4522_F420, .rax1, "rax1 z0.d, z1.d, z2.d"),
    ]

    @Test func everyConstructiveFormWritesAFreshDestination() {
        for (encoding, mnemonic, expected) in Self.constructive {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticReads) == [33, 34])
            #expect(canonicalIndices(d.semanticWrites) == [32])
        }
    }

    @Test func polynomialMultiplyWritesAQuadwordPair() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x4522_F820, .pmull, "pmull { z0.q, z1.q }, z1.d, z2.d"),
            (0x4522_FC20, .pmlal, "pmlal { z0.q, z1.q }, z1.d, z2.d"),
        ]
        for (encoding, mnemonic, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticWrites) == [32, 33])
            #expect(canonicalIndices(d.semanticReads) == [33, 34])
        }
    }

    @Test func multiVectorAesGroupsTwoAndFourVectors() {
        let pair = decode(0x4522_E800)
        #expect(pair.mnemonic == .aese)
        #expect(text(0x4522_E800) == "aese { z0.b, z1.b }, { z0.b, z1.b }, z0.q[0]")
        #expect(canonicalIndices(pair.semanticWrites) == [32, 33])

        let quad = decode(0x4526_E800)
        #expect(text(0x4526_E800) == "aese { z0.b - z3.b }, { z0.b - z3.b }, z0.q[0]")
        #expect(canonicalIndices(quad.semanticWrites) == [32, 33, 34, 35])

        #expect(decode(0x4527_E800).mnemonic == .aesemc)
        #expect(text(0x4527_E800) == "aesemc { z0.b - z3.b }, { z0.b - z3.b }, z0.q[0]")
        #expect(decode(0x4527_EC00).mnemonic == .aesdimc)
    }

    @Test func reservedCryptoOpcodesAreUndefined() {
        for encoding: UInt32 in [
            0x4520_E020,
            0x4524_E800,
        ] {
            #expect(decode(encoding).mnemonic == .undefined, "0x\(String(encoding, radix: 16))")
        }
    }
}

/// Validates the LUT cluster at 0x45 (bits[15:13]=101).
@Suite("SVE crypto / lookup-table LUTI2/LUTI4/LUTI6")
struct SVELutiDecodeTests {
    private static let rows: [(UInt32, Mnemonic, String)] = [
        (0x4520_B000, .luti2, "luti2 z0.b, { z0.b }, z0[0]"),
        (0x4520_A800, .luti2, "luti2 z0.h, { z0.h }, z0[0]"),
        (0x4560_A400, .luti4, "luti4 z0.b, { z0.b }, z0[0]"),
        (0x4520_BC00, .luti4, "luti4 z0.h, { z0.h }, z0[0]"),
        (0x4520_B400, .luti4, "luti4 z0.h, { z0.h, z1.h }, z0[0]"),
        (0x4520_AC00, .luti6, "luti6 z0.b, { z0.b, z1.b }, z0"),
        (0x4560_AC00, .luti6, "luti6 z0.h, { z0.h, z1.h }, z0[0]"),
    ]

    @Test func everyLutiFormDecodes() {
        for (encoding, mnemonic, expected) in Self.rows {
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(decode(encoding).memoryAccess == .none)
        }
    }

    @Test func twoRegisterTableReadsBothMembers() {
        let d = decode(0x4522_B420)
        #expect(d.mnemonic == .luti4)
        #expect(text(0x4522_B420) == "luti4 z0.h, { z1.h, z2.h }, z2[0]")
        #expect(canonicalIndices(d.semanticReads) == [33, 34])
        #expect(canonicalIndices(d.semanticWrites) == [32])
    }
}
