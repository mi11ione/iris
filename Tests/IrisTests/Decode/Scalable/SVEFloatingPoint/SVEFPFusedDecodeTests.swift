// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ e: UInt32) -> Instruction {
    Iris.decode(e, at: 0)
}

private func text(_ e: UInt32) -> String {
    decode(e).text
}

private func canonicalIndices(_ set: RegisterSet) -> [Int] {
    (0 ..< 64).filter { (set.mask >> UInt64($0)) & 1 == 1 }
}

/// Validates the predicated fused multiply-add groups.
@Suite("SVE floating-point / fused multiply-add and FTMAD")
struct SVEFPFusedDecodeTests {
    private static let fmlaBase: UInt32 = 0x6562_0420

    @Test func everyAccumulatorOpcodeReadsAllThreeSources() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0b00, .fmla, "fmla"), (0b01, .fmls, "fmls"),
            (0b10, .fnmla, "fnmla"), (0b11, .fnmls, "fnmls"),
        ]
        for (opc, mnemonic, name) in rows {
            let encoding = Self.fmlaBase | (opc << 13)
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == "\(name) z0.h, p1/m, z1.h, z2.h")
            #expect(canonicalIndices(d.semanticReads) == [32, 33, 34], "\(name) reads Zda, Zn, Zm")
            #expect(canonicalIndices(d.semanticWrites) == [32])
            #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite], "\(name) is merging")
        }
    }

    @Test func theAccumulatorSizeZeroSlotsAreTheBf16Twins() {
        let base = Self.fmlaBase & ~(UInt32(0b11) << 22)
        #expect(text(base) == "bfmla z0.h, p1/m, z1.h, z2.h")
        #expect(text(base | (0b01 << 13)) == "bfmls z0.h, p1/m, z1.h, z2.h")
        #expect(decode(base | (0b10 << 13)).mnemonic == .undefined)
        #expect(decode(base | (0b11 << 13)).mnemonic == .undefined)
    }

    private static let fmadBase: UInt32 = 0x6564_8460

    @Test func everyMultiplicandOpcodeUsesTheReversedFieldOrder() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0b00, .fmad, "fmad"), (0b01, .fmsb, "fmsb"),
            (0b10, .fnmad, "fnmad"), (0b11, .fnmsb, "fnmsb"),
        ]
        for (opc, mnemonic, name) in rows {
            let encoding = Self.fmadBase | (opc << 13)
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == "\(name) z0.h, p1/m, z3.h, z4.h")
            #expect(canonicalIndices(d.semanticReads) == [32, 35, 36], "\(name) reads Zdn, Zm, Za")
            #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite])
        }
        #expect(decode(Self.fmadBase & ~(UInt32(0b11) << 22)).mnemonic == .undefined)
    }

    @Test func bothPredicatedFamiliesTakeEverySize() {
        let fmla = Self.fmlaBase & ~(UInt32(0b11) << 22)
        let fmad = Self.fmadBase & ~(UInt32(0b11) << 22)
        #expect(text(fmla | (0b10 << 22)) == "fmla z0.s, p1/m, z1.s, z2.s")
        #expect(text(fmla | (0b11 << 22)) == "fmla z0.d, p1/m, z1.d, z2.d")
        #expect(text(fmad | (0b10 << 22)) == "fmad z0.s, p1/m, z3.s, z4.s")
        #expect(text(fmad | (0b11 << 22)) == "fmad z0.d, p1/m, z3.d, z4.d")
    }

    private static let ftmadBase: UInt32 = 0x6550_8020

    @Test func ftmadRendersItsCoefficientIndexAndRewritesEveryLane() {
        let d = decode(Self.ftmadBase)
        #expect(d.mnemonic == .ftmad)
        #expect(text(Self.ftmadBase) == "ftmad z0.h, z0.h, z1.h, #0")
        #expect(text(Self.ftmadBase | (7 << 16)) == "ftmad z0.h, z0.h, z1.h, #7")
        #expect(canonicalIndices(d.semanticReads) == [32, 33], "ftmad reads Zdn and Zm")
        #expect(canonicalIndices(d.semanticWrites) == [32])
        #expect(d.scalableEffect == .readsStreamingMode)
    }

    @Test func ftmadRejectsANonZeroPredicateFieldAndSizeZero() {
        #expect(decode(Self.ftmadBase | (1 << 10)).mnemonic == .undefined, "bits[12:10] must be zero")
        #expect(decode(Self.ftmadBase & ~(UInt32(0b11) << 22)).mnemonic == .undefined, "sz=00 hole")
    }
}
