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

/// Validates the FP reductions.
@Suite("SVE floating-point / reductions")
struct SVEFPReductionDecodeTests {
    private static let fastBase: UInt32 = 0x6540_2440

    @Test func everyFastReductionDecodesToAScalarOfElementWidth() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0b000, .faddv, "faddv"), (0b100, .fmaxnmv, "fmaxnmv"),
            (0b101, .fminnmv, "fminnmv"), (0b110, .fmaxv, "fmaxv"), (0b111, .fminv, "fminv"),
        ]
        for (opc, mnemonic, name) in rows {
            let encoding = Self.fastBase | (opc << 16)
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == "\(name) h0, p1, z2.h")
            #expect(canonicalIndices(d.semanticReads) == [34], "\(name) reads Zn")
            #expect(canonicalIndices(d.semanticWrites) == [32], "\(name) writes the V scalar dest")
            #expect(d.scalableEffect == .readsStreamingMode, "a fresh scalar is a full write")
        }
        for opc: UInt32 in [0b001, 0b010, 0b011] {
            #expect(decode(Self.fastBase | (opc << 16)).mnemonic == .undefined, "reserved fast-reduction opcode")
        }
    }

    @Test func fastReductionScalarWidthTracksTheElementSize() {
        let base = Self.fastBase & ~(UInt32(0b11) << 22)
        #expect(text(base | (0b01 << 22)) == "faddv h0, p1, z2.h")
        #expect(text(base | (0b10 << 22)) == "faddv s0, p1, z2.s")
        #expect(text(base | (0b11 << 22)) == "faddv d0, p1, z2.d")
        #expect(decode(base).mnemonic == .undefined, "sz=00 hole")
    }

    private static let faddaBase: UInt32 = 0x6558_2440

    @Test func faddaCarriesTheScalarAccumulatorTwice() {
        let d = decode(Self.faddaBase)
        #expect(d.mnemonic == .fadda)
        #expect(text(Self.faddaBase) == "fadda h0, p1, h0, z2.h")
        #expect(canonicalIndices(d.semanticReads) == [32, 34], "fadda reads Vdn and Zm")
        #expect(canonicalIndices(d.semanticWrites) == [32])
        #expect(d.scalableEffect == .readsStreamingMode, "a full V-register write")
    }

    @Test func faddaTakesEverySizeAndRejectsItsHoles() {
        let base = Self.faddaBase & ~(UInt32(0b11) << 22)
        #expect(text(base | (0b10 << 22)) == "fadda s0, p1, s0, z2.s")
        #expect(text(base | (0b11 << 22)) == "fadda d0, p1, d0, z2.d")
        #expect(decode(base).mnemonic == .undefined, "sz=00 hole")
        #expect(decode(Self.faddaBase | (1 << 16)).mnemonic == .undefined, "bits[18:16] must be zero")
    }

    private static let quadBase: UInt32 = 0x6450_A440

    @Test func everyQuadwordReductionDecodesToANeonArrangement() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0b000, .faddqv, "faddqv"), (0b100, .fmaxnmqv, "fmaxnmqv"),
            (0b101, .fminnmqv, "fminnmqv"), (0b110, .fmaxqv, "fmaxqv"), (0b111, .fminqv, "fminqv"),
        ]
        for (opc, mnemonic, name) in rows {
            let encoding = Self.quadBase | (opc << 16)
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == "\(name) v0.8h, p1, z2.h")
            #expect(canonicalIndices(d.semanticWrites) == [32])
            #expect(d.scalableEffect == .readsStreamingMode)
        }
        for opc: UInt32 in [0b001, 0b010, 0b011] {
            #expect(decode(Self.quadBase | (opc << 16)).mnemonic == .undefined, "reserved quad-reduction opcode")
        }
    }

    @Test func quadwordArrangementTracksTheElementSize() {
        let base = Self.quadBase & ~(UInt32(0b11) << 22)
        #expect(text(base | (0b01 << 22)) == "faddqv v0.8h, p1, z2.h")
        #expect(text(base | (0b10 << 22)) == "faddqv v0.4s, p1, z2.s")
        #expect(text(base | (0b11 << 22)) == "faddqv v0.2d, p1, z2.d")
        #expect(decode(base).mnemonic == .undefined, "sz=00 hole")
    }
}
