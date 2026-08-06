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

/// Validates the unpredicated forms.
@Suite("SVE floating-point / unpredicated arithmetic, clamp, trig carve-outs")
struct SVEFPUnpredicatedDecodeTests {
    private static let threeOpBase: UInt32 = 0x6542_0020

    @Test func everyUnpredicatedThreeOpDecodes() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0b000, .fadd, "fadd"), (0b001, .fsub, "fsub"), (0b010, .fmul, "fmul"),
            (0b011, .ftsmul, "ftsmul"), (0b110, .frecps, "frecps"), (0b111, .frsqrts, "frsqrts"),
        ]
        for (opc, mnemonic, name) in rows {
            let encoding = Self.threeOpBase | (opc << 10)
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == "\(name) z0.h, z1.h, z2.h")
            #expect(canonicalIndices(d.semanticReads) == [33, 34], "\(name) reads Zn and Zm, not the destination")
            #expect(canonicalIndices(d.semanticWrites) == [32])
            #expect(d.scalableEffect == .readsStreamingMode)
        }
        for opc: UInt32 in [0b100, 0b101] {
            #expect(decode(Self.threeOpBase | (opc << 10)).mnemonic == .undefined, "reserved 3-op opcode")
        }
    }

    @Test func theThreeOpSizeZeroSlotsAreBf16() {
        let base = Self.threeOpBase & ~(UInt32(0b11) << 22)
        #expect(text(base | (0b000 << 10)) == "bfadd z0.h, z1.h, z2.h")
        #expect(text(base | (0b001 << 10)) == "bfsub z0.h, z1.h, z2.h")
        #expect(text(base | (0b010 << 10)) == "bfmul z0.h, z1.h, z2.h")
        #expect(decode(base | (0b011 << 10)).mnemonic == .undefined, "no bf16 ftsmul")
    }

    private static let recipBase: UInt32 = 0x654E_3020

    @Test func reciprocalEstimateSelectsOnBitSixteen() {
        #expect(decode(Self.recipBase).mnemonic == .frecpe)
        #expect(text(Self.recipBase) == "frecpe z0.h, z1.h")
        #expect(decode(Self.recipBase | (1 << 16)).mnemonic == .frsqrte)
        #expect(text(Self.recipBase | (1 << 16)) == "frsqrte z0.h, z1.h")
        let d = decode(Self.recipBase)
        #expect(canonicalIndices(d.semanticReads) == [33])
        #expect(canonicalIndices(d.semanticWrites) == [32])
    }

    @Test func reciprocalEstimateTakesEverySize() {
        let base = Self.recipBase & ~(UInt32(0b11) << 22)
        #expect(text(base | (0b10 << 22)) == "frecpe z0.s, z1.s")
        #expect(text(base | (0b11 << 22)) == "frecpe z0.d, z1.d")
        #expect(decode(base).mnemonic == .undefined, "sz=00 hole")
    }

    private static let clampBase: UInt32 = 0x6462_2420

    @Test func clampIsAThreeSourceDestructiveForm() {
        let d = decode(Self.clampBase)
        #expect(d.mnemonic == .fclamp)
        #expect(text(Self.clampBase) == "fclamp z0.h, z1.h, z2.h")
        #expect(canonicalIndices(d.semanticReads) == [32, 33, 34], "fclamp reads Zd, Zn and Zm")
        #expect(canonicalIndices(d.semanticWrites) == [32])
        #expect(d.scalableEffect == .readsStreamingMode, "every lane is recomputed — a full write")
        #expect(text(Self.clampBase & ~(UInt32(0b11) << 22)) == "bfclamp z0.h, z1.h, z2.h")
    }

    private static let fabsMergeBase: UInt32 = 0x045C_A420

    @Test func fabsAndFnegDecodeInBothQualifiers() {
        #expect(text(Self.fabsMergeBase) == "fabs z0.h, p1/m, z1.h")
        #expect(text(Self.fabsMergeBase | (1 << 16)) == "fneg z0.h, p1/m, z1.h")
        #expect(text(Self.fabsMergeBase & ~(UInt32(1) << 20)) == "fabs z0.h, p1/z, z1.h")
        #expect(text((Self.fabsMergeBase | (1 << 16)) & ~(UInt32(1) << 20)) == "fneg z0.h, p1/z, z1.h")
    }

    @Test func fabsMergingReadsItsDestinationButZeroingDoesNot() {
        let merging = decode(Self.fabsMergeBase)
        #expect(merging.scalableEffect == [.readsStreamingMode, .partialWrite])
        #expect(canonicalIndices(merging.semanticReads) == [32, 33], "/m reads the destination")

        let zeroing = decode(Self.fabsMergeBase & ~(UInt32(1) << 20))
        #expect(zeroing.scalableEffect == .readsStreamingMode, "/z is a full write")
        #expect(canonicalIndices(zeroing.semanticReads) == [33], "/z reads only the source")
    }

    @Test func fabsAndFnegTakeEverySize() {
        let base = Self.fabsMergeBase & ~(UInt32(0b11) << 22)
        #expect(text(base | (0b10 << 22)) == "fabs z0.s, p1/m, z1.s")
        #expect(text(base | (0b11 << 22)) == "fabs z0.d, p1/m, z1.d")
    }

    private static let ftsselBase: UInt32 = 0x0462_B020

    @Test func ftsselIsAnUnpredicatedTwoSourceForm() {
        let d = decode(Self.ftsselBase)
        #expect(d.mnemonic == .ftssel)
        #expect(text(Self.ftsselBase) == "ftssel z0.h, z1.h, z2.h")
        #expect(canonicalIndices(d.semanticReads) == [33, 34])
        #expect(canonicalIndices(d.semanticWrites) == [32])
        let base = Self.ftsselBase & ~(UInt32(0b11) << 22)
        #expect(text(base | (0b10 << 22)) == "ftssel z0.s, z1.s, z2.s")
    }

    private static let fexpaBase: UInt32 = 0x0460_B820

    @Test func fexpaIsAnUnpredicatedUnaryForm() {
        let d = decode(Self.fexpaBase)
        #expect(d.mnemonic == .fexpa)
        #expect(text(Self.fexpaBase) == "fexpa z0.h, z1.h")
        #expect(canonicalIndices(d.semanticReads) == [33], "fexpa reads only Zn")
        #expect(canonicalIndices(d.semanticWrites) == [32])
        let base = Self.fexpaBase & ~(UInt32(0b11) << 22)
        #expect(text(base | (0b11 << 22)) == "fexpa z0.d, z1.d")
    }
}
