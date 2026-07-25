// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ e: UInt32) -> Instruction {
    Iris.decode(e, at: 0, features: .scalable)
}

private func text(_ e: UInt32) -> String {
    decode(e).text
}

private func canonicalIndices(_ set: RegisterSet) -> [Int] {
    (0 ..< 64).filter { (set.mask >> UInt64($0)) & 1 == 1 }
}

/// Validates the predicated FP binary arithmetic groups: G1 register form
/// (`sve_fp_2op_p_zds`), G2 the two-constant arith immediate
/// (`sve_fp_2op_i_p_zds`), and G16 pairwise (`sve2_fp_pairwise_pred`). All
/// three are merging-predicated destructive forms — the destination is read,
/// the write is partial, the governing predicate is `/m` — and the sz=00 slots
/// are either the B16B16 bf16 twin or an architectural hole, decided per
/// opcode rather than by a blanket size gate.
@Suite("SVE floating-point / predicated binary, immediate, pairwise")
struct SVEFPBinaryDecodeTests {
    /// fadd z0.h, p1/m, z0.h, z2.h — the class base (opc=0, sz=.h, Pg=1, Zm=2).
    private static let g1Base: UInt32 = 0x6540_8440

    @Test func everyRegisterOpcodeDecodesAtHalfPrecision() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x0, .fadd, "fadd"), (0x1, .fsub, "fsub"), (0x2, .fmul, "fmul"),
            (0x3, .fsubr, "fsubr"), (0x4, .fmaxnm, "fmaxnm"), (0x5, .fminnm, "fminnm"),
            (0x6, .fmax, "fmax"), (0x7, .fmin, "fmin"), (0x8, .fabd, "fabd"),
            (0x9, .fscale, "fscale"), (0xA, .fmulx, "fmulx"), (0xC, .fdivr, "fdivr"),
            (0xD, .fdiv, "fdiv"), (0xE, .famax, "famax"), (0xF, .famin, "famin"),
        ]
        for (opc, mnemonic, name) in rows {
            let encoding = Self.g1Base | (opc << 16)
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == "\(name) z0.h, p1/m, z0.h, z2.h")
            #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite], "\(name) is merging")
            #expect(canonicalIndices(d.semanticReads) == [32, 34], "\(name) reads Zdn and Zm")
            #expect(canonicalIndices(d.semanticWrites) == [32])
            #expect(d.flagEffect == .none)
        }
        #expect(decode(Self.g1Base | (0xB << 16)).mnemonic == .undefined, "opc 1011 is a hole")
    }

    @Test func theRegisterFormTakesEverySize() {
        // sz 01/10/11 → h/s/d; the base opcode fadd renders each.
        let base = Self.g1Base & ~(UInt32(0b11) << 22)
        #expect(text(base | (0b01 << 22)) == "fadd z0.h, p1/m, z0.h, z2.h")
        #expect(text(base | (0b10 << 22)) == "fadd z0.s, p1/m, z0.s, z2.s")
        #expect(text(base | (0b11 << 22)) == "fadd z0.d, p1/m, z0.d, z2.d")
    }

    @Test func theSizeZeroSlotsAreTheBf16Twins() {
        // sz=00 replaces the fp form with its bfloat16 sibling where one exists.
        let base = Self.g1Base & ~(UInt32(0b11) << 22) // sz=00
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x0, .bfadd, "bfadd"), (0x1, .bfsub, "bfsub"), (0x2, .bfmul, "bfmul"),
            (0x4, .bfmaxnm, "bfmaxnm"), (0x5, .bfminnm, "bfminnm"), (0x6, .bfmax, "bfmax"),
            (0x7, .bfmin, "bfmin"), (0x9, .bfscale, "bfscale"),
        ]
        for (opc, mnemonic, name) in rows {
            let encoding = base | (opc << 16)
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == "\(name) z0.h, p1/m, z0.h, z2.h")
        }
        // sz=00 with an opcode that has no bf16 twin is a hole (fdiv, famax…).
        for opc: UInt32 in [0x3, 0x8, 0xA, 0xC, 0xD, 0xE, 0xF] {
            #expect(decode(base | (opc << 16)).mnemonic == .undefined, "sz=00 opc \(opc) is a hole")
        }
    }

    /// fadd z0.h, p1/m, z0.h, #0.5 — the immediate class base (opc=0, i1=0).
    private static let g2Base: UInt32 = 0x6558_8400

    @Test func everyImmediateOpcodeRendersItsConstantPair() {
        // i1 selects the low/high constant, and the pair differs per mnemonic.
        let rows: [(UInt32, Mnemonic, String, String, String)] = [
            (0b000, .fadd, "fadd", "#0.5", "#1.0"),
            (0b001, .fsub, "fsub", "#0.5", "#1.0"),
            (0b010, .fmul, "fmul", "#0.5", "#2.0"),
            (0b011, .fsubr, "fsubr", "#0.5", "#1.0"),
            (0b100, .fmaxnm, "fmaxnm", "#0.0", "#1.0"),
            (0b101, .fminnm, "fminnm", "#0.0", "#1.0"),
            (0b110, .fmax, "fmax", "#0.0", "#1.0"),
            (0b111, .fmin, "fmin", "#0.0", "#1.0"),
        ]
        for (opc, mnemonic, name, lowConst, highConst) in rows {
            let low = Self.g2Base | (opc << 16)
            let high = low | (1 << 5)
            #expect(decode(low).mnemonic == mnemonic, "0x\(String(low, radix: 16))")
            #expect(text(low) == "\(name) z0.h, p1/m, z0.h, \(lowConst)")
            #expect(text(high) == "\(name) z0.h, p1/m, z0.h, \(highConst)")
        }
    }

    @Test func theImmediateFormIsMergingAndReadsItsDestination() {
        let d = decode(Self.g2Base)
        #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite])
        #expect(canonicalIndices(d.semanticReads) == [32], "the immediate form reads only Zdn")
        #expect(canonicalIndices(d.semanticWrites) == [32])
    }

    @Test func theImmediateFormRejectsANonZeroFixedFieldAndSizeZero() {
        // bits[9:6] are a fixed zero field; sz=00 has no immediate form.
        #expect(decode(Self.g2Base | (1 << 6)).mnemonic == .undefined, "nonzero fixed field")
        #expect(decode(Self.g2Base & ~(UInt32(0b11) << 22)).mnemonic == .undefined, "sz=00 hole")
    }

    /// faddp z0.h, p1/m, z0.h, z2.h — the pairwise class base.
    private static let g16Base: UInt32 = 0x6450_8440

    @Test func everyPairwiseOpcodeDecodes() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0b000, .faddp, "faddp"), (0b100, .fmaxnmp, "fmaxnmp"),
            (0b101, .fminnmp, "fminnmp"), (0b110, .fmaxp, "fmaxp"), (0b111, .fminp, "fminp"),
        ]
        for (opc, mnemonic, name) in rows {
            let encoding = Self.g16Base | (opc << 16)
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == "\(name) z0.h, p1/m, z0.h, z2.h")
            #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite])
        }
        for opc: UInt32 in [0b001, 0b010, 0b011] {
            #expect(decode(Self.g16Base | (opc << 16)).mnemonic == .undefined, "pairwise opc \(opc) hole")
        }
        #expect(decode(Self.g16Base & ~(UInt32(0b11) << 22)).mnemonic == .undefined, "pairwise sz=00 hole")
    }
}
