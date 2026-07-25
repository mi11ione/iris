// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Every mnemonic constant the SVE floating-point tier declares, grouped as
/// the encoding tables group them.
private let reductions: [Mnemonic] = [
    .fadda, .faddv, .faddqv, .fmaxqv, .fminqv, .fmaxnmqv, .fminnmqv,
]
private let reversed: [Mnemonic] = [.fsubr, .fdivr]
private let compares: [Mnemonic] = [.fcmne, .fcmuo]
private let converts: [Mnemonic] = [
    .fcvtlt, .fcvtnt, .fcvtx, .fcvtxnt, .bfcvtnt, .fcvtnb, .fcvtzsn, .fcvtzun,
]
private let logarithm: [Mnemonic] = [.flogb]
private let trig: [Mnemonic] = [.fexpa, .ftssel, .ftsmul, .ftmad]
private let fusedMultiplicand: [Mnemonic] = [.fmad, .fmsb, .fnmad, .fnmla, .fnmls, .fnmsb]
private let clamps: [Mnemonic] = [.fclamp, .bfclamp]
private let matrix: [Mnemonic] = [.fmmla]
private let wideningLong: [Mnemonic] = [.fmlslb, .fmlslt, .bfmlslb, .bfmlslt]
private let bf16Arithmetic: [Mnemonic] = [
    .bfadd, .bfsub, .bfmul, .bfmax, .bfmin, .bfmaxnm, .bfminnm, .bfmla, .bfmls, .bfscale,
]
private let fp8Converts: [Mnemonic] = [
    .f1cvt, .f1cvtlt, .f2cvt, .f2cvtlt, .bf1cvt, .bf1cvtlt, .bf2cvt, .bf2cvtlt,
]
private let fp8IntConverts: [Mnemonic] = [.scvtflt, .ucvtflt]

private let declaredHere: [Mnemonic] =
    reductions + reversed + compares + converts + logarithm + trig
        + fusedMultiplicand + clamps + matrix + wideningLong + bf16Arithmetic
        + fp8Converts + fp8IntConverts

/// Validates the mnemonic constants the SVE floating-point tier declares. They
/// continue the scalable slab directly after 2s.3's allocation, so three things
/// must hold: every new constant sits inside the reserved scalable range, the
/// constants are distinct and contiguous (later work must know exactly where it
/// may begin), and the shared floating-point text tokens — fadd, fmul, fmla,
/// fmov, fcvt and dozens more that 2.6's SIMD slab or 2s.3 already declared —
/// are reused rather than redeclared, since a duplicate raw value would
/// silently collide two different instructions onto one token.
@Suite("SVE floating-point / mnemonic allocations")
struct MnemonicSVEFloatingPointTests {
    private static let scalableRange: ClosedRange<UInt16> = 16384 ... 28671
    private static let subpieceRange: ClosedRange<UInt16> = 16627 ... 16683

    @Test func everyDeclaredMnemonicSitsInTheScalableRange() {
        for m in declaredHere {
            #expect(Self.scalableRange.contains(m.rawValue), "\(m.rawValue) is outside the scalable range")
        }
    }

    @Test func theScalableRangeIsTheOneTheSubstrateReserved() {
        let reserved = Mnemonic.allocations.first { $0.label == "SVE / SVE2 tier" }
        #expect(reserved?.range == Self.scalableRange)
    }

    @Test func theDeclaredMnemonicsAreContiguousAfterTheIntegerSlab() {
        // 2s.3 ended at 16626; 2s.4 starts at 16627 and leaves no gaps, so the
        // tier above knows its first free value is 16684.
        let raws = declaredHere.map(\.rawValue).sorted()
        #expect(raws.count == 57)
        #expect(Set(raws).count == raws.count)
        #expect(raws == Array(Self.subpieceRange))
    }

    @Test func theSharedTextTokensAreReusedNotRedeclared() {
        // These mnemonics already exist for base-instruction or NEON forms (2.6
        // SIMD/FP) or 2s.3's vector-integer forms; 2s.4 reuses them, so their
        // raw values must stay outside this tier's block.
        let shared: [Mnemonic] = [
            .fadd, .fsub, .fmul, .fdiv, .fmax, .fmin, .fmaxnm, .fminnm,
            .fabs, .fneg, .fabd, .fmulx, .fscale, .famax, .famin,
            .fmla, .fmls, .fmov, .fcvt, .fcvtzs, .fcvtzu, .scvtf, .ucvtf,
            .frinta, .frinti, .frintm, .frintn, .frintp, .frintx, .frintz,
            .frint32x, .frint32z, .frint64x, .frint64z,
            .frecpe, .frecps, .frecpx, .frsqrte, .frsqrts, .fsqrt,
            .fcmeq, .fcmge, .fcmgt, .fcmle, .fcmlt, .facge, .facgt,
            .fcadd, .fcmla, .bfdot, .bfmmla, .bfmlalb, .bfmlalt, .bfcvt, .bfcvtn,
            .fdot, .faddp, .fmaxp, .fminp, .fmaxnmp, .fminnmp,
            .fmaxv, .fminv, .fmaxnmv, .fminnmv,
            .fmlalb, .fmlalt, .fmlallbb, .fmlallbt, .fmlalltb, .fmlalltt, .fcvtn,
        ]
        for m in shared {
            #expect(
                !Self.subpieceRange.contains(m.rawValue),
                "\(m.rawValue) was redeclared in the SVE floating-point block",
            )
        }
    }

    @Test func eachEncodingGroupContributesItsOwnConstants() {
        // A group that accidentally shared a constant with another would decode
        // to the wrong text; keep the groups provably disjoint.
        let groups = [
            reductions, reversed, compares, converts, logarithm, trig,
            fusedMultiplicand, clamps, matrix, wideningLong, bf16Arithmetic,
            fp8Converts, fp8IntConverts,
        ]
        var seen = Set<UInt16>()
        for group in groups {
            for m in group {
                #expect(seen.insert(m.rawValue).inserted, "\(m.rawValue) appears in two groups")
            }
        }
        #expect(seen.count == declaredHere.count)
    }
}
