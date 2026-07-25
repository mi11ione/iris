// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Every mnemonic constant subpiece 2s.3 declares, grouped as the encoding
/// tables group them.
private let multiplyAddLong: [Mnemonic] = [
    .adclb, .adclt, .sabalb, .sabalt, .sbclb, .sbclt,
    .smlalb, .smlalt, .smlslb, .smlslt, .smullb,
    .sqdmlalb, .sqdmlalbt, .sqdmlalt, .sqdmlslb, .sqdmlslbt, .sqdmlslt, .sqdmullt,
    .uabalb, .uabalt, .umlalb, .umlalt, .umlslb, .umlslt,
]
private let narrowing: [Mnemonic] = [
    .addhnb, .addhnt, .raddhnb, .raddhnt, .rshrnb, .rshrnt, .rsubhnb, .rsubhnt,
    .shrnb, .shrnt, .sqcvtn, .sqcvtun,
    .sqrshrnb, .sqrshrnt, .sqrshrunb, .sqrshrunt,
    .sqshrnb, .sqshrnt, .sqshrunb, .sqshrunt,
    .sqxtnb, .sqxtnt, .sqxtunb, .sqxtunt, .subhnb, .subhnt,
    .uqcvtn, .uqrshrnb, .uqrshrnt, .uqshrnb, .uqshrnt, .uqxtnb, .uqxtnt,
]
private let unpredicated: [Mnemonic] = [.addqp, .addsubp]
private let reductions: [Mnemonic] = [
    .addqv, .andqv, .andv, .eorqv, .eorv, .orqv, .orv, .saddv,
    .smaxqv, .sminqv, .uaddv, .umaxqv, .uminqv,
]
private let predicatedShifts: [Mnemonic] = [.asrd, .asrr, .lslr, .lsrr]
private let bitPermuteAndWide: [Mnemonic] = [
    .bdep, .bext, .bgrp, .eorbt, .eortb, .histcnt, .histseg, .match, .nmatch,
    .pmullb, .pmullt, .sabdlb, .sabdlt, .saddlb, .saddlbt, .saddlt,
    .saddwb, .saddwt, .smullt, .sqdmullb,
    .ssublb, .ssublbt, .ssublt, .ssubltb, .ssubwb, .ssubwt,
    .uabdlb, .uabdlt, .uaddlb, .uaddlt, .uaddwb, .uaddwt,
    .umullb, .umullt, .usublb, .usublt, .usubwb, .usubwt,
]
private let ternary: [Mnemonic] = [.bsl1n, .bsl2n, .nbsl]
private let complex: [Mnemonic] = [.cadd, .cdot, .cmla, .sqcadd, .sqrdcmlah]
private let compares: [Mnemonic] = [
    .cmpeq, .cmpge, .cmpgt, .cmphi, .cmphs,
    .cmple, .cmplo, .cmpls, .cmplt, .cmpne,
]
private let predicatedUnary: [Mnemonic] = [.cnot, .uxtw]
private let bitwiseImmediate: [Mnemonic] = [.dupm]
private let multiplyAdd: [Mnemonic] = [.mad, .msb]
private let checkedPointer: [Mnemonic] = [.madpt, .mlapt]
private let clamps: [Mnemonic] = [.sclamp, .uclamp]
private let divides: [Mnemonic] = [.sdivr, .udivr]
private let saturatingPredicated: [Mnemonic] = [
    .shsubr, .sqrshlr, .sqshlr, .sqsubr, .srshlr,
    .uhsubr, .uqrshlr, .uqshlr, .uqsubr, .urshlr,
]
private let shiftLong: [Mnemonic] = [.sshllb, .sshllt, .ushllb, .ushllt]
private let wideImmediate: [Mnemonic] = [.subr]

private let declaredHere: [Mnemonic] =
    multiplyAddLong + narrowing + unpredicated + reductions + predicatedShifts
        + bitPermuteAndWide + ternary + complex + compares + predicatedUnary
        + bitwiseImmediate + multiplyAdd + checkedPointer + clamps + divides
        + saturatingPredicated + shiftLong + wideImmediate

/// Validates the mnemonic constants this decoder declares. They continue the
/// scalable slab directly after 2s.2's allocation, so three things must hold:
/// every new constant sits inside the reserved scalable range, the constants
/// are distinct and contiguous (the next subpiece must know exactly where it
/// may begin), and the shared text tokens — add, mul, mov, smax, sqadd and a
/// hundred more that earlier subpieces already declared — are reused rather
/// than redeclared, since a duplicate raw value would silently collide.
@Suite("SVE integer / mnemonic allocations")
struct MnemonicSVEIntegerTests {
    private static let scalableRange: ClosedRange<UInt16> = 16384 ... 28671
    private static let subpieceRange: ClosedRange<UInt16> = 16469 ... 16626

    @Test func everyDeclaredMnemonicSitsInTheScalableRange() {
        for m in declaredHere {
            #expect(Self.scalableRange.contains(m.rawValue), "\(m.rawValue) is outside the scalable range")
        }
    }

    @Test func theScalableRangeIsTheOneTheSubstrateReserved() {
        let reserved = Mnemonic.allocations.first { $0.label == "SVE / SVE2 tier" }
        #expect(reserved?.range == Self.scalableRange)
    }

    @Test func theDeclaredMnemonicsAreContiguousAfterThePredicateControlSlab() {
        // 2s.2 consumed 16384...16468; 2s.3 starts at 16469 and leaves no
        // gaps, so 2s.4 knows its first free value is 16627.
        let raws = declaredHere.map(\.rawValue).sorted()
        #expect(raws.count == 158)
        #expect(Set(raws).count == raws.count)
        #expect(raws == Array(Self.subpieceRange))
    }

    @Test func theSharedTextTokensAreReusedNotRedeclared() {
        // These mnemonics already exist for base-instruction or NEON forms
        // (or 2s.2's predicate forms); the vector integer forms reuse them,
        // so their raw values must stay outside this subpiece's block.
        let shared: [Mnemonic] = [
            .add, .sub, .and, .orr, .eor, .bic, .mul, .mov, .not, .neg, .abs,
            .asr, .lsl, .lsr, .cls, .clz, .cnt, .smax, .smin, .umax, .umin,
            .sdiv, .udiv, .sxtb, .sxth, .sxtw, .uxtb, .uxth,
            .sqadd, .uqadd, .sqsub, .uqsub, .sabd, .uabd, .mla, .mls, .adr,
            .sdot, .udot, .usdot, .sudot, .sri, .sli,
            .smmla, .ummla, .usmmla, .pmul, .sqdmulh, .sqrdmulh,
            .saba, .uaba, .sabal, .uabal, .sqabs, .sqneg, .xar, .eor3, .bcax,
            .bsl, .addp, .subp, .smulh, .umulh, .sadalp, .uadalp,
            .srshl, .urshl, .sqshl, .uqshl, .sqrshl, .uqrshl, .sqshlu,
            .shadd, .uhadd, .shsub, .uhsub, .srhadd, .urhadd,
            .suqadd, .usqadd, .smaxp, .sminp, .umaxp, .uminp,
            .ssra, .usra, .srsra, .ursra, .srshr, .urshr,
            .sqrdmlah, .sqrdmlsh, .urecpe, .ursqrte, .addpt, .subpt,
        ]
        for m in shared {
            #expect(
                !Self.subpieceRange.contains(m.rawValue),
                "\(m.rawValue) was redeclared in the SVE-integer block",
            )
        }
    }

    @Test func eachEncodingGroupContributesItsOwnConstants() {
        // A group that accidentally shared a constant with another would
        // decode to the wrong text; keep the groups provably disjoint.
        let groups = [
            multiplyAddLong, narrowing, unpredicated, reductions, predicatedShifts,
            bitPermuteAndWide, ternary, complex, compares, predicatedUnary,
            bitwiseImmediate, multiplyAdd, checkedPointer, clamps, divides,
            saturatingPredicated, shiftLong, wideImmediate,
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
