// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private let sme2Mnemonics: [(Mnemonic, String)] = [
    (.movaz, "movaz"), (.movt, "movt"),
    (.zip, "zip"), (.uzp, "uzp"), (.sunpk, "sunpk"), (.uunpk, "uunpk"),
    (.bfmlal, "bfmlal"), (.bfmlsl, "bfmlsl"),
    (.smlall, "smlall"), (.umlall, "umlall"), (.smlsll, "smlsll"), (.umlsll, "umlsll"),
    (.usmlall, "usmlall"), (.sumlall, "sumlall"), (.fmlall, "fmlall"),
    (.fvdot, "fvdot"), (.bfvdot, "bfvdot"), (.svdot, "svdot"), (.uvdot, "uvdot"),
    (.suvdot, "suvdot"), (.usvdot, "usvdot"), (.fvdotb, "fvdotb"), (.fvdott, "fvdott"),
    (.sqcvt, "sqcvt"), (.uqcvt, "uqcvt"), (.sqcvtu, "sqcvtu"),
    (.sqrshr, "sqrshr"), (.uqrshr, "uqrshr"), (.sqrshru, "sqrshru"),
    (.pext, "pext"), (.psel, "psel"), (.firstp, "firstp"), (.lastp, "lastp"),
    (.fmop4a, "fmop4a"), (.fmop4s, "fmop4s"), (.bfmop4a, "bfmop4a"), (.bfmop4s, "bfmop4s"),
    (.smop4a, "smop4a"), (.smop4s, "smop4s"), (.umop4a, "umop4a"), (.umop4s, "umop4s"),
    (.sumop4a, "sumop4a"), (.sumop4s, "sumop4s"), (.usmop4a, "usmop4a"), (.usmop4s, "usmop4s"),
    (.ftmopa, "ftmopa"), (.bftmopa, "bftmopa"), (.stmopa, "stmopa"),
    (.utmopa, "utmopa"), (.sutmopa, "sutmopa"), (.ustmopa, "ustmopa"),
]

/// Validates the SME2 mnemonic tokens.
@Suite("SME2 / mnemonic tokens")
struct MnemonicSME2Tests {
    @Test func everyDeclaredTokenIsDistinct() {
        let values = sme2Mnemonics.map(\.0.rawValue)
        #expect(Set(values).count == values.count)
    }

    @Test func theSlabContinuesAtItsAssignedBaseAndIsContiguous() {
        #expect(sme2Mnemonics.map(\.0.rawValue) == Array(UInt16(28689) ... 28739))
    }

    @Test func everyTokenLivesInsideTheScalableMatrixSlab() {
        for (mnemonic, name) in sme2Mnemonics {
            #expect(mnemonic.rawValue >= 28672 && mnemonic.rawValue < 40960, "\(name)")
        }
    }

    @Test func noSME2TokenCollidesWithTheSMECoreSlab() {
        for (mnemonic, name) in sme2Mnemonics {
            #expect(mnemonic.rawValue > 28688, "\(name) overlaps the SME-core slab")
        }
    }

    @Test func theReusedArchitecturalTokensStayOutsideTheNewRange() {
        let reused: [(Mnemonic, String)] = [
            (.mov, "mov"), (.zero, "zero"), (.add, "add"), (.sub, "sub"),
            (.fadd, "fadd"), (.fmla, "fmla"), (.sdot, "sdot"), (.fmul, "fmul"),
            (.smax, "smax"), (.sclamp, "sclamp"), (.fcvtzs, "fcvtzs"),
            (.ld1b, "ld1b"), (.st1d, "st1d"), (.ldnt1b, "ldnt1b"), (.ldr, "ldr"),
            (.whilege, "whilege"), (.ptrue, "ptrue"), (.cntp, "cntp"), (.sel, "sel"),
            (.smopa, "smopa"),
        ]
        for (mnemonic, name) in reused {
            #expect(mnemonic.rawValue < 28689, "\(name) must not be re-declared in the 2s.7 range")
        }
    }

    @Test func theAccumulateAndSubtractHalvesOfEachOuterProductAreDistinct() {
        let pairs: [(Mnemonic, Mnemonic)] = [
            (.fmop4a, .fmop4s), (.bfmop4a, .bfmop4s), (.smop4a, .smop4s),
            (.umop4a, .umop4s), (.sumop4a, .sumop4s), (.usmop4a, .usmop4s),
        ]
        for (accumulate, subtract) in pairs {
            #expect(accumulate != subtract)
        }
    }
}
