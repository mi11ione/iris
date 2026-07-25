// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// The tokens subpiece 2s.7 declares, in encoding order — continuing the
/// SME/SME2 slab at 28689, immediately after 2s.6's `28672...28688`.
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

/// Validates the SME2 mnemonic tokens. A `Mnemonic` raw value is a wire-visible
/// contract — records carry it, the canonicalizer keys text off it, and the slab
/// boundaries partition the token space between subpieces — so a collision would
/// silently retag decoded instructions. The distinctness and slab placement are
/// asserted rather than assumed.
@Suite("SME2 / mnemonic tokens")
struct MnemonicSME2Tests {
    @Test func everyDeclaredTokenIsDistinct() {
        let values = sme2Mnemonics.map(\.0.rawValue)
        #expect(Set(values).count == values.count)
    }

    @Test func theSlabContinuesAtItsAssignedBaseAndIsContiguous() {
        // 2s.6 took `28672...28688`; 2s.7 continues at 28689 for 51 tokens.
        #expect(sme2Mnemonics.map(\.0.rawValue) == Array(UInt16(28689) ... 28739))
    }

    @Test func everyTokenLivesInsideTheScalableMatrixSlab() {
        // 28672..<40960 is the SME/SME2 slab; a token outside it would collide
        // with another tier's numbering.
        for (mnemonic, name) in sme2Mnemonics {
            #expect(mnemonic.rawValue >= 28672 && mnemonic.rawValue < 40960, "\(name)")
        }
    }

    @Test func noSME2TokenCollidesWithTheSMECoreSlab() {
        // 2s.6 owns `28672...28688`; a 2s.7 token landing there would retag an
        // SME-core instruction.
        for (mnemonic, name) in sme2Mnemonics {
            #expect(mnemonic.rawValue > 28688, "\(name) overlaps the SME-core slab")
        }
    }

    @Test func theReusedArchitecturalTokensStayOutsideTheNewRange() {
        // The dot/mla/minmax/shift/convert families, the loads/stores, the
        // WHILE conditions, PTRUE/CNTP/SEL and the base tokens are declared by
        // earlier subpieces and reused verbatim — no 2s.7 duplicate exists.
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
        // Every MOP4 comes in an `…4A` / `…4S` pair selected by the S bit;
        // conflating them would invert the accumulation sign.
        let pairs: [(Mnemonic, Mnemonic)] = [
            (.fmop4a, .fmop4s), (.bfmop4a, .bfmop4s), (.smop4a, .smop4s),
            (.umop4a, .umop4s), (.sumop4a, .sumop4s), (.usmop4a, .usmop4s),
        ]
        for (accumulate, subtract) in pairs {
            #expect(accumulate != subtract)
        }
    }
}
