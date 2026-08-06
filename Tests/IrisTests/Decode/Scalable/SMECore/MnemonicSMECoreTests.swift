// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private let smeCoreMnemonics: [(Mnemonic, String)] = [
    (.zero, "zero"),
    (.addha, "addha"), (.addva, "addva"),
    (.fmopa, "fmopa"), (.fmops, "fmops"),
    (.bfmopa, "bfmopa"), (.bfmops, "bfmops"),
    (.smopa, "smopa"), (.smops, "smops"),
    (.sumopa, "sumopa"), (.sumops, "sumops"),
    (.usmopa, "usmopa"), (.usmops, "usmops"),
    (.umopa, "umopa"), (.umops, "umops"),
    (.bmopa, "bmopa"), (.bmops, "bmops"),
]

/// Validates the SME-core mnemonic tokens.
@Suite("SME core / mnemonic tokens")
struct MnemonicSMECoreTests {
    @Test func everyDeclaredTokenIsDistinct() {
        let values = smeCoreMnemonics.map(\.0.rawValue)
        #expect(Set(values).count == values.count)
    }

    @Test func theSlabStartsAtItsAssignedBaseAndIsContiguous() {
        #expect(smeCoreMnemonics.map(\.0.rawValue) == Array(UInt16(28672) ... 28688))
    }

    @Test func everyTokenLivesInsideTheScalableMatrixSlab() {
        for (mnemonic, name) in smeCoreMnemonics {
            #expect(mnemonic.rawValue >= 28672 && mnemonic.rawValue < 40960, "\(name)")
        }
    }

    @Test func theReusedArchitecturalTokensStayOutsideTheSlab() {
        let reused: [(Mnemonic, String)] = [
            (.mov, "mov"), (.ldr, "ldr"), (.str, "str"),
            (.ld1b, "ld1b"), (.ld1h, "ld1h"), (.ld1w, "ld1w"), (.ld1d, "ld1d"), (.ld1q, "ld1q"),
            (.st1b, "st1b"), (.st1h, "st1h"), (.st1w, "st1w"), (.st1d, "st1d"), (.st1q, "st1q"),
            (.smstart, "smstart"), (.smstop, "smstop"),
        ]
        for (mnemonic, name) in reused {
            #expect(mnemonic.rawValue < 28672, "\(name) must not be re-declared in the SME slab")
        }
    }

    @Test func theAccumulateAndSubtractHalvesOfEachFamilyAreDistinct() {
        let pairs: [(Mnemonic, Mnemonic)] = [
            (.fmopa, .fmops), (.bfmopa, .bfmops), (.smopa, .smops),
            (.sumopa, .sumops), (.usmopa, .usmops), (.umopa, .umops),
            (.bmopa, .bmops), (.addha, .addva),
        ]
        for (accumulate, subtract) in pairs {
            #expect(accumulate != subtract)
        }
    }
}
