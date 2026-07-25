// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// The seventeen SME-unique tokens subpiece 2s.6 declares, in encoding order.
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

/// Validates the SME-core mnemonic tokens. A `Mnemonic` is a raw-value token
/// whose numeric identity is a wire-visible contract: records carry it, the
/// canonicalizer keys its text off it, and the slab boundaries partition the
/// token space between subpieces. A collision with another subpiece's token
/// would silently retag decoded instructions, so the distinctness and the slab
/// placement are asserted rather than assumed.
@Suite("SME core / mnemonic tokens")
struct MnemonicSMECoreTests {
    @Test func everyDeclaredTokenIsDistinct() {
        let values = smeCoreMnemonics.map(\.0.rawValue)
        #expect(Set(values).count == values.count)
    }

    @Test func theSlabStartsAtItsAssignedBaseAndIsContiguous() {
        // The SME/SME2 slab begins at 28672; 2s.6 takes the first seventeen
        // slots, leaving the remainder of the slab to 2s.7.
        #expect(smeCoreMnemonics.map(\.0.rawValue) == Array(UInt16(28672) ... 28688))
    }

    @Test func everyTokenLivesInsideTheScalableMatrixSlab() {
        // 28672..<40960 is the SME/SME2 slab; a token outside it would collide
        // with another tier's numbering.
        for (mnemonic, name) in smeCoreMnemonics {
            #expect(mnemonic.rawValue >= 28672 && mnemonic.rawValue < 40960, "\(name)")
        }
    }

    @Test func theReusedArchitecturalTokensStayOutsideTheSlab() {
        // MOVA renders `mov`, and the ZA load/store/streaming forms reuse the
        // base-ISA and SVE tokens verbatim — the record's mnemonic is the
        // preferred-alias-resolved identity, so no SME-private duplicate exists.
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
        // Every outer product comes in an `…OPA` / `…OPS` pair selected by the
        // S bit; conflating the two would invert the accumulation sign.
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
