// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates that the SIMD/FP mnemonic constants declared in
/// Mnemonic+SIMDAndFP.swift fall within the SIMD/FP slab (6144..12287)
/// allocated by Mnemonic.allocations.
@Suite("SIMD/FP / Mnemonic slab membership")
struct SIMDFPMnemonicSlabTests {
    @Test func slabRangeIsRegistered() {
        let entry = Mnemonic.allocations.first(where: { $0.label == "SIMD & Floating-Point" })
        #expect(entry != nil)
        let range = entry?.range
        #expect(range == 6144 ... 12287)
    }

    @Test func everyNewMnemonicFallsInSlab() {
        // Sample several from each sub-slab to confirm range membership.
        let samples: [Mnemonic] = [
            .sqadd, .uqadd, .sqsub, .uqsub, .cmtst, .sshl, .sqdmulh,
            .sshr, .ssra, .srshr, .srsra, .shl, .ushr, .sxtl, .uxtl,
            .fmulx, .frecps, .frsqrts, .fcmeq, .fcmge, .fcmgt,
            .shadd, .srhadd, .shsub, .uhadd, .urhadd, .uhsub,
            .smax, .smin, .umax, .umin, .sabd, .uabd, .saba, .uaba,
            .pmul, .smaxp, .sminp, .umaxp, .uminp, .bsl, .bit, .bif,
            .fmaxnm, .fminnm, .fmax, .fmin, .fmla, .fmls, .fadd, .fsub,
            .saddl, .saddl2, .saddw, .saddw2, .ssubl, .addhn, .smlal,
            .pmull, .uaddl, .raddhn, .rsubhn, .uabdl, .umlal,
            .rev64, .saddlp, .uaddlp, .sadalp, .uadalp,
            .cnt, .xtn, .xtn2, .shll, .urecpe, .ursqrte,
            .saddlv, .smaxv, .sminv, .addv, .uaddlv, .umaxv, .uminv,
            .fmaxnmv, .fmaxv, .fminnmv, .fminv, .not,
            .sdot, .udot, .usdot, .sudot, .bfdot, .bfmlalb, .bfmmla,
            .bfcvt, .smmla, .ummla, .usmmla, .fmlal, .fmlsl,
            .movi, .mvni, .dup, .ins, .umov, .smov,
            .uzp1, .uzp2, .trn1, .trn2, .zip1, .zip2, .ext, .tbl, .tbx,
            .fmov, .fabs, .fneg, .fsqrt, .fcvt,
            .frintn, .frintp, .frintm, .frintz, .frinta, .frintx, .frinti,
            .frint32z, .frint32x, .frint64z, .frint64x,
            .fcvtl, .fcvtl2, .fcvtn, .fcvtn2, .fcvtxn, .fcvtxn2,
            .fnmul, .fmadd, .fmsub, .fnmadd, .fnmsub,
            .fcvtas, .fcvtau, .fcvtms, .fcvtmu, .fcvtns, .fcvtnu,
            .fcvtps, .fcvtpu, .fcvtzs, .fcvtzu, .fjcvtzs, .scvtf, .ucvtf,
            .fcmp, .fcmpe, .fccmp, .fccmpe, .fcsel,
            .ld1, .ld2, .ld3, .ld4, .st1, .st2, .st3, .st4,
            .ld1r, .ld2r, .ld3r, .ld4r,
        ]
        for m in samples {
            #expect(m.rawValue >= 6144 && m.rawValue <= 12287,
                    "mnemonic raw \(m.rawValue) outside the SIMD/FP slab")
        }
    }

    @Test func samplesAreUniqueRawValues() {
        // Spot-check that distinct mnemonics have distinct raw values.
        var seen: [UInt16: Mnemonic] = [:]
        for m: Mnemonic in [.sqadd, .uqadd, .sqsub, .uqsub, .cmtst, .cmgt, .cmge, .cmeq, .cmhi, .cmhs] {
            #expect(seen[m.rawValue] == nil, "duplicate raw value \(m.rawValue)")
            seen[m.rawValue] = m
        }
    }
}
