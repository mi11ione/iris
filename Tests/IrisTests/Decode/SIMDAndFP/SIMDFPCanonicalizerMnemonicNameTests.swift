// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates that every SIMD/FP mnemonic the canonicalizer's
/// mnemonicName(_:) switch knows about renders to the expected lowercase
/// text. One pair = one regional path through the switch — taken together
/// these tests cover every named case + the `?simdfp-mnemonic-N` default.
@Suite("Disassembler / SIMDFPCanonicalizer mnemonic-name coverage")
struct SIMDFPCanonicalizerMnemonicNameTests {
    private func render(_ m: Mnemonic) -> String {
        let d = Instruction(
            address: 0, encoding: 0, mnemonic: m, category: .simdAndFP, operands: [],
        )
        return d.text
    }

    @Test func everyMnemonicRendersToExpectedName() {
        // (mnemonic, expected text) — covers every case in the
        // canonicalizer's mnemonicName(_:) switch.
        let cases: [(Mnemonic, String)] = [
            // FP scalar.
            (.fmul, "fmul"), (.fdiv, "fdiv"), (.fadd, "fadd"), (.fsub, "fsub"),
            (.fmax, "fmax"), (.fmin, "fmin"), (.fmaxnm, "fmaxnm"), (.fminnm, "fminnm"),
            (.fnmul, "fnmul"), (.fcmp, "fcmp"), (.fcmpe, "fcmpe"), (.fccmp, "fccmp"),
            (.fccmpe, "fccmpe"), (.fcsel, "fcsel"), (.fmov, "fmov"), (.fabs, "fabs"),
            (.fneg, "fneg"), (.fsqrt, "fsqrt"), (.fmadd, "fmadd"), (.fmsub, "fmsub"),
            (.fnmadd, "fnmadd"), (.fnmsub, "fnmsub"), (.fcvt, "fcvt"),
            (.frintn, "frintn"), (.frintp, "frintp"), (.frintm, "frintm"),
            (.frintz, "frintz"), (.frinta, "frinta"), (.frintx, "frintx"),
            (.frinti, "frinti"), (.frint32z, "frint32z"), (.frint32x, "frint32x"),
            (.frint64z, "frint64z"), (.frint64x, "frint64x"),
            (.bfcvt, "bfcvt"), (.fcvtl, "fcvtl"), (.fcvtl2, "fcvtl2"),
            (.fcvtn, "fcvtn"), (.fcvtn2, "fcvtn2"), (.fcvtxn, "fcvtxn"),
            (.fcvtxn2, "fcvtxn2"),
            (.fcvtas, "fcvtas"), (.fcvtau, "fcvtau"), (.fcvtms, "fcvtms"),
            (.fcvtmu, "fcvtmu"), (.fcvtns, "fcvtns"), (.fcvtnu, "fcvtnu"),
            (.fcvtps, "fcvtps"), (.fcvtpu, "fcvtpu"), (.fcvtzs, "fcvtzs"),
            (.fcvtzu, "fcvtzu"), (.fjcvtzs, "fjcvtzs"),
            (.scvtf, "scvtf"), (.ucvtf, "ucvtf"),
            // AdvSIMD arithmetic / logic.
            (.add, "add"), (.sub, "sub"), (.mul, "mul"), (.mla, "mla"), (.mls, "mls"),
            (.neg, "neg"), (.abs, "abs"), (.cnt, "cnt"), (.cls, "cls"), (.clz, "clz"),
            (.rbit, "rbit"), (.rev16, "rev16"), (.rev32, "rev32"), (.rev64, "rev64"),
            (.not, "not"), (.mvn, "mvn"),
            (.and, "and"), (.orr, "orr"), (.eor, "eor"), (.bic, "bic"),
            (.orn, "orn"), (.bsl, "bsl"), (.bit, "bit"), (.bif, "bif"),
            (.mov, "mov"),
            // Saturating.
            (.sqadd, "sqadd"), (.uqadd, "uqadd"), (.sqsub, "sqsub"), (.uqsub, "uqsub"),
            (.sqdmulh, "sqdmulh"), (.sqrdmulh, "sqrdmulh"), (.sqrdmlah, "sqrdmlah"),
            (.sqrdmlsh, "sqrdmlsh"),
            (.sqdmlal, "sqdmlal"), (.sqdmlsl, "sqdmlsl"), (.sqdmull, "sqdmull"),
            (.sqdmlal2, "sqdmlal2"), (.sqdmlsl2, "sqdmlsl2"), (.sqdmull2, "sqdmull2"),
            (.suqadd, "suqadd"), (.usqadd, "usqadd"),
            (.sqabs, "sqabs"), (.sqneg, "sqneg"),
            (.sqxtn, "sqxtn"), (.sqxtn2, "sqxtn2"),
            (.uqxtn, "uqxtn"), (.uqxtn2, "uqxtn2"),
            (.sqxtun, "sqxtun"), (.sqxtun2, "sqxtun2"),
            // Compares.
            (.cmtst, "cmtst"), (.cmgt, "cmgt"), (.cmge, "cmge"), (.cmeq, "cmeq"),
            (.cmhi, "cmhi"), (.cmhs, "cmhs"), (.cmle, "cmle"), (.cmlt, "cmlt"),
            // Shifts.
            (.sshl, "sshl"), (.ushl, "ushl"), (.sqshl, "sqshl"), (.uqshl, "uqshl"),
            (.srshl, "srshl"), (.urshl, "urshl"), (.sqrshl, "sqrshl"), (.uqrshl, "uqrshl"),
            (.sshr, "sshr"), (.ssra, "ssra"), (.srshr, "srshr"), (.srsra, "srsra"),
            (.shl, "shl"), (.ushr, "ushr"), (.usra, "usra"), (.urshr, "urshr"),
            (.ursra, "ursra"), (.sri, "sri"), (.sli, "sli"), (.sqshlu, "sqshlu"),
            (.shrn, "shrn"), (.shrn2, "shrn2"), (.rshrn, "rshrn"), (.rshrn2, "rshrn2"),
            (.sqshrn, "sqshrn"), (.sqshrn2, "sqshrn2"),
            (.sqrshrn, "sqrshrn"), (.sqrshrn2, "sqrshrn2"),
            (.uqshrn, "uqshrn"), (.uqshrn2, "uqshrn2"),
            (.uqrshrn, "uqrshrn"), (.uqrshrn2, "uqrshrn2"),
            (.sqshrun, "sqshrun"), (.sqshrun2, "sqshrun2"),
            (.sqrshrun, "sqrshrun"), (.sqrshrun2, "sqrshrun2"),
            (.sshll, "sshll"), (.sshll2, "sshll2"),
            (.ushll, "ushll"), (.ushll2, "ushll2"),
            (.sxtl, "sxtl"), (.sxtl2, "sxtl2"), (.uxtl, "uxtl"), (.uxtl2, "uxtl2"),
            // FP family.
            (.fmla, "fmla"), (.fmls, "fmls"),
            (.fmlal, "fmlal"), (.fmlal2, "fmlal2"),
            (.fmlsl, "fmlsl"), (.fmlsl2, "fmlsl2"),
            (.fmulx, "fmulx"), (.frecps, "frecps"), (.frsqrts, "frsqrts"),
            (.fcmeq, "fcmeq"), (.fcmge, "fcmge"), (.fcmgt, "fcmgt"),
            (.fcmle, "fcmle"), (.fcmlt, "fcmlt"),
            (.facge, "facge"), (.facgt, "facgt"),
            (.fabd, "fabd"),
            (.frecpe, "frecpe"), (.frecpx, "frecpx"), (.frsqrte, "frsqrte"),
            (.fmaxnmp, "fmaxnmp"), (.fminnmp, "fminnmp"),
            (.faddp, "faddp"), (.fmaxp, "fmaxp"), (.fminp, "fminp"),
            (.fmaxnmv, "fmaxnmv"), (.fmaxv, "fmaxv"),
            (.fminnmv, "fminnmv"), (.fminv, "fminv"),
            // Integer three-same.
            (.shadd, "shadd"), (.srhadd, "srhadd"), (.shsub, "shsub"),
            (.uhadd, "uhadd"), (.urhadd, "urhadd"), (.uhsub, "uhsub"),
            (.smax, "smax"), (.smin, "smin"), (.umax, "umax"), (.umin, "umin"),
            (.sabd, "sabd"), (.uabd, "uabd"), (.saba, "saba"), (.uaba, "uaba"),
            (.pmul, "pmul"),
            (.smaxp, "smaxp"), (.sminp, "sminp"), (.umaxp, "umaxp"), (.uminp, "uminp"),
            (.addp, "addp"),
            // Three-different.
            (.saddl, "saddl"), (.saddl2, "saddl2"),
            (.saddw, "saddw"), (.saddw2, "saddw2"),
            (.ssubl, "ssubl"), (.ssubl2, "ssubl2"),
            (.ssubw, "ssubw"), (.ssubw2, "ssubw2"),
            (.addhn, "addhn"), (.addhn2, "addhn2"),
            (.sabal, "sabal"), (.sabal2, "sabal2"),
            (.subhn, "subhn"), (.subhn2, "subhn2"),
            (.sabdl, "sabdl"), (.sabdl2, "sabdl2"),
            (.smlal, "smlal"), (.smlal2, "smlal2"),
            (.smlsl, "smlsl"), (.smlsl2, "smlsl2"),
            (.smull, "smull"), (.smull2, "smull2"),
            (.pmull, "pmull"), (.pmull2, "pmull2"),
            (.uaddl, "uaddl"), (.uaddl2, "uaddl2"),
            (.uaddw, "uaddw"), (.uaddw2, "uaddw2"),
            (.usubl, "usubl"), (.usubl2, "usubl2"),
            (.usubw, "usubw"), (.usubw2, "usubw2"),
            (.raddhn, "raddhn"), (.raddhn2, "raddhn2"),
            (.uabal, "uabal"), (.uabal2, "uabal2"),
            (.rsubhn, "rsubhn"), (.rsubhn2, "rsubhn2"),
            (.uabdl, "uabdl"), (.uabdl2, "uabdl2"),
            (.umlal, "umlal"), (.umlal2, "umlal2"),
            (.umlsl, "umlsl"), (.umlsl2, "umlsl2"),
            (.umull, "umull"), (.umull2, "umull2"),
            // Across-lanes / Saddle.
            (.saddlp, "saddlp"), (.uaddlp, "uaddlp"),
            (.sadalp, "sadalp"), (.uadalp, "uadalp"),
            (.xtn, "xtn"), (.xtn2, "xtn2"),
            (.shll, "shll"), (.shll2, "shll2"),
            (.urecpe, "urecpe"), (.ursqrte, "ursqrte"),
            (.saddlv, "saddlv"), (.smaxv, "smaxv"), (.sminv, "sminv"),
            (.addv, "addv"), (.uaddlv, "uaddlv"),
            (.umaxv, "umaxv"), (.uminv, "uminv"),
            // DOT/MMLA.
            (.sdot, "sdot"), (.udot, "udot"), (.usdot, "usdot"), (.sudot, "sudot"),
            (.bfdot, "bfdot"),
            (.bfmlalb, "bfmlalb"), (.bfmlalt, "bfmlalt"), (.bfmmla, "bfmmla"),
            (.smmla, "smmla"), (.ummla, "ummla"), (.usmmla, "usmmla"),
            // Modified-immediate / copy.
            (.movi, "movi"), (.mvni, "mvni"),
            (.dup, "dup"), (.ins, "ins"), (.umov, "umov"), (.smov, "smov"),
            // Permute / extract / TBL.
            (.uzp1, "uzp1"), (.uzp2, "uzp2"),
            (.trn1, "trn1"), (.trn2, "trn2"),
            (.zip1, "zip1"), (.zip2, "zip2"),
            (.ext, "ext"), (.tbl, "tbl"), (.tbx, "tbx"),
            // LD/ST.
            (.ld1, "ld1"), (.ld2, "ld2"), (.ld3, "ld3"), (.ld4, "ld4"),
            (.st1, "st1"), (.st2, "st2"), (.st3, "st3"), (.st4, "st4"),
            (.ld1r, "ld1r"), (.ld2r, "ld2r"), (.ld3r, "ld3r"), (.ld4r, "ld4r"),
            (.ldr, "ldr"), (.str, "str"),
            (.ldur, "ldur"), (.stur, "stur"),
            (.ldp, "ldp"), (.stp, "stp"),
            (.ldnp, "ldnp"), (.stnp, "stnp"),
        ]
        for (m, expected) in cases {
            #expect(render(m) == expected, "mnemonic \(m.rawValue): expected \(expected)")
        }
    }
}
