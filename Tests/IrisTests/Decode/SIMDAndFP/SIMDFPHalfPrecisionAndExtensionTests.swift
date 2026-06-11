// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the FP16, FP8/BF16, complex-arithmetic, dot-product /
/// matrix-multiply, lookup-table, and SIMD-register LRCPC2 encoding
/// classes: vector and scalar three-same FP16, the RDM scalar extras,
/// vector and scalar two-reg-misc FP16, the FCVTN/FCVTL/FCVTXN/BFCVTN
/// and FP8 long-convert shapes, scalar pairwise FP16, the three-register
/// extension class (FCMLA/FCADD/dot/MMLA/BF16/FP8), their by-element
/// forms, FEAT_LUT LUTI2/LUTI4, and STLUR/LDAPUR of SIMD registers —
/// every mnemonic row plus the reserved-shape rejections.
@Suite("SIMD/FP / FP16, FP8/BF16, complex, dot/MMLA, LUT, SIMD LRCPC2")
struct SIMDFPHalfPrecisionAndExtensionTests {
    @Test func vectorThreeSameFP16DecodesEveryRow() {
        let rows: [(word: UInt32, name: String)] = [
            (0x0E42_0420, "fmaxnm"), (0x0E42_0C20, "fmla"), (0x0E42_1420, "fadd"),
            (0x0E42_1C20, "fmulx"), (0x0E42_2420, "fcmeq"), (0x0E42_3420, "fmax"),
            (0x0E42_3C20, "frecps"),
            (0x0EC2_0420, "fminnm"), (0x0EC2_0C20, "fmls"), (0x0EC2_1420, "fsub"),
            (0x0EC2_1C20, "famax"), (0x0EC2_3420, "fmin"), (0x0EC2_3C20, "frsqrts"),
            (0x2E42_0420, "fmaxnmp"), (0x2E42_1420, "faddp"), (0x2E42_1C20, "fmul"),
            (0x2E42_2420, "fcmge"), (0x2E42_2C20, "facge"), (0x2E42_3420, "fmaxp"),
            (0x2E42_3C20, "fdiv"),
            (0x2EC2_0420, "fminnmp"), (0x2EC2_1420, "fabd"), (0x2EC2_1C20, "famin"),
            (0x2EC2_2420, "fcmgt"), (0x2EC2_2C20, "facgt"), (0x2EC2_3420, "fminp"),
            (0x2EC2_3C20, "fscale"),
        ]
        for row in rows {
            let d = decode(row.word)
            #expect(d.category == .simdAndFP)
            #expect(d.text == "\(row.name) v0.4h, v1.4h, v2.4h")
            // Q=1 form of the same row is .8h.
            let q = decode(row.word | (1 << 30))
            #expect(q.text == "\(row.name) v0.8h, v1.8h, v2.8h")
        }
        #expect(decode(0x0E42_2C20).isUndefined) // (U=0,a=0,op3=5) unmapped
        #expect(decode(0x0EC2_2420).isUndefined) // (U=0,a=1,op3=4) unmapped
        #expect(decode(0x0E42_4420).isUndefined) // bit14 = 1 reserved
    }

    @Test func scalarThreeSameFP16DecodesEveryRow() {
        let rows: [(word: UInt32, name: String)] = [
            (0x5E42_1C20, "fmulx"), (0x5E42_2420, "fcmeq"), (0x5E42_3C20, "frecps"),
            (0x5EC2_3C20, "frsqrts"),
            (0x7E42_2420, "fcmge"), (0x7E42_2C20, "facge"),
            (0x7EC2_1420, "fabd"), (0x7EC2_2420, "fcmgt"), (0x7EC2_2C20, "facgt"),
        ]
        for row in rows {
            let d = decode(row.word)
            #expect(d.category == .simdAndFP)
            #expect(d.text == "\(row.name) h0, h1, h2")
        }
        #expect(decode(0x5E42_0420).isUndefined) // (0,0,0) unmapped scalar
    }

    @Test func scalarRDMExtraDecodesBothOpsAndSizes() {
        #expect(decode(0x7E42_8420).text == "sqrdmlah h0, h1, h2")
        #expect(decode(0x7E42_8C20).text == "sqrdmlsh h0, h1, h2")
        #expect(decode(0x7E82_8420).text == "sqrdmlah s0, s1, s2")
        #expect(decode(0x7E82_8C20).text == "sqrdmlsh s0, s1, s2")
        // Accumulating RMW: destination participates in the reads.
        #expect(decode(0x7E42_8420).semanticReads.contains(.simd(0)))
        #expect(decode(0x5E42_8420).isUndefined) // U=0 reserved
        #expect(decode(0x7E02_8420).isUndefined) // size=00 reserved
        #expect(decode(0x7EC2_8420).isUndefined) // size=11 reserved
        #expect(decode(0x7E42_9420).isUndefined) // op5=10010 unmapped
    }

    @Test func vectorTwoRegMiscFP16DecodesEveryRow() {
        let rows: [(word: UInt32, text: String)] = [
            (0x0E79_8820, "frintn v0.4h, v1.4h"), (0x0E79_9820, "frintm v0.4h, v1.4h"),
            (0x0E79_A820, "fcvtns v0.4h, v1.4h"), (0x0E79_B820, "fcvtms v0.4h, v1.4h"),
            (0x0E79_C820, "fcvtas v0.4h, v1.4h"), (0x0E79_D820, "scvtf v0.4h, v1.4h"),
            (0x0EF8_C820, "fcmgt v0.4h, v1.4h, #0.0"), (0x0EF8_D820, "fcmeq v0.4h, v1.4h, #0.0"),
            (0x0EF8_E820, "fcmlt v0.4h, v1.4h, #0.0"), (0x0EF8_F820, "fabs v0.4h, v1.4h"),
            (0x0EF9_8820, "frintp v0.4h, v1.4h"), (0x0EF9_9820, "frintz v0.4h, v1.4h"),
            (0x0EF9_A820, "fcvtps v0.4h, v1.4h"), (0x0EF9_B820, "fcvtzs v0.4h, v1.4h"),
            (0x0EF9_D820, "frecpe v0.4h, v1.4h"),
            (0x2E79_8820, "frinta v0.4h, v1.4h"), (0x2E79_9820, "frintx v0.4h, v1.4h"),
            (0x2E79_A820, "fcvtnu v0.4h, v1.4h"), (0x2E79_B820, "fcvtmu v0.4h, v1.4h"),
            (0x2E79_C820, "fcvtau v0.4h, v1.4h"), (0x2E79_D820, "ucvtf v0.4h, v1.4h"),
            (0x2EF8_C820, "fcmge v0.4h, v1.4h, #0.0"), (0x2EF8_D820, "fcmle v0.4h, v1.4h, #0.0"),
            (0x2EF8_F820, "fneg v0.4h, v1.4h"),
            (0x2EF9_9820, "frinti v0.4h, v1.4h"),
            (0x2EF9_A820, "fcvtpu v0.4h, v1.4h"), (0x2EF9_B820, "fcvtzu v0.4h, v1.4h"),
            (0x2EF9_D820, "frsqrte v0.4h, v1.4h"), (0x2EF9_F820, "fsqrt v0.4h, v1.4h"),
        ]
        for row in rows {
            #expect(decode(row.word).text == row.text)
        }
        // The Q=1 form of one representative row renders .8h.
        #expect(decode(0x4E79_8820).text == "frintn v0.8h, v1.8h")
        #expect(decode(0x0E78_0820).isUndefined) // opcode 00000 unmapped
        #expect(decode(0x0E38_0820).isUndefined) // bit22 = 0 reserved
    }

    @Test func scalarTwoRegMiscFP16DecodesEveryRow() {
        let rows: [(word: UInt32, text: String)] = [
            (0x5E79_A820, "fcvtns h0, h1"), (0x5E79_B820, "fcvtms h0, h1"),
            (0x5E79_C820, "fcvtas h0, h1"), (0x5E79_D820, "scvtf h0, h1"),
            (0x5EF8_C820, "fcmgt h0, h1, #0.0"), (0x5EF8_D820, "fcmeq h0, h1, #0.0"),
            (0x5EF8_E820, "fcmlt h0, h1, #0.0"),
            (0x5EF9_A820, "fcvtps h0, h1"), (0x5EF9_B820, "fcvtzs h0, h1"),
            (0x5EF9_D820, "frecpe h0, h1"), (0x5EF9_F820, "frecpx h0, h1"),
            (0x7E79_A820, "fcvtnu h0, h1"), (0x7E79_B820, "fcvtmu h0, h1"),
            (0x7E79_C820, "fcvtau h0, h1"), (0x7E79_D820, "ucvtf h0, h1"),
            (0x7EF8_C820, "fcmge h0, h1, #0.0"), (0x7EF8_D820, "fcmle h0, h1, #0.0"),
            (0x7EF9_A820, "fcvtpu h0, h1"), (0x7EF9_B820, "fcvtzu h0, h1"),
            (0x7EF9_D820, "frsqrte h0, h1"),
        ]
        for row in rows {
            #expect(decode(row.word).text == row.text)
        }
        #expect(decode(0x5E78_0820).isUndefined) // opcode 00000 unmapped
        #expect(decode(0x5E38_0820).isUndefined) // bit22 = 0 reserved
    }

    @Test func fpConvertNarrowLongDecodesEveryShape() {
        let rows: [(word: UInt32, text: String)] = [
            (0x0E21_6820, "fcvtn v0.4h, v1.4s"), (0x4E21_6820, "fcvtn2 v0.8h, v1.4s"),
            (0x0E61_6820, "fcvtn v0.2s, v1.2d"), (0x4E61_6820, "fcvtn2 v0.4s, v1.2d"),
            (0x0E21_7820, "fcvtl v0.4s, v1.4h"), (0x4E21_7820, "fcvtl2 v0.4s, v1.8h"),
            (0x0E61_7820, "fcvtl v0.2d, v1.2s"), (0x4E61_7820, "fcvtl2 v0.2d, v1.4s"),
            (0x2E61_6820, "fcvtxn v0.2s, v1.2d"), (0x6E61_6820, "fcvtxn2 v0.4s, v1.2d"),
            (0x0EA1_6820, "bfcvtn v0.4h, v1.4s"), (0x4EA1_6820, "bfcvtn2 v0.8h, v1.4s"),
            (0x2E21_7820, "f1cvtl v0.8h, v1.8b"), (0x6E21_7820, "f1cvtl2 v0.8h, v1.16b"),
            (0x2E61_7820, "f2cvtl v0.8h, v1.8b"), (0x6E61_7820, "f2cvtl2 v0.8h, v1.16b"),
            (0x2EA1_7820, "bf1cvtl v0.8h, v1.8b"), (0x6EA1_7820, "bf1cvtl2 v0.8h, v1.16b"),
            (0x2EE1_7820, "bf2cvtl v0.8h, v1.8b"), (0x6EE1_7820, "bf2cvtl2 v0.8h, v1.16b"),
        ]
        for row in rows {
            #expect(decode(row.word).text == row.text)
        }
        #expect(decode(0x2E21_6820).isUndefined) // fcvtxn at sz=0 reserved
        #expect(decode(0x0EE1_6820).isUndefined) // bfcvtn at sz=1 reserved
        #expect(decode(0x2EA1_6820).isUndefined) // (U=1, 10110, bit23=1) unmapped
    }

    @Test func fpFamilyTwoRegMiscReservedShapesAreUndefined() {
        #expect(decode(0x4EE1_E820).isUndefined) // frint32z shape with altBit=1
        #expect(decode(0x4EE1_C820).isUndefined) // urecpe .2d reserved
    }

    @Test func scalarPairwiseFP16DecodesEveryRow() {
        let rows: [(word: UInt32, text: String)] = [
            (0x5E30_C820, "fmaxnmp h0, v1.2h"),
            (0x5EB0_C820, "fminnmp h0, v1.2h"),
            (0x5E30_D820, "faddp h0, v1.2h"),
            (0x5E30_F820, "fmaxp h0, v1.2h"),
            (0x5EB0_F820, "fminp h0, v1.2h"),
        ]
        for row in rows {
            #expect(decode(row.word).text == row.text)
        }
        #expect(decode(0x5E30_E820).isUndefined) // opcode 01110 unmapped FP16
    }

    @Test func scalarFcvtxnDecodes() {
        let d = decode(0x7E61_6820)
        #expect(d.mnemonic == .fcvtxn)
        #expect(d.text == "fcvtxn s0, d1")
        #expect(decode(0x7E21_6820).isUndefined) // size=00 reserved scalar
    }

    @Test func threeRegExtensionDecodesComplexArithmetic() {
        let rows: [(word: UInt32, text: String)] = [
            (0x2E42_C420, "fcmla v0.4h, v1.4h, v2.4h, #0"),
            (0x2E42_CC20, "fcmla v0.4h, v1.4h, v2.4h, #90"),
            (0x2E42_D420, "fcmla v0.4h, v1.4h, v2.4h, #180"),
            (0x2E42_DC20, "fcmla v0.4h, v1.4h, v2.4h, #270"),
            (0x6E42_C420, "fcmla v0.8h, v1.8h, v2.8h, #0"),
            (0x2E82_C420, "fcmla v0.2s, v1.2s, v2.2s, #0"),
            (0x6E82_C420, "fcmla v0.4s, v1.4s, v2.4s, #0"),
            (0x6EC2_C420, "fcmla v0.2d, v1.2d, v2.2d, #0"),
            (0x2E42_E420, "fcadd v0.4h, v1.4h, v2.4h, #90"),
            (0x2E42_F420, "fcadd v0.4h, v1.4h, v2.4h, #270"),
            (0x2E42_8420, "sqrdmlah v0.4h, v1.4h, v2.4h"),
            (0x2E42_8C20, "sqrdmlsh v0.4h, v1.4h, v2.4h"),
            (0x2E82_8420, "sqrdmlah v0.2s, v1.2s, v2.2s"),
        ]
        for row in rows {
            #expect(decode(row.word).text == row.text)
        }
        #expect(decode(0x2EC2_C420).isUndefined) // fcmla .1d (size=3, Q=0)
        // FCMLA accumulates — Vd participates in the reads.
        #expect(decode(0x2E42_C420).semanticReads.contains(.simd(0)))
        #expect(!decode(0x2E42_E420).semanticReads.contains(.simd(0))) // FCADD does not
    }

    @Test func threeRegExtensionDecodesDotMMLAAndConvertFamilies() {
        let rows: [(word: UInt32, text: String)] = [
            (0x0E82_9420, "sdot v0.2s, v1.8b, v2.8b"),
            (0x2E82_9420, "udot v0.2s, v1.8b, v2.8b"),
            (0x0E82_9C20, "usdot v0.2s, v1.8b, v2.8b"),
            (0x2E42_FC20, "bfdot v0.2s, v1.4h, v2.4h"),
            (0x0E02_FC20, "fdot v0.2s, v1.8b, v2.8b"),
            (0x0E42_FC20, "fdot v0.4h, v1.8b, v2.8b"),
            (0x4E82_A420, "smmla v0.4s, v1.16b, v2.16b"),
            (0x6E82_A420, "ummla v0.4s, v1.16b, v2.16b"),
            (0x4E82_AC20, "usmmla v0.4s, v1.16b, v2.16b"),
            (0x6E42_EC20, "bfmmla v0.4s, v1.8h, v2.8h"),
            (0x2EC2_FC20, "bfmlalb v0.4s, v1.8h, v2.8h"),
            (0x6EC2_FC20, "bfmlalt v0.4s, v1.8h, v2.8h"),
            (0x0EC2_FC20, "fmlalb v0.8h, v1.16b, v2.16b"),
            (0x4EC2_FC20, "fmlalt v0.8h, v1.16b, v2.16b"),
            (0x0E02_C420, "fmlallbb v0.4s, v1.16b, v2.16b"),
            (0x4E02_C420, "fmlalltb v0.4s, v1.16b, v2.16b"),
            (0x0E42_C420, "fmlallbt v0.4s, v1.16b, v2.16b"),
            (0x4E42_C420, "fmlalltt v0.4s, v1.16b, v2.16b"),
            (0x0E02_F420, "fcvtn v0.8b, v1.4s, v2.4s"),
            (0x4E02_F420, "fcvtn2 v0.16b, v1.4s, v2.4s"),
            (0x0E42_F420, "fcvtn v0.8b, v1.4h, v2.4h"),
            (0x4E42_F420, "fcvtn v0.16b, v1.8h, v2.8h"),
        ]
        for row in rows {
            #expect(decode(row.word).text == row.text)
        }
        // MMLA forms are 128-bit only; Q=0 is reserved.
        #expect(decode(0x0E82_A420).isUndefined)
        #expect(decode(0x2E82_AC20).isUndefined) // (1,2,5) unmapped
    }

    @Test func byElementDotFormsDecode() {
        let rows: [(word: UInt32, text: String)] = [
            (0x0F02_F020, "sudot v0.2s, v1.8b, v2.4b[0]"),
            (0x0F42_F020, "bfdot v0.2s, v1.4h, v2.2h[0]"),
            (0x0F02_0020, "fdot v0.2s, v1.8b, v2.4b[0]"),
            (0x0F42_0020, "fdot v0.4h, v1.8b, v2.2b[0]"),
            (0x4F42_0020, "fdot v0.8h, v1.16b, v2.2b[0]"),
            (0x0F72_0820, "fdot v0.4h, v1.8b, v2.2b[7]"),
        ]
        for row in rows {
            let d = decode(row.word)
            #expect(d.text == row.text)
            #expect(d.semanticReads.contains(.simd(0))) // dot accumulates
        }
    }

    @Test func byElementFmlalFamiliesDecode() {
        let rows: [(word: UInt32, text: String)] = [
            (0x0FC2_0020, "fmlalb v0.8h, v1.16b, v2.b[0]"),
            (0x4FC2_0020, "fmlalt v0.8h, v1.16b, v2.b[0]"),
            (0x0FFA_0820, "fmlalb v0.8h, v1.16b, v2.b[15]"),
            (0x0FC2_F020, "bfmlalb v0.4s, v1.8h, v2.h[0]"),
            (0x4FC2_F020, "bfmlalt v0.4s, v1.8h, v2.h[0]"),
            (0x0FD2_F820, "bfmlalb v0.4s, v1.8h, v2.h[5]"),
            (0x2F02_8020, "fmlallbb v0.4s, v1.16b, v2.b[0]"),
            (0x6F02_8020, "fmlalltb v0.4s, v1.16b, v2.b[0]"),
            (0x2F42_8020, "fmlallbt v0.4s, v1.16b, v2.b[0]"),
            (0x6F42_8020, "fmlalltt v0.4s, v1.16b, v2.b[0]"),
        ]
        for row in rows {
            #expect(decode(row.word).text == row.text)
        }
    }

    @Test func byElementFcmlaDecodes() {
        let rows: [(word: UInt32, text: String)] = [
            (0x2F42_1020, "fcmla v0.4h, v1.4h, v2.h[0], #0"),
            (0x2F42_3020, "fcmla v0.4h, v1.4h, v2.h[0], #90"),
            (0x2F42_5020, "fcmla v0.4h, v1.4h, v2.h[0], #180"),
            (0x2F42_7020, "fcmla v0.4h, v1.4h, v2.h[0], #270"),
            (0x6F42_1020, "fcmla v0.8h, v1.8h, v2.h[0], #0"),
            (0x6F62_1820, "fcmla v0.8h, v1.8h, v2.h[3], #0"),
            (0x6F82_1020, "fcmla v0.4s, v1.4s, v2.s[0], #0"),
            (0x6F82_1820, "fcmla v0.4s, v1.4s, v2.s[1], #0"),
        ]
        for row in rows {
            #expect(decode(row.word).text == row.text)
        }
        #expect(decode(0x2F42_1820).isUndefined) // .4h with H=1 reserved
        #expect(decode(0x2F82_1020).isUndefined) // .2s form reserved
    }

    @Test func lutFormsDecodeWithListAndLaneOperands() {
        let rows: [(word: UInt32, text: String)] = [
            (0x4E82_1020, "luti2 v0.16b, { v1.16b }, v2[0]"),
            (0x4E82_5020, "luti2 v0.16b, { v1.16b }, v2[2]"),
            (0x4EC2_0020, "luti2 v0.8h, { v1.8h }, v2[0]"),
            (0x4EC2_1020, "luti2 v0.8h, { v1.8h }, v2[1]"),
            (0x4E43_1020, "luti4 v0.8h, { v1.8h, v2.8h }, v3[0]"),
            (0x4E42_2020, "luti4 v0.16b, { v1.16b }, v2[0]"),
            (0x4E42_6020, "luti4 v0.16b, { v1.16b }, v2[1]"),
        ]
        for row in rows {
            let d = decode(row.word)
            #expect(d.category == .simdAndFP)
            #expect(d.text == row.text)
        }
        #expect(decode(0x0E82_1020).isUndefined) // Q=0 unallocated
        #expect(decode(0x4E82_0020).isUndefined) // LUTI2 .16b needs bit12=1
        #expect(decode(0x4E42_0020).isUndefined) // LUTI4 with neither bit12/13
        #expect(decode(0x4E82_1420).isUndefined) // bits 11:10 must be 0
    }

    @Test func pmullQuadwordPolynomialFormsDecode() {
        // PMULL/PMULL2 at size=11 produce the .1q polynomial product.
        let lo = decode(0x0EE2_E020)
        #expect(lo.mnemonic == .pmull)
        #expect(lo.text == "pmull v0.1q, v1.1d, v2.1d")
        #expect(lo.semanticReads.contains(.simd(1)) && lo.semanticReads.contains(.simd(2)))
        #expect(lo.semanticWrites.contains(.simd(0)))
        let hi = decode(0x4EE2_E020)
        #expect(hi.mnemonic == .pmull2)
        #expect(hi.text == "pmull2 v0.1q, v1.2d, v2.2d")
    }

    @Test func fp16AcrossLanesReductionsDecode() {
        let h4 = decode(0x0E30_C820)
        #expect(h4.mnemonic == .fmaxnmv)
        #expect(h4.text == "fmaxnmv h0, v1.4h")
        let h8 = decode(0x4E30_C820)
        #expect(h8.mnemonic == .fmaxnmv)
        #expect(h8.text == "fmaxnmv h0, v1.8h")
        let minnm = decode(0x0EB0_C820)
        #expect(minnm.mnemonic == .fminnmv)
        #expect(minnm.text == "fminnmv h0, v1.4h")
    }

    @Test func movi64BitFormsDecode() {
        // op=1 vector form replicates the abcdefgh byte mask into .2d.
        let vec = decode(0x6F05_E540)
        #expect(vec.mnemonic == .movi)
        #expect(vec.text == "movi v0.2d, #0xff00ff00ff00ff00")
        // op=1 with Q=0 is the scalar 64-bit MOVI (Dd destination).
        let scalar = decode(0x2F07_E7E0)
        #expect(scalar.mnemonic == .movi)
        #expect(scalar.text == "movi d0, #0xffffffffffffffff")
    }

    @Test func lengtheningByElementFormsUseTheUpperHalfMnemonicAtQ1() {
        let rows: [(word: UInt32, mnemonic: Mnemonic, name: String)] = [
            (0x4F42_2020, .smlal2, "smlal2"),
            (0x4F42_6020, .smlsl2, "smlsl2"),
            (0x4F42_A020, .smull2, "smull2"),
            (0x4F42_3020, .sqdmlal2, "sqdmlal2"),
            (0x4F42_7020, .sqdmlsl2, "sqdmlsl2"),
            (0x4F42_B020, .sqdmull2, "sqdmull2"),
            (0x6F42_2020, .umlal2, "umlal2"),
            (0x6F42_6020, .umlsl2, "umlsl2"),
            (0x6F42_A020, .umull2, "umull2"),
        ]
        for row in rows {
            let d = decode(row.word)
            #expect(d.mnemonic == row.mnemonic, "0x\(String(row.word, radix: 16))")
            #expect(d.text == "\(row.name) v0.4s, v1.8h, v2.h[0]")
        }
        // Q=0 keeps the base mnemonic.
        let base = decode(0x0F42_2020)
        #expect(base.mnemonic == .smlal)
        #expect(base.text == "smlal v0.4s, v1.4h, v2.h[0]")
    }

    @Test func narrowingShiftRightFormsDecodeEveryArrangement() {
        let rows: [(word: UInt32, text: String)] = [
            (0x0F0F_8420, "shrn v0.8b, v1.8h, #1"),
            (0x4F0F_8420, "shrn2 v0.16b, v1.8h, #1"),
            (0x0F1F_8420, "shrn v0.4h, v1.4s, #1"),
            (0x0F3F_8420, "shrn v0.2s, v1.2d, #1"),
            (0x4F3F_8420, "shrn2 v0.4s, v1.2d, #1"),
        ]
        for row in rows {
            let d = decode(row.word)
            #expect(d.text == row.text, "0x\(String(row.word, radix: 16))")
        }
    }

    @Test func lrcpc3SingleStructureFormsDecode() {
        // FEAT_LRCPC3 STL1/LDAP1 {Vt.d}[i]: release store / acquire load
        // of one D lane; the load preserves the other lane so Vt is both
        // read and written.
        let st0 = decode(0x0D01_8420)
        #expect(st0.mnemonic == .stl1)
        #expect(st0.memoryAccess == .store)
        #expect(st0.memoryOrdering == [.release])
        #expect(st0.text == "stl1 { v0.d }[0], [x1]")
        #expect(st0.semanticReads.contains(.simd(0)) && st0.semanticReads.contains(.x(1)))
        let st1 = decode(0x4D01_8420)
        #expect(st1.text == "stl1 { v0.d }[1], [x1]")
        let ld0 = decode(0x0D41_8420)
        #expect(ld0.mnemonic == .ldap1)
        #expect(ld0.memoryAccess == .load)
        #expect(ld0.memoryOrdering == [.acquire])
        #expect(ld0.text == "ldap1 { v0.d }[0], [x1]")
        #expect(ld0.semanticReads.contains(.simd(0)))
        #expect(ld0.semanticWrites.contains(.simd(0)))
        let ld1 = decode(0x4D41_8420)
        #expect(ld1.text == "ldap1 { v0.d }[1], [x1]")
    }

    @Test func vectorExtensionRowsDecodeEveryNewMnemonic() {
        let rows: [(word: UInt32, text: String)] = [
            (0x0EC2_1C20, "famax v0.4h, v1.4h, v2.4h"), // FEAT_FAMINMAX
            (0x6EA2_DC20, "famin v0.4s, v1.4s, v2.4s"),
            (0x2EC2_3C20, "fscale v0.4h, v1.4h, v2.4h"), // FEAT_FP8
            (0x0E21_E820, "frint32z v0.2s, v1.2s"), // FEAT_FRINTTS
            (0x2E21_E820, "frint32x v0.2s, v1.2s"),
            (0x0E21_F820, "frint64z v0.2s, v1.2s"),
            (0x2E21_F820, "frint64x v0.2s, v1.2s"),
            (0x4E62_B420, "sqdmulh v0.8h, v1.8h, v2.8h"),
            (0x0EA2_B420, "sqdmulh v0.2s, v1.2s, v2.2s"),
            (0x4EA2_B420, "sqdmulh v0.4s, v1.4s, v2.4s"),
            (0x6E20_5820, "mvn v0.16b, v1.16b"),
            (0x6E60_5820, "rbit v0.16b, v1.16b"),
            (0x4E21_2820, "xtn2 v0.16b, v1.8h"),
            (0x4E21_4820, "sqxtn2 v0.16b, v1.8h"),
            (0x6E21_3820, "shll2 v0.8h, v1.16b, #8"),
            (0x6E21_2820, "sqxtun2 v0.16b, v1.8h"),
            (0x6E21_4820, "uqxtn2 v0.16b, v1.8h"),
            (0x0F03_FE00, "fmov v0.4h, #1.00000000"),
            (0x6F03_F600, "fmov v0.2d, #1.00000000"),
        ]
        for row in rows {
            #expect(decode(row.word).text == row.text, "0x\(String(row.word, radix: 16))")
        }
    }

    @Test func singlePrecisionFaminmaxAndFscaleRowsDecode() {
        // The non-FP16 rows of FEAT_FAMINMAX / FEAT_FP8 FSCALE (the .4h
        // forms route through the half-precision three-same decoder).
        #expect(decode(0x4EA2_DC20).text == "famax v0.4s, v1.4s, v2.4s")
        #expect(decode(0x6EA2_FC20).text == "fscale v0.4s, v1.4s, v2.4s")
    }

    @Test func rdmThreeSameExtraDecodesAtBothVectorSizes() {
        // SQRDMLAH (vector, three-same extra) at .4h (size 1) and .4s
        // (size 2).
        #expect(decode(0x2E42_8420).text == "sqrdmlah v0.4h, v1.4h, v2.4h")
        #expect(decode(0x6E82_8420).text == "sqrdmlah v0.4s, v1.4s, v2.4s")
        #expect(decode(0x6E82_8C20).text == "sqrdmlsh v0.4s, v1.4s, v2.4s")
    }

    @Test func fp8DotProductWithHalfDestinationDecodes() {
        // FP8DOT2: byte sources, half-precision destination, Q = 1.
        #expect(decode(0x4E42_FC20).text == "fdot v0.8h, v1.16b, v2.16b")
    }

    @Test func byElementExtensionRowsDecode() {
        let rows: [(word: UInt32, text: String)] = [
            (0x0F02_1020, "fmla v0.4h, v1.4h, v2.h[0]"),
            (0x4F02_1020, "fmla v0.8h, v1.8h, v2.h[0]"),
            (0x0F82_F020, "usdot v0.2s, v1.8b, v2.4b[0]"),
            (0x4F82_F020, "usdot v0.4s, v1.16b, v2.4b[0]"),
            (0x4F42_F020, "bfdot v0.4s, v1.8h, v2.2h[0]"),
            (0x2F42_D020, "sqrdmlah v0.4h, v1.4h, v2.h[0]"),
            (0x2F42_F020, "sqrdmlsh v0.4h, v1.4h, v2.h[0]"),
            (0x2F42_1020, "fcmla v0.4h, v1.4h, v2.h[0], #0"),
            (0x6F42_1020, "fcmla v0.8h, v1.8h, v2.h[0], #0"),
            (0x6F82_3020, "fcmla v0.4s, v1.4s, v2.s[0], #90"),
        ]
        for row in rows {
            #expect(decode(row.word).text == row.text, "0x\(String(row.word, radix: 16))")
        }
    }

    @Test func scalarExtensionRowsDecode() {
        #expect(decode(0x5F1F_9420).text == "sqshrn h0, s1, #1")
        #expect(decode(0x5EA2_B420).text == "sqdmulh s0, s1, s2")
        #expect(decode(0x5F02_1020).text == "fmla h0, h1, v2.h[0]")
    }

    @Test func simdRegisterLrcpc2FormsDecodeEveryWidth() {
        let rows: [(word: UInt32, mnemonic: Mnemonic, text: String, access: MemoryAccess)] = [
            (0x1D00_0820, .stlur, "stlur b0, [x1]", .store),
            (0x1D40_0820, .ldapur, "ldapur b0, [x1]", .load),
            (0x5D00_0820, .stlur, "stlur h0, [x1]", .store),
            (0x5D40_0820, .ldapur, "ldapur h0, [x1]", .load),
            (0x9D00_0820, .stlur, "stlur s0, [x1]", .store),
            (0x9D40_0820, .ldapur, "ldapur s0, [x1]", .load),
            (0xDD00_0820, .stlur, "stlur d0, [x1]", .store),
            (0xDD40_0820, .ldapur, "ldapur d0, [x1]", .load),
            (0x1D80_0820, .stlur, "stlur q0, [x1]", .store),
            (0x1DC0_0820, .ldapur, "ldapur q0, [x1]", .load),
        ]
        for row in rows {
            let d = decode(row.word)
            #expect(d.mnemonic == row.mnemonic)
            #expect(d.memoryAccess == row.access)
            #expect(d.text == row.text)
        }
        // Negative unscaled displacement.
        #expect(decode(0xDD10_0820).text == "stlur d0, [x1, #-256]")
        #expect(decode(0x5D80_0820).isUndefined) // size=01 with opc=10 reserved
        #expect(decode(0x1D00_0020).isUndefined) // bits 11:10 != 10
        #expect(decode(0x1D20_0820).isUndefined) // bit 21 set
    }
}
