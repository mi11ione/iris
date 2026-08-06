// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Exercises the scalable text router behind ``Instruction/text``, the
/// scalable projections on both the ``Instruction`` and.
@Suite("Scalable coverage — router, projections, CSSC")
struct ScalableCoverageTests {
    static let regionCases: [(word: UInt32, text: String)] = [
        (0x2518_E020, "ptrue p0.b, vl1"),
        (0x04C3_03E1, "subr z1.d, p0/m, z1.d, z31.d"),
        (0x6508_0840, "bfmul z0.h, z2.h, z8.h"),
        (0x844F_7FC0, "ldff1b { z0.s }, p7/z, [x30, z15.s, sxtw]"),
        (0x2521_801F, "firstp xzr, p0, p0.b"),
        (0x8080_FC00, "fmopa za0.s, p7/m, p7/m, z0.s, z0.s"),
        (0xE07F_BFEC, "st1h {za1v.h[w13, 4]}, p7, [sp]"),
        (0xC150_64C4, "fmla za.s[w11, 4, vgx2], { z6.s, z7.s }, z0.s[1]"),
    ]

    @Test func textRoutesThroughEveryScalableRegion() {
        for c in Self.regionCases {
            let inst = decode(c.word, at: 0)
            #expect(inst.text == c.text, "0x\(String(c.word, radix: 16)): got `\(inst.text)`")
        }
    }

    @Test func scalableTierHolesRenderLongDirective() {
        let sve = decode(0x2540_4210, at: 0)
        #expect(sve.category == .sve)
        #expect(sve.isUndefined)
        #expect(sve.text == ".long 0x25404210")

        let sme = decode(0x802D_E5FA, at: 0)
        #expect(sme.category == .sme)
        #expect(sme.isUndefined)
        #expect(sme.text == ".long 0x802de5fa")
    }

    @Test func aScalableRecordOutsideTheTierRendersLongDirective() {
        let foreign = Instruction(encoding: 0xD503_201F, mnemonic: .add, category: .sve)
        #expect(foreign.text == ".long 0xd503201f")
    }

    @Test func scalableProjectionsReadBackOnBothTiers() {
        let subr = decode(0x04C3_03E1, at: 0)
        #expect(!subr.scalableReads.isEmpty)
        #expect(subr.scalableEffect != .none)
        let fmopa = decode(0x8080_FC00, at: 0)
        #expect(!fmopa.scalableWrites.isEmpty)

        let bytes: [UInt8] = [0xE1, 0x03, 0xC3, 0x04]
        let stream = InstructionStream(bytes: bytes, at: 0)
        var sawReads = false, sawEffect = false
        stream.withSession { session in
            for view in session {
                if !view.scalableReads.isEmpty { sawReads = true }
                _ = view.scalableWrites
                if view.scalableEffect != .none { sawEffect = true }
            }
        }
        #expect(sawReads)
        #expect(sawEffect)
    }

    @Test func csscMinMaxImmediateAllOpcodesAndReject() {
        #expect(decode(0x91C3_0000).text == "smax x0, x0, #-64")
        #expect(decode(0x91C7_0000).text == "umax x0, x0, #192")
        #expect(decode(0x91CB_0000).text == "smin x0, x0, #-64")
        #expect(decode(0x91CF_0000).text == "umin x0, x0, #192")
        for m in [decode(0x91C3_0000).mnemonic, decode(0x91C7_0000).mnemonic,
                  decode(0x91CB_0000).mnemonic, decode(0x91CF_0000).mnemonic]
        {
            #expect([.smax, .umax, .smin, .umin].contains(m))
        }
        let rej = decode(0x91D3_0000)
        #expect(rej.isUndefined)
        #expect(rej.category == .undefined)
    }

    @Test func csscMinMaxImmediateDecodesTheThirtyTwoBitForms() {
        #expect(decode(0x11C3_0000).text == "smax w0, w0, #-64")
        #expect(decode(0x11C7_0000).text == "umax w0, w0, #192")
        #expect(decode(0x11CB_0000).text == "smin w0, w0, #-64")
        #expect(decode(0x11CF_0000).text == "umin w0, w0, #192")
    }
}

/// The scalable scope predicates are the seam decode, text and validation all
/// route through, so what a caller can hold them to is tested directly.
@Suite("Scalable scope predicates — total over any word")
struct ScalableScopePredicateTotalityTests {
    @Test func everyPredicateRejectsANonScalableWord() {
        let nop: UInt32 = 0xD503_201F
        #expect(!isSVEPredicateControlEncoding(nop))
        #expect(!isSVEIntegerEncoding(nop))
        #expect(!isSVEFloatingPointEncoding(nop))
        #expect(!isSVEPermuteMemoryCryptoEncoding(nop))
        #expect(!isSVECounterPredicateEncoding(nop))
        #expect(!isSMECoreEncoding(nop))
        #expect(decode(nop).category == .branchesExceptionSystem)
    }

    @Test func sveIntegerRejectsThePredicateCarveOutsAtTopByteZeroFour() {
        #expect(!isSVEIntegerEncoding(0x0410_2000))
        #expect(isSVEPredicateControlEncoding(0x0410_2000))
        #expect(!isSVEIntegerEncoding(0x0424_4000))
        #expect(isSVEPredicateControlEncoding(0x0424_4000))
    }
}
