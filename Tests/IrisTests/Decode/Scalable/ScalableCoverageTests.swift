// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Exercises the scalable text router behind ``Instruction/text``, the scalable
/// projections on both the ``Instruction`` and ``BorrowedInstruction`` tiers,
/// and the FEAT_CSSC min/max-immediate decoder — the paths the per-family
/// decode/canonicalizer suites reach indirectly or not at all.
@Suite("Scalable coverage — router, projections, CSSC")
struct ScalableCoverageTests {
    /// One decoded instruction per SVE/SME region, with its canonical text.
    /// Routing each through ``Instruction/text`` covers every arm of the
    /// scalable text router and its region canonicalizers.
    static let regionCases: [(word: UInt32, text: String)] = [
        (0x2518_E020, "ptrue p0.b, vl1"), // SVE predicate/control
        (0x04C3_03E1, "subr z1.d, p0/m, z1.d, z31.d"), // SVE integer (predicated)
        (0x6508_0840, "bfmul z0.h, z2.h, z8.h"), // SVE floating-point
        (0x844F_7FC0, "ldff1b { z0.s }, p7/z, [x30, z15.s, sxtw]"), // SVE permute/memory
        (0x2521_801F, "firstp xzr, p0, p0.b"), // SVE predicate-as-counter carve
        (0x8080_FC00, "fmopa za0.s, p7/m, p7/m, z0.s, z0.s"), // SME core (outer product)
        (0xE07F_BFEC, "st1h {za1v.h[w13, 4]}, p7, [sp]"), // SME core (ZA load/store)
        (0xC150_64C4, "fmla za.s[w11, 4, vgx2], { z6.s, z7.s }, z0.s[1]"), // SME2 multi-vector
    ]

    @Test func textRoutesThroughEveryScalableRegion() {
        for c in Self.regionCases {
            let inst = decode(c.word, at: 0)
            #expect(inst.text == c.text, "0x\(String(c.word, radix: 16)): got `\(inst.text)`")
        }
    }

    @Test func scalableTierHolesRenderLongDirective() {
        // An in-scope but unallocated word: category stays .sve/.sme, mnemonic
        // is the UNDEFINED sentinel, and the router renders the raw `.long`.
        let sve = decode(0x2540_4210, at: 0)
        #expect(sve.category == .sve)
        #expect(sve.isUndefined)
        #expect(sve.text == ".long 0x25404210")

        let sme = decode(0x802D_E5FA, at: 0)
        #expect(sme.category == .sme)
        #expect(sme.isUndefined)
        #expect(sme.text == ".long 0x802de5fa")
    }

    /// A `.sve`-tagged record whose word is not an SVE-tier encoding at all —
    /// which only a hand-built record can be, since the decoder only tags words
    /// it routed — has no region canonicalizer to render it, so the router falls
    /// back to the raw `.long` directive instead of guessing a region.
    @Test func aScalableRecordOutsideTheTierRendersLongDirective() {
        let foreign = Instruction(encoding: 0xD503_201F, mnemonic: .add, category: .sve)
        #expect(foreign.text == ".long 0xd503201f")
    }

    @Test func scalableProjectionsReadBackOnBothTiers() {
        // A predicated SVE op populates scalableReads (governing predicate) and
        // scalableEffect (streaming-mode); an SME outer product writes ZA.
        let subr = decode(0x04C3_03E1, at: 0)
        #expect(!subr.scalableReads.isEmpty)
        #expect(subr.scalableEffect != .none)
        let fmopa = decode(0x8080_FC00, at: 0)
        #expect(!fmopa.scalableWrites.isEmpty)

        // The borrowed session tier mirrors the three projections.
        let bytes: [UInt8] = [0xE1, 0x03, 0xC3, 0x04] // 0x04c303e1, little-endian
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
        #expect(decode(0x91C3_0000).text == "smax x0, x0, #-64") // opc=00 SMAX (signed)
        #expect(decode(0x91C7_0000).text == "umax x0, x0, #192") // opc=01 UMAX (unsigned)
        #expect(decode(0x91CB_0000).text == "smin x0, x0, #-64") // opc=10 SMIN
        #expect(decode(0x91CF_0000).text == "umin x0, x0, #192") // opc=11 UMIN
        for m in [decode(0x91C3_0000).mnemonic, decode(0x91C7_0000).mnemonic,
                  decode(0x91CB_0000).mnemonic, decode(0x91CF_0000).mnemonic]
        {
            #expect([.smax, .umax, .smin, .umin].contains(m))
        }
        // op1=0b011, bit22=1, but bits[21:20] != 0 — the fixed-bit guard rejects.
        let rej = decode(0x91D3_0000)
        #expect(rej.isUndefined)
        #expect(rej.category == .undefined)
    }

    /// The 32-bit (`sf=0`) half of the min/max-immediate forms — same opcodes
    /// against `w` registers, which is the other arm of the width selector.
    @Test func csscMinMaxImmediateDecodesTheThirtyTwoBitForms() {
        #expect(decode(0x11C3_0000).text == "smax w0, w0, #-64")
        #expect(decode(0x11C7_0000).text == "umax w0, w0, #192")
        #expect(decode(0x11CB_0000).text == "smin w0, w0, #-64")
        #expect(decode(0x11CF_0000).text == "umin w0, w0, #192")
    }
}

/// The scalable scope predicates are the public seam decode, text, and
/// validation all route through, so what a caller can hold them to is tested
/// directly: they are safe on any 32-bit word (rejecting anything outside their
/// tier), and the family boundaries inside the SVE tier fall where the
/// architecture puts them, not where the coarse region map would.
@Suite("Scalable scope predicates — total over any word")
struct ScalableScopePredicateTotalityTests {
    /// A word outside the scalable tiers entirely (`NOP`, `op0=0b1010`). Every
    /// predicate re-checks its own architectural position, so each rejects it
    /// rather than reading fields that mean nothing there.
    @Test func everyPredicateRejectsANonScalableWord() {
        let nop: UInt32 = 0xD503_201F
        #expect(!isSVEPredicateControlEncoding(nop))
        #expect(!isSVEIntegerEncoding(nop))
        #expect(!isSVEFloatingPointEncoding(nop))
        #expect(!isSVEPermuteMemoryCryptoEncoding(nop))
        #expect(!isSVECounterPredicateEncoding(nop))
        #expect(!isSMECoreEncoding(nop))
        // And the decoded record agrees it is not scalable.
        #expect(decode(nop).category == .branchesExceptionSystem)
    }

    /// The 0x04 top byte is the coarse "integer" region, but SVE-predicate owns
    /// a carve-out inside it: predicated MOVPRFX and the element-count / INDEX /
    /// stack-adjust groups. SVE-integer's predicate must reject exactly those,
    /// which is finer than the region map — so a word from each carve-out is
    /// asked directly.
    @Test func sveIntegerRejectsThePredicateCarveOutsAtTopByteZeroFour() {
        // b21=0, b21:19=010, b18:17=00, b15:13=001 — predicated MOVPRFX.
        #expect(!isSVEIntegerEncoding(0x0410_2000))
        #expect(isSVEPredicateControlEncoding(0x0410_2000))
        // b21=1, bits[15:12]=0100 — the INDEX group.
        #expect(!isSVEIntegerEncoding(0x0424_4000))
        #expect(isSVEPredicateControlEncoding(0x0424_4000))
    }
}
