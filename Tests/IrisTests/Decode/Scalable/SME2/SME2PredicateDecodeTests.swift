// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ e: UInt32) -> Instruction {
    Iris.decode(e, at: 0)
}

private func text(_ e: UInt32) -> String {
    decode(e).text
}

private func expectFamily(_ e: UInt32, _ m: Mnemonic, _ label: String) {
    let d = decode(e)
    #expect(d.mnemonic == m, "\(label) 0x\(String(e, radix: 16))")
    #expect(d.category == .sve, "\(label)")
    let t = text(e)
    #expect(!t.isEmpty && !t.contains("?") && !t.contains("\n"), "\(label) -> \(t)")
}

/// Validates the SME2 op0=2 predicate-as-counter carve (top byte `0x25`,
/// b21=1) — the words the four SVE subpiece decoders (2s.2–2s.5) reject: WHILE
/// producing a counter predicate or a predicate pair, PEXT, PTRUE-counter,
/// CNTP-counter, FIRSTP/LASTP, and PSEL. The carve keeps the SVE-family
/// identity (`category = .sve`), sets NZCV only on WHILE, and rejects its holes
/// to a well-formed UNDEFINED.
@Suite("SME2 / predicate-as-counter carve decode")
struct SME2PredicateDecodeTests {
    @Test func theWhileCounterConditionsCoverEveryComparison() {
        // (unsigned, less, or-equal) select the eight WHILE conditions; the
        // destination is a counter predicate PN8-PN15 with a mandatory vlx.
        let conditions: [(UInt32, Mnemonic)] = [
            (0x2520_4010, .whilege), (0x2520_4018, .whilegt),
            (0x2520_4410, .whilelt), (0x2520_4418, .whilele),
            (0x2520_4810, .whilehs), (0x2520_4818, .whilehi),
            (0x2520_4C10, .whilelo), (0x2520_4C18, .whilels),
        ]
        for (e, m) in conditions {
            expectFamily(e, m, "while-counter")
            #expect(decode(e).flagEffect == .nzcv, "0x\(String(e, radix: 16)) sets NZCV")
        }
        #expect(text(0x2520_4010) == "whilege pn8.b, x0, x0, vlx2")
        #expect(text(0x2520_6010) == "whilege pn8.b, x0, x0, vlx4")
    }

    @Test func theWhilePairFormWritesAnEvenOddPredicatePair() {
        expectFamily(0x2520_5010, .whilege, "while-pair")
        expectFamily(0x2520_5410, .whilelt, "while-pair lt")
        #expect(text(0x2520_5010) == "whilege { p0.b, p1.b }, x0, x0")
        #expect(decode(0x2520_5010).flagEffect == .nzcv)
    }

    @Test func pextExtractsASinglePredicateOrAPair() {
        expectFamily(0x2520_7010, .pext, "pext single")
        expectFamily(0x2520_7410, .pext, "pext pair")
        #expect(text(0x2520_7010) == "pext p0.b, pn8[0]")
        #expect(text(0x2520_7410) == "pext { p0.b, p1.b }, pn8[0]")
    }

    @Test func ptrueCounterMakesAnAllTrueCounterPredicate() {
        expectFamily(0x2520_7810, .ptrue, "ptrue counter")
        #expect(text(0x2520_7810) == "ptrue pn8.b")
    }

    @Test func cntpCounterCountsActiveCounterElements() {
        expectFamily(0x2520_8200, .cntp, "cntp counter")
        #expect(text(0x2520_8200) == "cntp x0, pn0.b, vlx2")
        #expect(text(0x2520_8600) == "cntp x0, pn0.b, vlx4")
    }

    @Test func firstpAndLastpReportTheActiveElementIndex() {
        expectFamily(0x2521_8000, .firstp, "firstp")
        expectFamily(0x2522_8000, .lastp, "lastp")
        #expect(text(0x2521_8000) == "firstp x0, p0, p0.b")
        #expect(text(0x2522_8000) == "lastp x0, p0, p0.b")
    }

    @Test func pselSelectsAPredicateByIndexedElement() {
        // The tsz trailing-one scheme sets the element and index; tsz==0000 is
        // reserved.
        expectFamily(0x2524_4000, .psel, "psel .b")
        expectFamily(0x2528_4000, .psel, "psel .h")
        expectFamily(0x2530_4000, .psel, "psel .s")
        expectFamily(0x2560_4000, .psel, "psel .d")
        #expect(text(0x2524_4000) == "psel p0, p0, p0.b[w12, 0]")
        // tsz == 0000 is the reserved PSEL hole.
        #expect(decode(0x2520_4000).mnemonic == .undefined)
    }

    @Test func everyCarveRecordKeepsTheSVEIdentityAndTouchesNoMatrix() {
        for e: UInt32 in [
            0x2520_4010, 0x2520_5010, 0x2520_7010, 0x2520_7410,
            0x2520_7810, 0x2520_8200, 0x2521_8000, 0x2522_8000, 0x2524_4000,
        ] {
            let d = decode(e)
            #expect(d.category == .sve, "0x\(String(e, radix: 16))")
            #expect(d.scalableReads.zaMask.isEmpty && d.scalableWrites.zaMask.isEmpty)
            #expect(!d.scalableReads.containsZT0 && !d.scalableWrites.containsZT0)
            #expect(d.scalableEffect.contains(.readsStreamingMode))
            #expect(d.branchClass == .none)
        }
    }

    @Test func theFamilyDecoderRoutesTheCarveThroughTheSVEGate() {
        // SVEDecoder intercepts the carve after the four subpiece predicates
        // reject it, so a carve word decodes to a real record via the family.
        let d = Iris.decode(0x2520_4010, at: 0x8000)
        #expect(d.mnemonic == .whilege)
        #expect(d.address == 0x8000)
    }
}
