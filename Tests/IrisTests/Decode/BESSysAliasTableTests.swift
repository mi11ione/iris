// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Pins named rows of the IC/DC/AT/TLBI SYS alias surface through the
/// public decode + text path: each (op1, CRn, CRm, op2) tuple is decoded
/// at Rt = 0 and Rt = 31 and must render the documented friendly form —
/// register-taking aliases render `name, x0` / `name, xzr`, bare aliases
/// render the name at XZR and fall back to the generic `sys` tuple form
/// otherwise, and unrecognized tuples always render the generic form.
/// The decoder and the canonicalizer share the alias table, so a
/// misaligned row would surface here and as a parity divergence.
@Suite("BES / SYS alias rendering")
struct BESSysAliasTableTests {
    private func sysText(_ op1: UInt8, _ CRn: UInt8, _ CRm: UInt8, _ op2: UInt8, rt: UInt32) -> String {
        let word = 0xD508_0000 | UInt32(op1) << 16 | UInt32(CRn) << 12 | UInt32(CRm) << 8 | UInt32(op2) << 5 | rt
        return decode(word).text
    }

    @Test func icIalluis() {
        #expect(sysText(0, 7, 1, 0, rt: 31) == "ic ialluis")
        #expect(sysText(0, 7, 1, 0, rt: 0) == "sys #0, c7, c1, #0, x0")
    }

    @Test func icIallu() {
        #expect(sysText(0, 7, 5, 0, rt: 31) == "ic iallu")
        #expect(sysText(0, 7, 5, 0, rt: 0) == "sys #0, c7, c5, #0, x0")
    }

    @Test func icIvauNeedsReg() {
        #expect(sysText(3, 7, 5, 1, rt: 0) == "ic ivau, x0")
        #expect(sysText(3, 7, 5, 1, rt: 31) == "ic ivau, xzr")
    }

    @Test func dcZva() {
        #expect(sysText(3, 7, 4, 1, rt: 0) == "dc zva, x0")
        #expect(sysText(3, 7, 4, 1, rt: 31) == "dc zva, xzr")
    }

    @Test func dcIvac() {
        #expect(sysText(0, 7, 6, 1, rt: 0) == "dc ivac, x0")
    }

    @Test func dcIsw() {
        #expect(sysText(0, 7, 6, 2, rt: 0) == "dc isw, x0")
    }

    @Test func dcCvac() {
        #expect(sysText(3, 7, 10, 1, rt: 0) == "dc cvac, x0")
    }

    @Test func dcCsw() {
        #expect(sysText(0, 7, 10, 2, rt: 0) == "dc csw, x0")
    }

    @Test func dcCvau() {
        #expect(sysText(3, 7, 11, 1, rt: 0) == "dc cvau, x0")
    }

    @Test func dcCivac() {
        #expect(sysText(3, 7, 14, 1, rt: 0) == "dc civac, x0")
    }

    @Test func dcCvap() {
        #expect(sysText(3, 7, 12, 1, rt: 0) == "dc cvap, x0")
    }

    @Test func dcCisw() {
        #expect(sysText(0, 7, 14, 2, rt: 0) == "dc cisw, x0")
    }

    @Test func atFamily() {
        #expect(sysText(0, 7, 8, 0, rt: 0) == "at s1e1r, x0")
        #expect(sysText(0, 7, 8, 1, rt: 0) == "at s1e1w, x0")
        #expect(sysText(0, 7, 8, 2, rt: 0) == "at s1e0r, x0")
        #expect(sysText(0, 7, 8, 3, rt: 0) == "at s1e0w, x0")
    }

    @Test func tlbiFamily() {
        let expected: [(UInt8, UInt8, UInt8, UInt8, String, Bool)] = [
            (0, 8, 3, 0, "tlbi vmalle1is", false),
            (0, 8, 3, 1, "tlbi vae1is", true),
            (0, 8, 7, 0, "tlbi vmalle1", false),
            (0, 8, 7, 1, "tlbi vae1", true),
            (0, 8, 3, 2, "tlbi aside1is", true),
            (0, 8, 7, 2, "tlbi aside1", true),
            (4, 8, 3, 4, "tlbi alle1is", false),
            (4, 8, 7, 4, "tlbi alle1", false),
            (0, 8, 3, 5, "tlbi vale1is", true),
            (0, 8, 7, 5, "tlbi vale1", true),
        ]
        for (op1, CRn, CRm, op2, name, needsReg) in expected {
            if needsReg {
                #expect(sysText(op1, CRn, CRm, op2, rt: 0) == "\(name), x0")
                #expect(sysText(op1, CRn, CRm, op2, rt: 31) == "\(name), xzr")
            } else {
                #expect(sysText(op1, CRn, CRm, op2, rt: 31) == name)
                #expect(sysText(op1, CRn, CRm, op2, rt: 0) == "sys #\(op1), c\(CRn), c\(CRm), #\(op2), x0")
            }
        }
    }

    @Test func unknownEncodingRendersGenericForm() {
        // Random unknown tuple → the generic sys tuple form at every Rt.
        #expect(sysText(5, 2, 3, 7, rt: 31) == "sys #5, c2, c3, #7")
        #expect(sysText(5, 2, 3, 7, rt: 0) == "sys #5, c2, c3, #7, x0")
    }
}
