// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the BES family's dispatch behavior through the public
/// surface: op0 routing into the family and the bits-31:24 sub-dispatch.
/// Hits every bits 31:24 value the dispatch table maps to a
/// sub-decoder, plus unallocated values rejected via .undefined.
@Suite("BES / BranchesExceptionSystemDecoder dispatch")
struct BESDispatcherTests {
    @Test func bothBESOp0PartitionsAttributeToTheFamily() {
        // op0=0xA (B) and op0=0xB (B with imm26 bit 25 set).
        #expect(decode(0x1400_0000).category == .branchesExceptionSystem)
        #expect(decode(0x1600_0000).category == .branchesExceptionSystem)
    }

    @Test func dispatchRoutesB() {
        let d = decode(0x1400_0000, at: 0)
        #expect(d.mnemonic == .b)
    }

    @Test func dispatchRoutesBL() {
        let d = decode(0x9400_0000, at: 0)
        #expect(d.mnemonic == .bl)
    }

    @Test func dispatchRoutesBcond() {
        let d = decode(0x5400_0000, at: 0)
        #expect(d.mnemonic == .bCond)
    }

    @Test func dispatchRoutesCBZ32() {
        let d = decode(0x3400_0000, at: 0)
        #expect(d.mnemonic == .cbz)
    }

    @Test func dispatchRoutesCBZ64() {
        let d = decode(0xB400_0000, at: 0)
        #expect(d.mnemonic == .cbz)
    }

    @Test func dispatchRoutesCBNZ32() {
        let d = decode(0x3500_0000, at: 0)
        #expect(d.mnemonic == .cbnz)
    }

    @Test func dispatchRoutesCBNZ64() {
        let d = decode(0xB500_0000, at: 0)
        #expect(d.mnemonic == .cbnz)
    }

    @Test func dispatchRoutesTBZ32() {
        let d = decode(0x3600_0000, at: 0)
        #expect(d.mnemonic == .tbz)
    }

    @Test func dispatchRoutesTBZ64() {
        let d = decode(0xB600_0000, at: 0)
        #expect(d.mnemonic == .tbz)
    }

    @Test func dispatchRoutesTBNZ32() {
        let d = decode(0x3700_0000, at: 0)
        #expect(d.mnemonic == .tbnz)
    }

    @Test func dispatchRoutesTBNZ64() {
        let d = decode(0xB700_0000, at: 0)
        #expect(d.mnemonic == .tbnz)
    }

    @Test func dispatchRoutesException() {
        let d = decode(0xD400_0001, at: 0)
        #expect(d.mnemonic == .svc)
    }

    @Test func dispatchRoutesSystem() {
        let d = decode(0xD503_201F, at: 0)
        #expect(d.mnemonic == .nop)
    }

    @Test func dispatchRoutesBranchRegRegular() {
        let d = decode(0xD65F_03C0, at: 0)
        #expect(d.mnemonic == .ret)
    }

    @Test func dispatchRoutesBranchRegAuth() {
        let d = decode(0xD71F_0A11, at: 0)
        #expect(d.mnemonic == .braa)
    }

    @Test func defensiveFallthroughOnInvalidBits31to24() {
        // The dispatcher guarantees op0 ∈ {0xA, 0xB} but as a defensive
        // path BranchesExceptionSystemDecoder still handles unmatched
        // bits 31:24 — emit .undefined rather than crash. The only
        // bits 31:24 values reachable here (given op0 ∈ {0xA, 0xB})
        // that match no BES class: e.g. 0x55..0x57 — bits 28:25
        // = 1010 / 1011, but bits 31:24 like 0x55 satisfy op0 yet not
        // any sub-case. Encoding 0x55000000 has op0 = 0xA and bits
        // 31:24 = 0x55 which doesn't match any known mnemonic-class
        // (bit 4 may be 0/1, bits 23:0 don't matter — the dispatch
        // falls through to .undefined).
        let d = decode(0x5500_0000, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func tierZeroDecodeReachesBES() {
        // The same dispatch path the stream init uses, via tier-0.
        let b = decode(0x1400_0000, at: 0) // op0 = 0xA (B)
        #expect(b.mnemonic == .b)
        #expect(b.category == .branchesExceptionSystem)
        let svc = decode(0xD400_0001, at: 0)
        #expect(svc.mnemonic == .svc)
    }
}
