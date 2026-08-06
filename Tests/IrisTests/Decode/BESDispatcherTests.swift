// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates BES dispatch through the public surface.
@Suite("BES / BranchesExceptionSystemDecoder dispatch")
struct BESDispatcherTests {
    @Test func bothBESOp0PartitionsAttributeToTheFamily() {
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

    @Test func dispatchRoutesPACReturnImmediate() {
        let d = decode(0x5500_001F, at: 0)
        #expect(d.mnemonic == .retaasppc)
    }

    @Test func defensiveFallthroughOnInvalidBits31to24() {
        for word: UInt32 in [0x5600_0000, 0x5700_0000, 0x7600_0000, 0x7700_0000,
                             0xF600_0000, 0xF700_0000]
        {
            #expect(decode(word, at: 0).mnemonic == .undefined, "0x\(String(word, radix: 16))")
        }
    }

    @Test func tierZeroDecodeReachesBES() {
        let b = decode(0x1400_0000, at: 0)
        #expect(b.mnemonic == .b)
        #expect(b.category == .branchesExceptionSystem)
        let svc = decode(0xD400_0001, at: 0)
        #expect(svc.mnemonic == .svc)
    }
}
