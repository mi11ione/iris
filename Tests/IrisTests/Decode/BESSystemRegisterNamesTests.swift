// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Pins one representative of each system-register family the name table
/// gained, in both directions, so the read-only / write-only asymmetry and the
/// shared MRRS / MSRR rendering stay honest.
@Suite("BES / System register names — new families and access directions")
struct BESSystemRegisterNamesTests {
    private func move(L: UInt32, op0: UInt32, op1: UInt32, crn: UInt32, crm: UInt32, op2: UInt32) -> String {
        let word: UInt32 = 0xD500_0000 | L << 21 | op0 << 19 | op1 << 16
            | crn << 12 | crm << 8 | op2 << 5 | 2
        return decode(word).text
    }

    private func pair(L: UInt32, op0: UInt32, op1: UInt32, crn: UInt32, crm: UInt32, op2: UInt32) -> String {
        let word: UInt32 = 0xD540_0000 | L << 21 | op0 << 19 | op1 << 16
            | crn << 12 | crm << 8 | op2 << 5 | 2
        return decode(word).text
    }

    @Test func readOnlyFamiliesNameOnlyTheReadDirection() {
        #expect(move(L: 1, op0: 2, op1: 1, crn: 8, crm: 0, op2: 0) == "mrs x2, brbinf0_el1")
        #expect(move(L: 0, op0: 2, op1: 1, crn: 8, crm: 0, op2: 0) == "msr s2_1_c8_c0_0, x2")
        #expect(move(L: 1, op0: 2, op1: 1, crn: 8, crm: 0, op2: 1) == "mrs x2, brbsrc0_el1")
        #expect(move(L: 1, op0: 3, op1: 4, crn: 10, crm: 8, op2: 7) == "mrs x2, mecidr_el2")
        #expect(move(L: 0, op0: 3, op1: 4, crn: 10, crm: 8, op2: 7) == "msr s3_4_c10_c8_7, x2")
        #expect(move(L: 1, op0: 3, op1: 3, crn: 2, crm: 4, op2: 0) == "mrs x2, rndr")
        #expect(move(L: 0, op0: 3, op1: 3, crn: 2, crm: 4, op2: 0) == "msr s3_3_c2_c4_0, x2")
        #expect(move(L: 1, op0: 3, op1: 1, crn: 0, crm: 0, op2: 2) == "mrs x2, ccsidr2_el1")
    }

    @Test func readWriteFamiliesNameBothDirections() {
        #expect(move(L: 1, op0: 2, op1: 1, crn: 9, crm: 0, op2: 0) == "mrs x2, brbcr_el1")
        #expect(move(L: 0, op0: 2, op1: 1, crn: 9, crm: 0, op2: 0) == "msr brbcr_el1, x2")
        #expect(move(L: 0, op0: 3, op1: 0, crn: 0, crm: 0, op2: 4) == "msr mpuir_el1, x2")
        #expect(move(L: 0, op0: 3, op1: 0, crn: 6, crm: 8, op2: 0) == "msr prbar_el1, x2")
        #expect(move(L: 1, op0: 3, op1: 0, crn: 6, crm: 15, op2: 5) == "mrs x2, prlar15_el1")
        #expect(move(L: 0, op0: 3, op1: 4, crn: 10, crm: 9, op2: 1) == "msr vmecid_a_el2, x2")
        #expect(move(L: 0, op0: 3, op1: 6, crn: 2, crm: 1, op2: 4) == "msr gptbr_el3, x2")
        #expect(move(L: 0, op0: 3, op1: 6, crn: 10, crm: 10, op2: 1) == "msr mecid_rl_a_el3, x2")
        #expect(move(L: 0, op0: 3, op1: 0, crn: 13, crm: 0, op2: 5) == "msr accdata_el1, x2")
        #expect(move(L: 0, op0: 3, op1: 0, crn: 9, crm: 9, op2: 1) == "msr pmsnevfr_el1, x2")
    }

    @Test func the128BitMovesShareTheSameNameTable() {
        #expect(pair(L: 1, op0: 2, op1: 1, crn: 8, crm: 0, op2: 0) == "mrrs x2, x3, brbinf0_el1")
        #expect(pair(L: 0, op0: 2, op1: 1, crn: 8, crm: 0, op2: 0) == "msrr s2_1_c8_c0_0, x2, x3")
        #expect(pair(L: 0, op0: 3, op1: 6, crn: 2, crm: 1, op2: 4) == "msrr gptbr_el3, x2, x3")
    }
}
