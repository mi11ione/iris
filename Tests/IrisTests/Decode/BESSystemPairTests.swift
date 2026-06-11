// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the FEAT_D128 128-bit system forms — SYSP (with and without
/// a TLBIP alias, including the xzr pair and the odd-Rt rejection) and
/// MSRR / MRRS (pair reads/writes, generic sysreg naming, odd-Rt
/// rejection) — plus the SME / NMI / SEBEP MSR-immediate forms
/// (SMSTART/SMSTOP with sm/za/both targets, ALLINT, PM).
@Suite("BES / 128-bit system pairs and SME PSTATE forms")
struct BESSystemPairTests {
    /// SYSP word: bits 23:22 = 01, L = 0, op0 = 01.
    private func syspWord(op1: UInt32, crn: UInt32, crm: UInt32, op2: UInt32, rt: UInt32) -> UInt32 {
        0xD548_0000 | op1 << 16 | crn << 12 | crm << 8 | op2 << 5 | rt
    }

    @Test func syspWithTLBIPAliasRendersThePair() {
        // (op1=0, CRn=8, CRm=1, op2=1) → "tlbip vae1os" (.reg kind).
        let d = decode(syspWord(op1: 0, crn: 8, crm: 1, op2: 1, rt: 4))
        #expect(d.mnemonic == .sysp)
        #expect(d.category == .branchesExceptionSystem)
        #expect(d.semanticReads.contains(.x(4)) && d.semanticReads.contains(.x(5)))
        #expect(d.text == "tlbip vae1os, x4, x5")
    }

    @Test func syspAliasWithRt31RendersXzrPair() {
        // Aliased SYSP always renders the pair, including xzr, xzr.
        let d = decode(syspWord(op1: 0, crn: 8, crm: 1, op2: 1, rt: 31))
        #expect(d.mnemonic == .sysp)
        #expect(d.text == "tlbip vae1os, xzr, xzr")
    }

    @Test func genericSyspRendersKeyTupleAndPair() {
        // (op1=0, CRn=0, CRm=0, op2=0) has no TLBIP alias.
        let d = decode(syspWord(op1: 0, crn: 0, crm: 0, op2: 0, rt: 2))
        #expect(d.mnemonic == .sysp)
        #expect(d.semanticReads.contains(.x(2)) && d.semanticReads.contains(.x(3)))
        #expect(d.text == "sysp #0, c0, c0, #0, x2, x3")
    }

    @Test func genericSyspWithRt31OmitsThePair() {
        let d = decode(syspWord(op1: 0, crn: 0, crm: 0, op2: 0, rt: 31))
        #expect(d.mnemonic == .sysp)
        #expect(d.semanticReads.isEmpty)
        #expect(d.text == "sysp #0, c0, c0, #0")
    }

    @Test func syspWithOddRtIsUndefined() {
        let word = syspWord(op1: 0, crn: 8, crm: 1, op2: 1, rt: 5)
        let d = decode(word)
        #expect(d.isUndefined)
        #expect(d.encoding == word)
    }

    @Test func msrrReadsThePairAndNamesTheSysreg() {
        // MSRR: bits 23:22 = 01, L = 0, op0 = 10 → 0xD550_0000.
        let d = decode(0xD550_0000 | 6) // op1=0 CRn=0 CRm=0 op2=0 Rt=6
        #expect(d.mnemonic == .msrr)
        #expect(d.semanticReads.contains(.x(6)) && d.semanticReads.contains(.x(7)))
        #expect(d.semanticWrites.isEmpty)
        #expect(d.text == "msrr s2_0_c0_c0_0, x6, x7")
    }

    @Test func mrrsWritesThePairAndNamesTheSysreg() {
        // MRRS: bits 23:22 = 01, L = 1, op0 = 10 → 0xD570_0000.
        let d = decode(0xD570_0000 | 6)
        #expect(d.mnemonic == .mrrs)
        #expect(d.semanticWrites.contains(.x(6)) && d.semanticWrites.contains(.x(7)))
        #expect(d.semanticReads.isEmpty)
        #expect(d.text == "mrrs x6, x7, s2_0_c0_c0_0")
    }

    @Test func pairMoveWithOddRtIsUndefined() {
        #expect(decode(0xD550_0000 | 7).isUndefined)
        #expect(decode(0xD570_0000 | 9).isUndefined)
    }

    @Test func d128ReservedBits23_22AreUndefined() {
        // bits 23:22 = 10 / 11 are reserved in the System tier.
        #expect(decode(0xD580_0000).isUndefined)
        #expect(decode(0xD5C0_0000).isUndefined)
    }

    /// MSR-immediate word: op1/CRm/op2 at their System-tier positions,
    /// bits 15:12 = 0100, Rt = 11111.
    private func msrImmWord(op1: UInt32, crm: UInt32, op2: UInt32) -> UInt32 {
        0xD500_401F | op1 << 16 | crm << 8 | op2 << 5
    }

    @Test func smstartSmstopDecodeEveryTargetForm() {
        let rows: [(crm: UInt32, mnemonic: Mnemonic, text: String)] = [
            (0b010, .smstop, "smstop sm"),
            (0b011, .smstart, "smstart sm"),
            (0b100, .smstop, "smstop za"),
            (0b101, .smstart, "smstart za"),
            (0b110, .smstop, "smstop"),
            (0b111, .smstart, "smstart"),
        ]
        for row in rows {
            let d = decode(msrImmWord(op1: 0b011, crm: row.crm, op2: 0b011))
            #expect(d.mnemonic == row.mnemonic)
            #expect(d.category == .branchesExceptionSystem)
            #expect(d.text == row.text)
        }
    }

    @Test func allintAndPmDecodeAsMsrImmediate() {
        let allint0 = decode(msrImmWord(op1: 0b001, crm: 0b000, op2: 0b000))
        #expect(allint0.mnemonic == .msrImm)
        #expect(Array(allint0.operands) == [
            .pstateField(.allInt), .unsignedImmediate(value: 0, width: 4),
        ])
        let allint1 = decode(msrImmWord(op1: 0b001, crm: 0b001, op2: 0b000))
        #expect(Array(allint1.operands) == [
            .pstateField(.allInt), .unsignedImmediate(value: 1, width: 4),
        ])
        let pm0 = decode(msrImmWord(op1: 0b001, crm: 0b010, op2: 0b000))
        #expect(Array(pm0.operands) == [
            .pstateField(.pm), .unsignedImmediate(value: 0, width: 4),
        ])
        let pm1 = decode(msrImmWord(op1: 0b001, crm: 0b011, op2: 0b000))
        #expect(pm1.mnemonic == .msrImm)
        #expect(Array(pm1.operands) == [
            .pstateField(.pm), .unsignedImmediate(value: 1, width: 4),
        ])
        // PSTATE-field names render in the MSR-immediate text.
        #expect(pm1.text == "msr pm, #1")
        #expect(allint1.text == "msr allint, #1")
    }
}
