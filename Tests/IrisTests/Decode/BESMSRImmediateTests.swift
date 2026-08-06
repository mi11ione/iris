// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates MSR-immediate: named PSTATE fields, the standalone
/// `.cfinv`/`.xaflag`/`.axflag` trio, and the unrecognized fallback to `.msr`.
@Suite("BES / MSR-immediate decode")
struct BESMSRImmediateTests {
    @Test func cfinv() {
        let d = decode(0xD500_401F, at: 0)
        #expect(d.mnemonic == .cfinv)
        #expect(d.operands.isEmpty)
        #expect(d.category == .branchesExceptionSystem)
        #expect(d.semanticReads.mask == 0)
        #expect(d.semanticWrites.mask == 0)
    }

    @Test func xaflag() {
        let d = decode(0xD500_403F, at: 0)
        #expect(d.mnemonic == .xaflag)
        #expect(d.operands.isEmpty)
    }

    @Test func axflag() {
        let d = decode(0xD500_405F, at: 0)
        #expect(d.mnemonic == .axflag)
    }

    @Test func msrSPSel() {
        let d = decode(0xD500_40BF, at: 0)
        #expect(d.mnemonic == .msrImm)
        #expect(d.operands.count == 2)
        #expect(d.operands[0] == .pstateField(.spSel))
        #expect(d.operands[1] == .unsignedImmediate(value: 0, width: 4))
    }

    @Test func msrSPSelImmNonZero() {
        let d = decode(0xD500_41BF, at: 0)
        #expect(d.operands[1] == .unsignedImmediate(value: 1, width: 4))
    }

    @Test func msrAllRecognizedFields() {
        let cases: [(UInt32, PSTATEField)] = [
            (0xD500_40BF, .spSel),
            (0xD503_40DF, .daifSet),
            (0xD503_40FF, .daifClr),
            (0xD500_407F, .uao),
            (0xD500_409F, .pan),
            (0xD503_405F, .dit),
            (0xD503_409F, .tco),
            (0xD503_403F, .ssbs),
        ]
        for (enc, expected) in cases {
            let d = decode(enc, at: 0)
            #expect(d.mnemonic == .msrImm, "encoding \(String(enc, radix: 16))")
            #expect(d.operands[0] == .pstateField(expected))
        }
    }

    @Test func msrDaifSetImm() {
        for (enc, imm): (UInt32, UInt64) in [
            (0xD503_40DF, 0), (0xD503_41DF, 1), (0xD503_47DF, 7), (0xD503_4FDF, 15),
        ] {
            let d = decode(enc, at: 0)
            #expect(d.mnemonic == .msrImm)
            #expect(d.operands[1] == .unsignedImmediate(value: imm, width: 4))
        }
    }

    @Test func unknownPstateFieldFallsBackToMsr() {
        let d = decode(0xD502_435F, at: 0)
        #expect(d.mnemonic == .msr)
        #expect(d.operands.count == 2)
        #expect(d.operands[0] == .systemRegister(SystemRegisterEncoding(op0: 0, op1: 2, crn: 4, crm: 3, op2: 2)))
        #expect(d.operands[1] == .register(.xzr()))
    }

    @Test func unknownPstateReadsXzr() {
        let d = decode(0xD502_435F, at: 0)
        #expect(d.semanticReads.contains(.xzr()))
    }
}
