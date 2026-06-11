// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates MSR-immediate decode: named
/// PSTATE fields emit `.msrImm` with `(.pstateField, .unsignedImmediate)`
/// operand pair; the standalone trio (op1=000, op2=000/001/010, CRm=0)
/// emit `.cfinv` / `.xaflag` / `.axflag` with no operand; unrecognized
/// (op1, op2) falls back to `.msr` with synthesized op0=0 sysreg + xzr
/// (matching llvm-mc).
@Suite("BES / MSR-immediate decode")
struct BESMSRImmediateTests {
    @Test func cfinv() {
        // 0xD500401F = CFINV (op1=000, CRm=0, op2=000)
        let d = decode(0xD500_401F, at: 0)
        #expect(d.mnemonic == .cfinv)
        #expect(d.operands.isEmpty)
        #expect(d.category == .branchesExceptionSystem)
        #expect(d.semanticReads.mask == 0)
        #expect(d.semanticWrites.mask == 0)
    }

    @Test func xaflag() {
        // 0xD500403F = XAFLAG (op1=000, CRm=0, op2=001)
        let d = decode(0xD500_403F, at: 0)
        #expect(d.mnemonic == .xaflag)
        #expect(d.operands.isEmpty)
    }

    @Test func axflag() {
        // 0xD500405F = AXFLAG (op1=000, CRm=0, op2=010)
        let d = decode(0xD500_405F, at: 0)
        #expect(d.mnemonic == .axflag)
    }

    @Test func msrSPSel() {
        // 0xD50040BF = MSR SPSel, #0 (op1=000, CRm=0, op2=101)
        let d = decode(0xD500_40BF, at: 0)
        #expect(d.mnemonic == .msrImm)
        #expect(d.operands.count == 2)
        #expect(d.operands[0] == .pstateField(.spSel))
        #expect(d.operands[1] == .unsignedImmediate(value: 0, width: 4))
    }

    @Test func msrSPSelImmNonZero() {
        // 0xD50041BF = MSR SPSel, #1
        let d = decode(0xD500_41BF, at: 0)
        #expect(d.operands[1] == .unsignedImmediate(value: 1, width: 4))
    }

    @Test func msrAllRecognizedFields() {
        // Cover every named PSTATE field item 10 + decoder.
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
        // 0xD50341DF = MSR DAIFSet, #1
        // 0xD50347DF = MSR DAIFSet, #7
        // 0xD5034FDF = MSR DAIFSet, #15
        for (enc, imm): (UInt32, UInt64) in [
            (0xD503_40DF, 0), (0xD503_41DF, 1), (0xD503_47DF, 7), (0xD503_4FDF, 15),
        ] {
            let d = decode(enc, at: 0)
            #expect(d.mnemonic == .msrImm)
            #expect(d.operands[1] == .unsignedImmediate(value: imm, width: 4))
        }
    }

    @Test func unknownPstateFieldFallsBackToMsr() {
        // (op1=010, op2=010) — not in the recognized PSTATE table.
        // Encoding: bits 31:22 = 1101010100, bit 21 = 0, bits 20:19 = 00,
        // bits 18:16 = 010, bits 15:12 = 0100, bits 11:8 = CRm, bits 7:5 = 010, bits 4:0 = 11111
        // For CRm = 3, encoding = 0xD502435F
        let d = decode(0xD502_435F, at: 0)
        #expect(d.mnemonic == .msr)
        #expect(d.operands.count == 2)
        #expect(d.operands[0] == .systemRegister(SystemRegisterEncoding(op0: 0, op1: 2, crn: 4, crm: 3, op2: 2)))
        #expect(d.operands[1] == .register(.xzr()))
    }

    @Test func unknownPstateReadsXzr() {
        // Fallback MSR semantics: reads Rt (XZR).
        let d = decode(0xD502_435F, at: 0)
        #expect(d.semanticReads.contains(.xzr()))
    }
}
