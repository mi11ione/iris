// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates barrier decode.
@Suite("BES / Barrier decode")
struct BESBarrierTests {
    @Test func clrexCRmAllOnesNoOperand() {
        let d = decode(0xD503_3F5F, at: 0)
        #expect(d.mnemonic == .clrex)
        #expect(d.operands.isEmpty)
        #expect(d.semanticReads.mask == 0)
        #expect(d.semanticWrites.mask == 0)
    }

    @Test func clrexCRmNonCanonicalCarriesOperand() {
        let d = decode(0xD503_305F, at: 0)
        #expect(d.mnemonic == .clrex)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 0, width: 4)])
    }

    @Test func clrexCRmAtCanonicalAndOtherValues() {
        for crm: UInt8 in 0 ..< 16 {
            let enc = UInt32(0xD503_305F) | (UInt32(crm) << 8)
            let d = decode(enc, at: 0)
            #expect(d.mnemonic == .clrex)
            if crm == 0xF {
                #expect(d.operands.isEmpty)
            } else {
                #expect(d.operands.count == 1)
            }
        }
    }

    @Test func dsbSY() {
        let d = decode(0xD503_3F9F, at: 0)
        #expect(d.mnemonic == .dsb)
        #expect(Array(d.operands) == [.barrierOption(.sy)])
    }

    @Test func dsbISH() {
        let d = decode(0xD503_3B9F, at: 0)
        #expect(Array(d.operands) == [.barrierOption(.ish)])
    }

    @Test func dsbAllNamedOptions() {
        let cases: [(UInt8, BarrierOption)] = [
            (0x1, .oshld), (0x2, .oshst), (0x3, .osh),
            (0x5, .nshld), (0x6, .nshst), (0x7, .nsh),
            (0x9, .ishld), (0xA, .ishst), (0xB, .ish),
            (0xD, .ld), (0xE, .st), (0xF, .sy),
        ]
        for (crm, option) in cases {
            let enc = UInt32(0xD503_309F) | (UInt32(crm) << 8)
            let d = decode(enc, at: 0)
            #expect(d.mnemonic == .dsb)
            #expect(Array(d.operands) == [.barrierOption(option)])
        }
    }

    @Test func dsbReservedCRm8GivesGenericImmediate() {
        let d = decode(0xD503_389F, at: 0)
        #expect(d.mnemonic == .dsb)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 8, width: 4)])
    }

    @Test func dsbCRm12IsDFB() {
        let d = decode(0xD503_3C9F, at: 0)
        #expect(d.mnemonic == .dfb)
        #expect(d.operands.isEmpty)
    }

    @Test func dsbCRm0IsSSBB() {
        let d = decode(0xD503_309F, at: 0)
        #expect(d.mnemonic == .ssbb)
        #expect(d.operands.isEmpty)
    }

    @Test func dsbCRm4IsPSSBB() {
        let d = decode(0xD503_349F, at: 0)
        #expect(d.mnemonic == .pssbb)
    }

    @Test func dmbSY() {
        let d = decode(0xD503_3FBF, at: 0)
        #expect(d.mnemonic == .dmb)
        #expect(Array(d.operands) == [.barrierOption(.sy)])
    }

    @Test func dmbReservedCRmGivesGenericImmediate() {
        let d = decode(0xD503_34BF, at: 0)
        #expect(d.mnemonic == .dmb)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 4, width: 4)])
    }

    @Test func isbSyNoOperand() {
        let d = decode(0xD503_3FDF, at: 0)
        #expect(d.mnemonic == .isb)
        #expect(d.operands.isEmpty)
    }

    @Test func isbNonCanonicalCRm() {
        let d = decode(0xD503_30DF, at: 0)
        #expect(d.mnemonic == .isb)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 0, width: 4)])
    }

    @Test func sbCRmZero() {
        let d = decode(0xD503_30FF, at: 0)
        #expect(d.mnemonic == .sb)
        #expect(d.operands.isEmpty)
    }

    @Test func sbNonZeroCRmDecodesAsSb() {
        let d = decode(0xD503_31FF, at: 0)
        #expect(d.mnemonic == .sb)
    }

    @Test func dsbNxsRecognizedCRmEmitsDsb() {
        let d = decode(0xD503_323F, at: 0)
        #expect(d.mnemonic == .dsb)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 0x12, width: 5)])
    }

    @Test func dsbNxsAllFourCRm() {
        for (crm, expectedImm): (UInt8, UInt64) in [(2, 0x12), (6, 0x16), (10, 0x1A), (14, 0x1E)] {
            let enc = UInt32(0xD503_303F) | (UInt32(crm) << 8)
            let d = decode(enc, at: 0)
            #expect(d.mnemonic == .dsb)
            #expect(Array(d.operands) == [.unsignedImmediate(value: expectedImm, width: 5)])
        }
    }

    @Test func dsbNxsCRm8DecodesAsMsr() {
        let d = decode(0xD503_383F, at: 0)
        #expect(d.mnemonic == .msr)
    }

    @Test func barrierReservedOp2ZeroIsMsr() {
        let d = decode(0xD503_301F, at: 0)
        #expect(d.mnemonic == .msr)
    }

    @Test func barrierReservedOp2ThreeIsMsr() {
        let d = decode(0xD503_307F, at: 0)
        #expect(d.mnemonic == .msr)
    }

    @Test func universalFields() {
        let d = decode(0xD503_3F9F, at: 0)
        #expect(d.memoryAccess == .none)
        #expect(d.memoryOrdering == [])
        #expect(d.flagEffect == .none)
        #expect(d.category == .branchesExceptionSystem)
    }
}
