// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates barrier decode (CRmSystemI sub-tier).
/// op2 routes the family (CLREX/DSB/DMB/
/// ISB/SB/DSBnXS); CRm parameterizes. CLREX and ISB elide operand when
/// CRm == 0xF; DSB with CRm = 0 / 4 emits `.ssbb` / `.pssbb`; nXS DSB
/// only at CRm ∈ {2, 6, 10, 14}; SB requires CRm == 0.
@Suite("BES / Barrier decode")
struct BESBarrierTests {
    @Test func clrexCRmAllOnesNoOperand() {
        // 0xD5033F5F = CLREX (CRm = 0xF, op2 = 010)
        let d = decode(0xD503_3F5F, at: 0)
        #expect(d.mnemonic == .clrex)
        #expect(d.operands.isEmpty)
        #expect(d.semanticReads.mask == 0)
        #expect(d.semanticWrites.mask == 0)
    }

    @Test func clrexCRmNonCanonicalCarriesOperand() {
        // 0xD503305F = CLREX #0 (CRm = 0)
        let d = decode(0xD503_305F, at: 0)
        #expect(d.mnemonic == .clrex)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 0, width: 4)])
    }

    @Test func clrexCRmAtCanonicalAndOtherValues() {
        // Exercise every CRm so the canonical-vs-other-value branch is covered.
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
        // 0xD5033F9F = DSB SY (op2 = 100, CRm = 1111)
        let d = decode(0xD503_3F9F, at: 0)
        #expect(d.mnemonic == .dsb)
        #expect(Array(d.operands) == [.barrierOption(.sy)])
    }

    @Test func dsbISH() {
        // CRm = 1011 (ISH = 0xB) → 0xD5033B9F
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
        // CRm = 0x8 → reserved per BarrierOption.init?(rawOptionBits:)
        // 0xD503389F → operand is raw immediate
        let d = decode(0xD503_389F, at: 0)
        #expect(d.mnemonic == .dsb)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 8, width: 4)])
    }

    @Test func dsbReservedCRm12GivesGenericImmediate() {
        // CRm = 0xC → reserved
        let d = decode(0xD503_3C9F, at: 0)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 12, width: 4)])
    }

    @Test func dsbCRm0IsSSBB() {
        // 0xD503309F = SSBB (special-case DSB with CRm = 0)
        let d = decode(0xD503_309F, at: 0)
        #expect(d.mnemonic == .ssbb)
        #expect(d.operands.isEmpty)
    }

    @Test func dsbCRm4IsPSSBB() {
        // 0xD503349F = PSSBB (CRm = 4)
        let d = decode(0xD503_349F, at: 0)
        #expect(d.mnemonic == .pssbb)
    }

    @Test func dmbSY() {
        // 0xD5033FBF = DMB SY (op2 = 101)
        let d = decode(0xD503_3FBF, at: 0)
        #expect(d.mnemonic == .dmb)
        #expect(Array(d.operands) == [.barrierOption(.sy)])
    }

    @Test func dmbReservedCRmGivesGenericImmediate() {
        // CRm = 0x4 → reserved (no PSSBB equivalent for DMB)
        let d = decode(0xD503_34BF, at: 0)
        #expect(d.mnemonic == .dmb)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 4, width: 4)])
    }

    @Test func isbSyNoOperand() {
        // 0xD5033FDF = ISB (CRm = 0xF) — bare
        let d = decode(0xD503_3FDF, at: 0)
        #expect(d.mnemonic == .isb)
        #expect(d.operands.isEmpty)
    }

    @Test func isbNonCanonicalCRm() {
        // 0xD50330DF = ISB #0
        let d = decode(0xD503_30DF, at: 0)
        #expect(d.mnemonic == .isb)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 0, width: 4)])
    }

    @Test func sbCRmZero() {
        // 0xD50330FF = SB (CRm must be 0, op2 = 111)
        let d = decode(0xD503_30FF, at: 0)
        #expect(d.mnemonic == .sb)
        #expect(d.operands.isEmpty)
    }

    @Test func sbNonZeroCRmDecodesAsSb() {
        // CRm = 1 is "potentially undefined" per the ARM ARM, but llvm-mc
        // decodes it as sb (with that warning) and the decoder accepts
        // potentially-undefined encodings, so sb is emitted.
        let d = decode(0xD503_31FF, at: 0)
        #expect(d.mnemonic == .sb)
    }

    @Test func dsbNxsRecognizedCRmEmitsDsb() {
        // 0xD503323F = DSB oshnxs (CRm = 2 with op2 = 001)
        let d = decode(0xD503_323F, at: 0)
        #expect(d.mnemonic == .dsb)
        // Operand carries CRm | 0x10 as 5-bit immediate (canonicalizer
        // renders "oshnxs"/"nshnxs"/...).
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
        // 0xD503383F is not a DSB-nXS at all: at the maximal mattr llvm-mc
        // decodes it as `msr S0_3_C3_C8_1, xzr` (CRn=3 op2=001 CRm=8 is the
        // MSR system-register space), and the decoder agrees.
        let d = decode(0xD503_383F, at: 0)
        #expect(d.mnemonic == .msr)
    }

    @Test func barrierReservedOp2ZeroIsMsr() {
        // op2 = 000 in CRn=3 is not a barrier; it's an op0 == 0 MSR
        // (the oracle renders `msr S0_3_C3_C0_0, xzr`).
        let d = decode(0xD503_301F, at: 0)
        #expect(d.mnemonic == .msr)
    }

    @Test func barrierReservedOp2ThreeIsMsr() {
        // op2 = 011 is not a barrier; an op0 == 0 MSR.
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
