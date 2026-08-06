// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisValidation
import Testing

/// Validates the per-mnemonic attribute tables and
/// `DPRSemanticChecker.verify(draft:)`, covering every expected-mask branch.
@Suite("DPR / Semantic attribute checker")
struct DPRSemanticAttributesTests {
    @Test func everyDPRRecordPassesSemanticCheck() {
        let cases: [UInt32] = [
            0x8B02_0020,
            0xAB02_0020,
            0xCB02_0020,
            0xEB02_0020,
            0xAB02_003F,
            0xEB02_003F,
            0xCB01_03E0,
            0xEB01_03E0,
            0x8B22_6020,
            0xEB21_63FF,
            0x8A02_0020,
            0xAA02_0020,
            0xCA02_0020,
            0xEA02_0020,
            0x8A22_0020,
            0xAA22_0020,
            0xCA22_0020,
            0xEA22_0020,
            0xAA02_03E0,
            0xAA22_03E0,
            0xEA02_003F,
            0x9A02_0020,
            0xBA02_0020,
            0xDA02_0020,
            0xFA02_0020,
            0xDA01_03E0,
            0xFA01_03E0,
            0xFA42_0025,
            0xFA40_0825,
            0xBA42_0025,
            0x9A82_0020,
            0x9A82_0420,
            0xDA82_0020,
            0xDA82_0420,
            0x9A9F_07E0,
            0xDA9F_03E0,
            0x9A81_0420,
            0xDA81_0020,
            0xDA81_0420,
            0x9B02_0C20,
            0x9B02_8C20,
            0x9B22_0C20,
            0x9B22_8C20,
            0x9BA2_0C20,
            0x9BA2_8C20,
            0x9B42_7C20,
            0x9BC2_7C20,
            0x9B02_7C20,
            0x9B02_FC20,
            0x9B22_7C20,
            0x9B22_FC20,
            0x9BA2_7C20,
            0x9BA2_FC20,
            0x9AC2_0820,
            0x9AC2_0C20,
            0x9AC2_2020,
            0x9AC2_2420,
            0x9AC2_2820,
            0x9AC2_2C20,
            0x1AC2_4020,
            0x1AC2_4420,
            0x1AC2_4820,
            0x9AC2_4C20,
            0x1AC2_5020,
            0x1AC2_5420,
            0x1AC2_5820,
            0x9AC2_5C20,
            0xDAC0_0020,
            0xDAC0_0420,
            0xDAC0_0820,
            0xDAC0_0C20,
            0xDAC0_1020,
            0xDAC0_1420,
        ]
        for encoding in cases {
            let d = decode(encoding, at: 0)
            #expect(d.mnemonic != .undefined, "encoding \(String(format: "0x%08x", encoding)) decoded as undefined")
            let issue = DPRSemanticChecker.verify(d)
            #expect(issue == nil, "encoding \(String(format: "0x%08x", encoding)) (\(d.mnemonic.rawValue)) → \(String(describing: issue))")
        }
    }

    @Test func undefinedRecordsSkipChecker() {
        let d = Instruction(address: 0, encoding: 0xDEAD_BEEF, mnemonic: .undefined, category: .undefined)
        #expect(DPRSemanticChecker.verify(d) == nil)
    }

    private func dprDraft(_ m: Mnemonic, operands: [Operand] = []) -> Instruction {
        Instruction(address: 0, encoding: 0, mnemonic: m, category: .dataProcessingRegister, operands: operands)
    }

    @Test func writeOnlyFlagSettersReportNzcv() {
        for m: Mnemonic in [.adds, .subs, .ands, .bics, .cmp, .cmn, .tst, .negs] {
            #expect(DPRSemanticAttributes.expectedFlagEffect(for: dprDraft(m)) == .nzcv, "\(m.rawValue)")
        }
    }

    @Test func carryConsumersReadCarry() {
        for m: Mnemonic in [.adc, .sbc, .ngc] {
            #expect(DPRSemanticAttributes.expectedFlagEffect(for: dprDraft(m)) == .readsC, "\(m.rawValue)")
        }
        for m: Mnemonic in [.adcs, .sbcs, .ngcs] {
            #expect(DPRSemanticAttributes.expectedFlagEffect(for: dprDraft(m)) == [.nzcv, .readsC], "\(m.rawValue)")
        }
    }

    @Test func conditionConsumersReadNzcv() {
        for m: Mnemonic in [.ccmp, .ccmn] {
            #expect(DPRSemanticAttributes.expectedFlagEffect(for: dprDraft(m)) == [.nzcv, .readsNZCV], "\(m.rawValue)")
        }
        for m: Mnemonic in [.csel, .csinc, .csinv, .csneg, .cset, .csetm, .cinc, .cinv, .cneg] {
            #expect(DPRSemanticAttributes.expectedFlagEffect(for: dprDraft(m)) == .readsNZCV, "\(m.rawValue)")
        }
    }

    @Test func setfWritesNzvPreservingCarry() {
        for m: Mnemonic in [.setf8, .setf16] {
            #expect(DPRSemanticAttributes.expectedFlagEffect(for: dprDraft(m)) == [.writesN, .writesZ, .writesV], "\(m.rawValue)")
        }
    }

    @Test func rmifWritesMaskSelectedFlags() {
        func rmif(mask: UInt64) -> Instruction {
            dprDraft(.rmif, operands: [
                .unsignedImmediate(value: 0, width: 6),
                .unsignedImmediate(value: 0, width: 6),
                .unsignedImmediate(value: mask, width: 4),
            ])
        }
        #expect(DPRSemanticAttributes.expectedFlagEffect(for: rmif(mask: 0b1111)) == .nzcv)
        #expect(DPRSemanticAttributes.expectedFlagEffect(for: rmif(mask: 0b1000)) == .writesN)
        #expect(DPRSemanticAttributes.expectedFlagEffect(for: rmif(mask: 0b0010)) == .writesC)
        #expect(DPRSemanticAttributes.expectedFlagEffect(for: rmif(mask: 0b0000)) == .none)
    }

    @Test func nonFlagMnemonicsReportNone() {
        for m: Mnemonic in [.add, .sub, .and, .orr, .mov, .madd, .udiv, .rbit] {
            #expect(DPRSemanticAttributes.expectedFlagEffect(for: dprDraft(m)) == .none)
        }
    }

    @Test func semanticIssueInit() {
        let issue = DPRSemanticIssue(field: "flagEffect", actual: "none", expected: "nzcv")
        #expect(issue.field == "flagEffect")
        #expect(issue.actual == "none")
        #expect(issue.expected == "nzcv")
    }

    @Test func expectedReadsInit() {
        let reads = DPRExpectedReads(required: 0x2, allowed: 0x6)
        #expect(reads.required == 0x2)
        #expect(reads.allowed == 0x6)
    }

    @Test func registerMaskAtPlainRegisterReturnsBit() {
        let ops: Instruction.Operands = [.register(.x(5))]
        let mask = DPRSemanticAttributes.registerMaskAt(operands: ops, index: 0, unwrapShiftExtend: false)
        #expect(mask == (1 << 5))
    }

    @Test func registerMaskAtZeroRegisterReturnsZero() {
        let ops: Instruction.Operands = [.register(.xzr())]
        let mask = DPRSemanticAttributes.registerMaskAt(operands: ops, index: 0, unwrapShiftExtend: false)
        #expect(mask == 0)
    }

    @Test func registerMaskAtIndexOutOfRangeReturnsZero() {
        let ops: Instruction.Operands = [.register(.x(1))]
        let mask = DPRSemanticAttributes.registerMaskAt(operands: ops, index: 5, unwrapShiftExtend: false)
        #expect(mask == 0)
    }

    @Test func registerMaskAtNegativeIndexReturnsZero() {
        let ops: Instruction.Operands = [.register(.x(1))]
        let mask = DPRSemanticAttributes.registerMaskAt(operands: ops, index: -1, unwrapShiftExtend: false)
        #expect(mask == 0)
    }

    @Test func registerMaskAtShiftedRegisterUnwrappedReturnsBit() {
        let ops: Instruction.Operands = [.shiftedRegister(reg: .x(3), shift: .lsl, amount: 1)]
        let mask = DPRSemanticAttributes.registerMaskAt(operands: ops, index: 0, unwrapShiftExtend: true)
        #expect(mask == (1 << 3))
    }

    @Test func registerMaskAtShiftedRegisterNoUnwrapReturnsZero() {
        let ops: Instruction.Operands = [.shiftedRegister(reg: .x(3), shift: .lsl, amount: 1)]
        let mask = DPRSemanticAttributes.registerMaskAt(operands: ops, index: 0, unwrapShiftExtend: false)
        #expect(mask == 0)
    }

    @Test func registerMaskAtExtendedRegisterUnwrappedReturnsBit() {
        let ops: Instruction.Operands = [.extendedRegister(reg: .x(7), extend: .uxtx, shift: 0)]
        let mask = DPRSemanticAttributes.registerMaskAt(operands: ops, index: 0, unwrapShiftExtend: true)
        #expect(mask == (1 << 7))
    }

    @Test func registerMaskAtExtendedRegisterNoUnwrapReturnsZero() {
        let ops: Instruction.Operands = [.extendedRegister(reg: .x(7), extend: .uxtx, shift: 0)]
        let mask = DPRSemanticAttributes.registerMaskAt(operands: ops, index: 0, unwrapShiftExtend: false)
        #expect(mask == 0)
    }

    @Test func registerMaskAtUnsupportedOperandReturnsZero() {
        let ops: Instruction.Operands = [.conditionCode(.eq)]
        let mask = DPRSemanticAttributes.registerMaskAt(operands: ops, index: 0, unwrapShiftExtend: true)
        #expect(mask == 0)
    }

    @Test func expectedReadMaskForUnknownMnemonicIsNil() {
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .b,
            category: .dataProcessingRegister,
        )
        #expect(DPRSemanticAttributes.expectedReadMask(for: draft) == nil)
    }

    @Test func expectedWriteMaskForUnknownMnemonicIsNil() {
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .b,
            category: .dataProcessingRegister,
        )
        #expect(DPRSemanticAttributes.expectedWriteMask(for: draft) == nil)
    }

    @Test func wrongBranchClassReturnsIssue() {
        let d = mutated(decode(0x8B02_0020, at: 0), branchClass: .direct)
        let issue = DPRSemanticChecker.verify(d)
        #expect(issue?.field == "branchClass")
    }

    @Test func wrongMemoryAccessReturnsIssue() {
        let d = mutated(decode(0x8B02_0020, at: 0), memoryAccess: .load)
        let issue = DPRSemanticChecker.verify(d)
        #expect(issue?.field == "memoryAccess")
    }

    @Test func wrongMemoryOrderingReturnsIssue() {
        let d = mutated(decode(0x8B02_0020, at: 0), memoryOrdering: .acquire)
        let issue = DPRSemanticChecker.verify(d)
        #expect(issue?.field == "memoryOrdering")
    }

    @Test func wrongCategoryReturnsIssue() {
        let d = mutated(decode(0x8B02_0020, at: 0), category: .branchesExceptionSystem)
        let issue = DPRSemanticChecker.verify(d)
        #expect(issue?.field == "category")
    }

    @Test func wrongFlagEffectReturnsIssue() {
        let d = mutated(decode(0x8B02_0020, at: 0), flagEffect: .nzcv)
        let issue = DPRSemanticChecker.verify(d)
        #expect(issue?.field == "flagEffect")
    }

    @Test func missingSemanticReadsReturnsIssue() {
        let d = mutated(decode(0x8B02_0020, at: 0), semanticReads: .empty)
        let issue = DPRSemanticChecker.verify(d)
        #expect(issue?.field == "semanticReads.missing")
    }

    @Test func extraneousSemanticReadsReturnsIssue() {
        let base = decode(0x8B02_0020, at: 0)
        let d = mutated(base, semanticReads: base.semanticReads.inserting(.x(10)))
        let issue = DPRSemanticChecker.verify(d)
        #expect(issue?.field == "semanticReads.extraneous")
    }

    @Test func wrongSemanticWritesReturnsIssue() {
        let d = mutated(decode(0x8B02_0020, at: 0), semanticWrites: RegisterSet.empty.inserting(.x(20)))
        let issue = DPRSemanticChecker.verify(d)
        #expect(issue?.field == "semanticWrites")
    }

    @Test func addShiftedSemanticMasksMatchEncoding() {
        let d = decode(0x8B02_0020, at: 0)
        #expect(d.semanticReads.mask == (UInt64(1) << 1) | (UInt64(1) << 2))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func cmpAliasSemanticMasksDropRd() {
        let d = decode(0xEB02_003F, at: 0)
        #expect(d.semanticReads.mask == (UInt64(1) << 1) | (UInt64(1) << 2))
        #expect(d.semanticWrites.mask == 0)
    }

    @Test func tstAliasSemanticMasksDropRd() {
        let d = decode(0xEA02_003F, at: 0)
        #expect(d.semanticReads.mask == (UInt64(1) << 1) | (UInt64(1) << 2))
        #expect(d.semanticWrites.mask == 0)
    }

    @Test func csetAliasSemanticMasksFromRnRmXZR() {
        let d = decode(0x9A9F_07E0, at: 0)
        #expect(d.semanticReads.mask == 0)
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func csetmAliasSemanticMasks() {
        let d = decode(0xDA9F_03E0, at: 0)
        #expect(d.semanticReads.mask == 0)
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func cnegWithXZRSemanticMasksAllowZeroRead() {
        let d = decode(0xDA9F_07E0, at: 0)
        #expect(d.semanticReads.mask == 0)
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func smaddlSemanticMasksThreeSource() {
        let d = decode(0x9B22_0C20, at: 0)
        let expected = (UInt64(1) << 1) | (UInt64(1) << 2) | (UInt64(1) << 3)
        #expect(d.semanticReads.mask == expected)
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func smulhSemanticMasksNoRa() {
        let d = decode(0x9B42_7C20, at: 0)
        #expect(d.semanticReads.mask == (UInt64(1) << 1) | (UInt64(1) << 2))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func crc32xSemanticMasksWithMixedWidths() {
        let d = decode(0x9AC2_4C20, at: 0)
        #expect(d.semanticReads.mask == (UInt64(1) << 1) | (UInt64(1) << 2))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func rmifWithoutItsMaskOperandExpectsFullNZCV() {
        let bare = Instruction(mnemonic: .rmif, category: .dataProcessingRegister)
        #expect(DPRSemanticAttributes.expectedFlagEffect(for: bare) == .nzcv)
        let full = decode(0xBA01_842F, at: 0)
        #expect(DPRSemanticAttributes.expectedFlagEffect(for: full)
            == [.writesN, .writesZ, .writesC, .writesV])
    }
}
