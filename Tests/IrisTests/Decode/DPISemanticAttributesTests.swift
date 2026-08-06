// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisValidation
import Testing

/// Validates the DPI semantic checker.
@Suite("DPI / Semantic attribute checker")
struct DPISemanticAttributesTests {
    @Test func everyDPIRecordPassesSemanticCheck() {
        let cases: [UInt32] = [
            0x9100_0420,
            0xB100_0420,
            0xD100_0420,
            0xF100_0420,
            0xF100_043F,
            0xB100_043F,
            0x9100_03E0,
            0x5282_8020,
            0x9240_0020,
            0xB240_0020,
            0xD240_0020,
            0xF240_0020,
            0xF240_003F,
            0x92A0_0000,
            0xD2A0_0000,
            0xF280_0020,
            0x1000_0000,
            0x9000_0000,
            0x93C2_1420,
            0x93C1_1420,
            0x9340_1C20,
            0x9340_3C20,
            0x9340_7C20,
            0x5300_1C20,
            0x5300_3C20,
            0x9345_FC20,
            0xD345_FC20,
            0xD37B_E820,
            0x937B_0C20,
            0x9345_2020,
            0x531B_0C20,
            0x5305_2020,
            0xB37B_0C20,
            0xB345_2020,
            0xB37B_0FE0,
            0xB340_FC20,
        ]
        for word in cases {
            let d = decode(word)
            #expect(d.category == .dataProcessingImmediate, "0x\(String(word, radix: 16))")
            let issue = DPISemanticChecker.verify(d)
            #expect(issue == nil, "0x\(String(word, radix: 16)) (\(d.mnemonic.name)): \(String(describing: issue))")
        }
    }

    @Test func reservedBitfieldWordsDecodeUndefinedNotDPI() {
        for word: UInt32 in [0x933B_0C20, 0x9305_2020] {
            let d = decode(word)
            #expect(d.isUndefined, "0x\(String(word, radix: 16))")
            #expect(d.category != .dataProcessingImmediate)
        }
    }

    @Test func undefinedAndDelegatedRecordsAreSkipped() {
        let undef = Instruction(mnemonic: .undefined, category: .dataProcessingImmediate)
        #expect(DPISemanticChecker.verify(undef) == nil)
        let addg = decode(0x9180_0020)
        #expect(addg.mnemonic == .addg)
        #expect(DPISemanticChecker.verify(addg) == nil)
    }

    @Test func everyFieldMismatchArmReportsItsIssue() {
        let good = decode(0x9100_0420)
        #expect(DPISemanticChecker.verify(mutated(good, branchClass: .call))?.field == "branchClass")
        #expect(DPISemanticChecker.verify(mutated(good, memoryAccess: .load))?.field == "memoryAccess")
        #expect(DPISemanticChecker.verify(mutated(good, memoryOrdering: [.acquire]))?.field == "memoryOrdering")
        #expect(DPISemanticChecker.verify(mutated(good, category: .loadsAndStores))?.field == "category")
        #expect(DPISemanticChecker.verify(mutated(good, flagEffect: .nzcv))?.field == "flagEffect")
        #expect(DPISemanticChecker.verify(mutated(good, semanticReads: .empty))?.field == "semanticReads.missing")
        #expect(DPISemanticChecker.verify(
            mutated(good, semanticReads: RegisterSet.empty.inserting(.x(1)).inserting(.x(9))),
        )?.field == "semanticReads.extraneous")
        #expect(DPISemanticChecker.verify(mutated(good, semanticWrites: .empty))?.field == "semanticWrites")
        let issue = DPISemanticChecker.verify(mutated(good, flagEffect: .nzcv))
        #expect(issue == DPISemanticIssue(field: "flagEffect", actual: "\(FlagEffect.nzcv)", expected: "\(FlagEffect.none)"))
    }

    @Test func readAndWriteTablesReturnNilForForeignMnemonics() {
        let foreign = Instruction(mnemonic: .ldr, category: .dataProcessingImmediate)
        #expect(DPISemanticAttributes.expectedReadMask(for: foreign) == nil)
        #expect(DPISemanticAttributes.expectedWriteMask(for: foreign) == nil)
        #expect(DPISemanticChecker.verify(foreign) == nil)
    }

    @Test func rawBFMAndSBFMRowsAreCoveredViaMaterializedRecords() {
        let bfm = Instruction(
            mnemonic: .bfm, category: .dataProcessingImmediate,
            operands: [.register(.x(0)), .register(.x(1))],
        )
        #expect(DPISemanticAttributes.expectedReadMask(for: bfm)
            == DPIExpectedReads(required: 1 << 1, allowed: 0b11))
        #expect(DPISemanticAttributes.expectedWriteMask(for: bfm) == 1 << 0)
        let sbfm = Instruction(
            mnemonic: .sbfm, category: .dataProcessingImmediate,
            operands: [.register(.x(2)), .register(.x(3))],
        )
        #expect(DPISemanticAttributes.expectedReadMask(for: sbfm)
            == DPIExpectedReads(required: 1 << 3, allowed: 1 << 3))
        let ubfm = Instruction(
            mnemonic: .ubfm, category: .dataProcessingImmediate,
            operands: [.register(.x(4)), .register(.x(5))],
        )
        #expect(DPISemanticAttributes.expectedWriteMask(for: ubfm) == 1 << 4)
    }

    @Test func expectedFlagEffectMarksExactlyTheFlagSetters() {
        for m: Mnemonic in [.adds, .subs, .ands, .cmp, .cmn, .tst] {
            #expect(DPISemanticAttributes.expectedFlagEffect(for: m) == .nzcv)
        }
        for m: Mnemonic in [.add, .sub, .and, .orr, .mov, .movk, .adr, .extr] {
            #expect(DPISemanticAttributes.expectedFlagEffect(for: m) == .none)
        }
    }

    @Test func registerMaskAtHandlesEveryOperandShape() {
        let ops: Instruction.Operands = [
            .register(.x(3)),
            .unsignedImmediate(value: 1, width: 12),
            .register(.xzr()),
        ]
        #expect(DPISemanticAttributes.registerMaskAt(operands: ops, index: 0) == 1 << 3)
        #expect(DPISemanticAttributes.registerMaskAt(operands: ops, index: 1) == 0)
        #expect(DPISemanticAttributes.registerMaskAt(operands: ops, index: 2) == 0)
        #expect(DPISemanticAttributes.registerMaskAt(operands: ops, index: -1) == 0)
        #expect(DPISemanticAttributes.registerMaskAt(operands: ops, index: 3) == 0)
    }
}
