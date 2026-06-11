// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

@_spi(Validation) import Iris
import Testing

/// Validates the DPI semantic-attribute checker: every decoded DPI
/// mnemonic class passes `DPISemanticChecker.verify(_:)`, every
/// field-mismatch arm reports its exact issue, and the
/// `expectedFlagEffect` / `expectedReadMask` / `expectedWriteMask` /
/// `registerMaskAt` tables cover their full per-mnemonic case lists.
@Suite("DPI / Semantic attribute checker")
struct DPISemanticAttributesTests {
    @Test func everyDPIRecordPassesSemanticCheck() {
        let cases: [UInt32] = [
            0x9100_0420, // add x0, x1, #1
            0xB100_0420, // adds
            0xD100_0420, // sub
            0xF100_0420, // subs
            0xF100_043F, // cmp alias
            0xB100_043F, // cmn alias
            0x9100_03E0, // mov x0, sp
            0x5282_8020, // mov w0, #5121 (movz alias)
            0x9240_0020, // and x0, x1, #1
            0xB240_0020, // orr
            0xD240_0020, // eor
            0xF240_0020, // ands
            0xF240_003F, // tst alias
            0x92A0_0000, // movn x0, #0, lsl #16
            0xD2A0_0000, // movz x0, #0, lsl #16
            0xF280_0020, // movk x0, #1
            0x1000_0000, // adr x0, #0
            0x9000_0000, // adrp x0, #0
            0x93C2_1420, // extr x0, x1, x2, #5
            0x93C1_1420, // ror alias (Rn == Rm)
            0x9340_1C20, // sxtb x0, w1
            0x9340_3C20, // sxth
            0x9340_7C20, // sxtw
            0x5300_1C20, // uxtb w0, w1
            0x5300_3C20, // uxth
            0x9345_FC20, // asr x0, x1, #5
            0xD345_FC20, // lsr x0, x1, #5
            0xD37B_E820, // lsl x0, x1, #5
            0x937B_0C20, // sbfiz x0, x1, #5, #4
            0x9345_2020, // sbfx x0, x1, #5, #4
            0x531B_0C20, // ubfiz w0, w1, #5, #4
            0x5305_2020, // ubfx w0, w1, #5, #4
            0xB37B_0C20, // bfi x0, x1, #5, #4
            0xB345_2020, // bfxil x0, x1, #5, #4
            0xB37B_0FE0, // bfc x0, #5, #4
            0xB340_FC20, // bfxil x0, x1, #0, #64 (full-width BFM)
        ]
        for word in cases {
            let d = decode(word)
            #expect(d.category == .dataProcessingImmediate, "0x\(String(word, radix: 16))")
            let issue = DPISemanticChecker.verify(d)
            #expect(issue == nil, "0x\(String(word, radix: 16)) (\(d.mnemonic.name)): \(String(describing: issue))")
        }
    }

    @Test func reservedBitfieldWordsDecodeUndefinedNotDPI() {
        // sf=1 with N=0 is reserved in the SBFM space (ARM ARM: bitfield
        // requires N == sf); llvm-mc 22.1.4 rejects both words as
        // "invalid instruction encoding".
        for word: UInt32 in [0x933B_0C20, 0x9305_2020] {
            let d = decode(word)
            #expect(d.isUndefined, "0x\(String(word, radix: 16))")
            #expect(d.category != .dataProcessingImmediate)
        }
    }

    @Test func undefinedAndDelegatedRecordsAreSkipped() {
        // UNDEFINED short-circuits to nil.
        let undef = Instruction(mnemonic: .undefined, category: .dataProcessingImmediate)
        #expect(DPISemanticChecker.verify(undef) == nil)
        // MTE ADDG flows through the DPI decoder but is verified by the
        // crypto/Apple-extensions checker — DPI's returns nil.
        let addg = decode(0x9180_0020)
        #expect(addg.mnemonic == .addg)
        #expect(DPISemanticChecker.verify(addg) == nil)
    }

    @Test func everyFieldMismatchArmReportsItsIssue() {
        let good = decode(0x9100_0420) // add x0, x1, #1
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
        // The issue value carries the field/actual/expected triple.
        let issue = DPISemanticChecker.verify(mutated(good, flagEffect: .nzcv))
        #expect(issue == DPISemanticIssue(field: "flagEffect", actual: "\(FlagEffect.nzcv)", expected: "\(FlagEffect.none)"))
    }

    @Test func readAndWriteTablesReturnNilForForeignMnemonics() {
        let foreign = Instruction(mnemonic: .ldr, category: .dataProcessingImmediate)
        #expect(DPISemanticAttributes.expectedReadMask(for: foreign) == nil)
        #expect(DPISemanticAttributes.expectedWriteMask(for: foreign) == nil)
        // verify passes a record whose masks have no expectation rows.
        #expect(DPISemanticChecker.verify(foreign) == nil)
    }

    @Test func rawBFMAndSBFMRowsAreCoveredViaMaterializedRecords() {
        // The raw BFM/SBFM/UBFM mnemonics only surface via aliases from
        // decode; the table rows still answer for hand-built records.
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
        let ops: [Operand] = [
            .register(.x(3)),
            .unsignedImmediate(value: 1, width: 12),
            .register(.xzr()),
        ]
        #expect(DPISemanticAttributes.registerMaskAt(operands: ops, index: 0) == 1 << 3)
        #expect(DPISemanticAttributes.registerMaskAt(operands: ops, index: 1) == 0) // not a register
        #expect(DPISemanticAttributes.registerMaskAt(operands: ops, index: 2) == 0) // zero register
        #expect(DPISemanticAttributes.registerMaskAt(operands: ops, index: -1) == 0)
        #expect(DPISemanticAttributes.registerMaskAt(operands: ops, index: 3) == 0) // out of range
    }
}
