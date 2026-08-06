// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates ADD/SUB-imm and CMP/CMN/MOV-to-SP alias precedence at both
/// register widths and both shift cases.
@Suite("DPI / ADD/SUB-imm decode")
struct DPIAddSubImmTests {
    @Test func baseAdd64Bit() {
        let d = decode(0x9100_0420, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.operands.count == 3)
        #expect(d.flagEffect == .none)
        #expect(d.category == .dataProcessingImmediate)
        #expect(d.semanticReads.contains(.x(1)))
        #expect(d.semanticWrites.contains(.x(0)))
    }

    @Test func baseAdd32Bit() {
        let d = decode(0x1100_0420, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.flagEffect == .none)
    }

    @Test func baseSub64Bit() {
        let d = decode(0xD100_0420, at: 0)
        #expect(d.mnemonic == .sub)
        #expect(d.flagEffect == .none)
    }

    @Test func adds64BitSetsFlags() {
        let d = decode(0xB100_0420, at: 0)
        #expect(d.mnemonic == .adds)
        #expect(d.flagEffect == .nzcv)
    }

    @Test func subs64BitSetsFlags() {
        let d = decode(0xF100_0420, at: 0)
        #expect(d.mnemonic == .subs)
        #expect(d.flagEffect == .nzcv)
    }

    @Test func addWithShiftEmitsFourthOperand() {
        let d = decode(0x9140_0020, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.operands.count == 4)
        #expect(
            d.operands[3] == .shiftAmount(kind: .lsl, amount: 12),
            "expected .shiftAmount(.lsl, 12) at operand index 3",
        )
    }

    @Test func cmpAliasDropsRd() {
        let d = decode(0xF100_147F, at: 0)
        #expect(d.mnemonic == .cmp)
        #expect(d.operands.count == 2)
        #expect(d.flagEffect == .nzcv)
        #expect(d.semanticWrites == .empty)
        #expect(d.semanticReads.contains(.x(3)))
    }

    @Test func cmnAliasDropsRd() {
        let d = decode(0xB100_147F, at: 0)
        #expect(d.mnemonic == .cmn)
        #expect(d.operands.count == 2)
        #expect(d.flagEffect == .nzcv)
    }

    @Test func cmpWithShiftHasThreeOperands() {
        let d = decode(0xF140_107F, at: 0)
        #expect(d.mnemonic == .cmp)
        #expect(d.operands.count == 3)
    }

    @Test func cmpAlias32Bit() {
        let d = decode(0x7100_147F, at: 0)
        #expect(d.mnemonic == .cmp)
    }

    @Test func cmnAlias32Bit() {
        let d = decode(0x3100_147F, at: 0)
        #expect(d.mnemonic == .cmn)
    }

    @Test func movToSPAliasFromX0PlusZero() {
        let d = decode(0x9100_03E0, at: 0)
        #expect(d.mnemonic == .mov)
        #expect(d.operands.count == 2)
        #expect(d.operands[1] == .register(.sp()), "expected SP at operand 1")
        #expect(d.semanticReads.contains(.sp()))
    }

    @Test func movFromSPAliasToX0() {
        let d = decode(0x9100_001F, at: 0)
        #expect(d.mnemonic == .mov)
        #expect(d.operands[0] == .register(.sp()), "expected SP at operand 0")
    }

    @Test func movSPSPAlias() {
        let d = decode(0x9100_03FF, at: 0)
        #expect(d.mnemonic == .mov)
    }

    @Test func movWspWAliasIn32Bit() {
        let d = decode(0x1100_001F, at: 0)
        #expect(d.mnemonic == .mov)
        #expect(d.operands[0] == .register(.wsp()), "expected WSP")
    }

    @Test func plainAddDoesNotTriggerMovWhenNeitherEndIsSP() {
        let d = decode(0x9100_0020, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.operands.count == 3)
    }

    @Test func subDoesNotTriggerMovEvenWithImmZero() {
        let d = decode(0xD100_03FF, at: 0)
        #expect(d.mnemonic == .sub)
    }

    @Test func subsRdNotXZRStaysAsSubs() {
        let d = decode(0xF100_1461, at: 0)
        #expect(d.mnemonic == .subs)
    }

    @Test func addImmZeroWithNeitherSP_NoMOVAlias() {
        let d = decode(0x9100_00C5, at: 0)
        #expect(d.mnemonic == .add)
    }

    @Test func subRnSPDoesNotTriggerMOVAlias() {
        let d = decode(0xD100_03E0, at: 0)
        #expect(d.mnemonic == .sub)
    }

    @Test func addsWithShiftEmitsShiftOperand() {
        let d = decode(0xB140_0020, at: 0)
        #expect(d.mnemonic == .adds)
        #expect(d.operands.count == 4)
    }

    @Test func subsWithShiftEmitsShiftOperand() {
        let d = decode(0xF140_0020, at: 0)
        #expect(d.mnemonic == .subs)
        #expect(d.operands.count == 4)
    }

    @Test func subWithShiftEmitsShiftOperand() {
        let d = decode(0xD140_0020, at: 0)
        #expect(d.mnemonic == .sub)
        #expect(d.operands.count == 4)
    }

    @Test func encodingPreservedInRecord() {
        let d = decode(0x9100_0420, at: 0xABCD)
        #expect(d.encoding == 0x9100_0420)
        #expect(d.address == 0xABCD)
    }
}
