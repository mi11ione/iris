// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates ADD/SUB-imm decode + CMP/CMN/MOV-to-SP alias precedence
/// Each row pins an encoding's mnemonic, operand count,
/// flag effect, and read/write semantics for both 32-bit and 64-bit
/// register widths and both shift cases (sh=0 / sh=1).
@Suite("DPI / ADD/SUB-imm decode")
struct DPIAddSubImmTests {
    @Test func baseAdd64Bit() {
        // ADD x0, x1, #1 (sf=1, op=0, S=0, sh=0, imm12=1)
        let d = decode(0x9100_0420, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.operands.count == 3)
        #expect(d.flagEffect == .none)
        #expect(d.category == .dataProcessingImmediate)
        #expect(d.semanticReads.contains(.x(1)))
        #expect(d.semanticWrites.contains(.x(0)))
    }

    @Test func baseAdd32Bit() {
        // ADD w0, w1, #1
        let d = decode(0x1100_0420, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.flagEffect == .none)
    }

    @Test func baseSub64Bit() {
        // SUB x0, x1, #1 (op=1, S=0)
        let d = decode(0xD100_0420, at: 0)
        #expect(d.mnemonic == .sub)
        #expect(d.flagEffect == .none)
    }

    @Test func adds64BitSetsFlags() {
        // ADDS x0, x1, #1 (op=0, S=1)
        let d = decode(0xB100_0420, at: 0)
        #expect(d.mnemonic == .adds)
        #expect(d.flagEffect == .nzcv)
    }

    @Test func subs64BitSetsFlags() {
        // SUBS x0, x1, #1 (op=1, S=1)
        let d = decode(0xF100_0420, at: 0)
        #expect(d.mnemonic == .subs)
        #expect(d.flagEffect == .nzcv)
    }

    @Test func addWithShiftEmitsFourthOperand() {
        // ADD x0, x1, #0, lsl #12 (sh=1)
        let d = decode(0x9140_0020, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.operands.count == 4)
        #expect(
            d.operands[3] == .shiftAmount(kind: .lsl, amount: 12),
            "expected .shiftAmount(.lsl, 12) at operand index 3",
        )
    }

    @Test func cmpAliasDropsRd() {
        // SUBS xzr, x3, #5  →  CMP x3, #5
        let d = decode(0xF100_147F, at: 0)
        #expect(d.mnemonic == .cmp)
        #expect(d.operands.count == 2)
        #expect(d.flagEffect == .nzcv)
        #expect(d.semanticWrites == .empty) // Rd=XZR omitted
        #expect(d.semanticReads.contains(.x(3)))
    }

    @Test func cmnAliasDropsRd() {
        // ADDS xzr, x3, #5  →  CMN x3, #5
        let d = decode(0xB100_147F, at: 0)
        #expect(d.mnemonic == .cmn)
        #expect(d.operands.count == 2)
        #expect(d.flagEffect == .nzcv)
    }

    @Test func cmpWithShiftHasThreeOperands() {
        // SUBS xzr, x3, #4, lsl #12  →  CMP x3, #4, lsl #12
        let d = decode(0xF140_107F, at: 0)
        #expect(d.mnemonic == .cmp)
        #expect(d.operands.count == 3)
    }

    @Test func cmpAlias32Bit() {
        // SUBS wzr, w3, #5  →  CMP w3, #5
        let d = decode(0x7100_147F, at: 0)
        #expect(d.mnemonic == .cmp)
    }

    @Test func cmnAlias32Bit() {
        // ADDS wzr, w3, #5  →  CMN w3, #5
        let d = decode(0x3100_147F, at: 0)
        #expect(d.mnemonic == .cmn)
    }

    @Test func movToSPAliasFromX0PlusZero() {
        // ADD x0, sp, #0  →  MOV x0, sp
        let d = decode(0x9100_03E0, at: 0)
        #expect(d.mnemonic == .mov)
        #expect(d.operands.count == 2)
        #expect(d.operands[1] == .register(.sp()), "expected SP at operand 1")
        #expect(d.semanticReads.contains(.sp())) // SP is tracked
    }

    @Test func movFromSPAliasToX0() {
        // ADD sp, x0, #0  →  MOV sp, x0
        let d = decode(0x9100_001F, at: 0)
        #expect(d.mnemonic == .mov)
        #expect(d.operands[0] == .register(.sp()), "expected SP at operand 0")
    }

    @Test func movSPSPAlias() {
        // ADD sp, sp, #0  →  MOV sp, sp
        let d = decode(0x9100_03FF, at: 0)
        #expect(d.mnemonic == .mov)
    }

    @Test func movWspWAliasIn32Bit() {
        // ADD wsp, w0, #0  →  MOV wsp, w0
        let d = decode(0x1100_001F, at: 0)
        #expect(d.mnemonic == .mov)
        #expect(d.operands[0] == .register(.wsp()), "expected WSP")
    }

    @Test func plainAddDoesNotTriggerMovWhenNeitherEndIsSP() {
        // ADD x0, x1, #0 (Rn != 31, Rd != 31)
        let d = decode(0x9100_0020, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.operands.count == 3)
    }

    @Test func subDoesNotTriggerMovEvenWithImmZero() {
        // SUB sp, sp, #0 — op=1 doesn't get MOV alias (MOV is for ADD)
        let d = decode(0xD100_03FF, at: 0)
        #expect(d.mnemonic == .sub)
    }

    @Test func subsRdNotXZRStaysAsSubs() {
        // SUBS x1, x3, #5 (Rd != 31)  →  stays as subs
        let d = decode(0xF100_1461, at: 0)
        #expect(d.mnemonic == .subs)
    }

    @Test func addImmZeroWithNeitherSP_NoMOVAlias() {
        // ADD x5, x6, #0 — no SP involved
        let d = decode(0x9100_00C5, at: 0)
        #expect(d.mnemonic == .add)
    }

    @Test func subRnSPDoesNotTriggerMOVAlias() {
        // SUB x0, sp, #0 (op=1) — MOV alias only for ADD (op=0)
        let d = decode(0xD100_03E0, at: 0)
        #expect(d.mnemonic == .sub)
    }

    @Test func addsWithShiftEmitsShiftOperand() {
        // ADDS x0, x1, #0, lsl #12 (S=1, sh=1)
        let d = decode(0xB140_0020, at: 0)
        #expect(d.mnemonic == .adds)
        #expect(d.operands.count == 4)
    }

    @Test func subsWithShiftEmitsShiftOperand() {
        // SUBS x0, x1, #0, lsl #12
        let d = decode(0xF140_0020, at: 0)
        #expect(d.mnemonic == .subs)
        #expect(d.operands.count == 4)
    }

    @Test func subWithShiftEmitsShiftOperand() {
        // SUB x0, x1, #0, lsl #12
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
