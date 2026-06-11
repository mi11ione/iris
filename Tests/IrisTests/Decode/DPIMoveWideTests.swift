// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates MOVN/MOVZ/MOVK decode + MOV-wide alias precedence.
/// Includes the MOVN→MOV gate that requires the value NOT
/// be MOVZ-representable, the 32-bit sign-extension rule, the MOVK
/// read-modify-write behavior, and the reserved-encoding rules.
@Suite("DPI / Move-wide decode + aliases")
struct DPIMoveWideTests {
    @Test func movzMovAliasDropsLslZero() {
        // MOVZ x0, #5121, lsl #0  →  MOV x0, #5121
        let d = decode(0xD282_8020, at: 0)
        #expect(d.mnemonic == .mov)
        #expect(d.operands.count == 2)
        #expect(
            d.operands[1] == .immediate(value: 5121, width: 64),
            "expected signed immediate at operand 1",
        )
    }

    @Test func movzWithImmAndShiftAliasToMov() {
        // MOVZ x0, #0x123, lsl #16 (hw=1, imm16=0x123)
        let d = decode(0xD2A0_2460, at: 0)
        #expect(d.mnemonic == .mov)
        if case let .immediate(value, _) = d.operands[1] {
            #expect(value == 0x123 << 16)
        }
    }

    @Test func movzWithImm0AndHwGreaterThan0StaysAsMovz() {
        // MOVZ x0, #0, lsl #32 (hw=2 imm=0) — multiple hw produce value 0,
        // so MOV alias is ambiguous; stays as MOVZ.
        let d = decode(0xD2C0_0000, at: 0)
        #expect(d.mnemonic == .movz)
        #expect(d.operands.count == 3)
    }

    @Test func movzWithImm0AndHw0IsMovZero() {
        // MOVZ x0, #0, lsl #0 (hw=0 imm=0) → MOV x0, #0
        let d = decode(0xD280_0000, at: 0)
        #expect(d.mnemonic == .mov)
        if case let .immediate(value, _) = d.operands[1] {
            #expect(value == 0)
        }
    }

    @Test func movnOfZeroIsMinusOneSigned() {
        // MOVN x0, #0, lsl #0  →  MOV x0, #-1
        let d = decode(0x9280_0000, at: 0)
        #expect(d.mnemonic == .mov)
        if case let .immediate(value, width) = d.operands[1] {
            #expect(value == -1)
            #expect(width == 64)
        }
    }

    @Test func movnOf1IsMinusTwoSigned() {
        // MOVN x0, #1, lsl #0  →  MOV x0, #-2
        let d = decode(0x9280_0020, at: 0)
        #expect(d.mnemonic == .mov)
        if case let .immediate(value, _) = d.operands[1] {
            #expect(value == -2)
        }
    }

    @Test func movn32BitSignExtendsViaInt32() {
        // MOVN w0, #1, lsl #0  →  MOV w0, #-2 (Int32 sign-extended)
        let d = decode(0x1280_0020, at: 0)
        #expect(d.mnemonic == .mov)
        if case let .immediate(value, width) = d.operands[1] {
            #expect(value == -2)
            #expect(width == 32)
        }
    }

    @Test func movnPreservedWhenMOVZCouldProduceSameValue() {
        // MOVN w0, #0xFFFF, lsl #0 — Value = 0xFFFF0000 which MOVZ can
        // also produce → llvm-mc keeps the MOVN form (NO MOV alias).
        let d = decode(0x129F_FFE0, at: 0)
        #expect(d.mnemonic == .movn)
        #expect(d.operands.count == 2) // hw=0 → no shift operand
    }

    @Test func movnImm0Hw16StaysAsMovn() {
        // MOVN x0, #0, lsl #16 — Value depends only on hw being 0; stays
        // as MOVN to preserve encoding identity.
        let d = decode(0x92A0_0000, at: 0)
        #expect(d.mnemonic == .movn)
        #expect(d.operands.count == 3) // hw=1 → shift operand emitted
    }

    @Test func movkIsBaseFormAndReadsRd() {
        // MOVK x0, #1 (hw=0)
        let d = decode(0xF280_0020, at: 0)
        #expect(d.mnemonic == .movk)
        #expect(d.operands.count == 2)
        // MOVK preserves un-replaced bits → Rd in BOTH read and write sets.
        #expect(d.semanticReads.contains(.x(0)))
        #expect(d.semanticWrites.contains(.x(0)))
    }

    @Test func movkWithShiftHasThreeOperands() {
        // MOVK x0, #5, lsl #16
        let d = decode(0xF2A0_00A0, at: 0)
        #expect(d.mnemonic == .movk)
        #expect(d.operands.count == 3)
    }

    @Test func movkWithHw32() {
        // MOVK x0, #5, lsl #32 (hw=2)
        let d = decode(0xF2C0_00A0, at: 0)
        #expect(d.mnemonic == .movk)
        #expect(d.operands[2] == .shiftAmount(kind: .lsl, amount: 32), "expected shift operand")
    }

    @Test func movkWithHw48() {
        // MOVK x0, #5, lsl #48 (hw=3)
        let d = decode(0xF2E0_00A0, at: 0)
        #expect(d.mnemonic == .movk)
        if case let .shiftAmount(_, amount) = d.operands[2] {
            #expect(amount == 48)
        }
    }

    @Test func movz32BitWithHw1() {
        // MOVZ w0, #1, lsl #16 (sf=0, hw=1, imm16=1)
        let d = decode(0x52A0_0020, at: 0)
        #expect(d.mnemonic == .mov)
        if case let .immediate(value, _) = d.operands[1] {
            #expect(value == 1 << 16)
        }
    }

    @Test func reserved32BitWithHw2IsUndefined() {
        // MOVN w0, #1, lsl #32 (sf=0, hw=2) → reserved
        let d = decode(0x12C0_0020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reserved32BitWithHw3IsUndefined() {
        // MOVZ w0, #1, lsl #48 (sf=0, hw=3) → reserved
        let d = decode(0x52E0_0020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedOpc01IsUndefined() {
        // Move-wide opc=01 → reserved Encoding 0x32800020:
        // sf=0, opc=01 (bits 30:29), bits 28:23=100101 (move-wide), hw=0,
        // imm16=1, Rd=0.
        let d = decode(0x3280_0020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func movnCannotAliasToMOVWhenImm0HwNonZero32Bit() {
        // MOVN w0, #0, lsl #16: sf=0 with hw=1 is a valid encoding
        // (hw < 2), but imm16=0 with hw≠0 fails the MOV-alias gate,
        // so the mnemonic stays MOVN.
        let d = decode(0x12A0_0000, at: 0)
        #expect(d.mnemonic == .movn)
    }

    @Test func movzWritesOnlyRd_NoRn() {
        // 0xD2800020: MOVZ x0, #1, lsl #0 (Rd=0).
        let d = decode(0xD280_0020, at: 0)
        #expect(d.semanticReads == .empty)
        #expect(d.semanticWrites.contains(.x(0)))
    }

    @Test func movnWritesOnlyRd_NoRn() {
        // 0x92800020: MOVN x0, #1, lsl #0 (Rd=0).
        let d = decode(0x9280_0020, at: 0)
        #expect(d.semanticReads == .empty)
        #expect(d.semanticWrites.contains(.x(0)))
    }
}
