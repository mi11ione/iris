// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates MOVN/MOVZ/MOVK and MOV-wide precedence.
@Suite("DPI / Move-wide decode + aliases")
struct DPIMoveWideTests {
    @Test func movzMovAliasDropsLslZero() {
        let d = decode(0xD282_8020, at: 0)
        #expect(d.mnemonic == .mov)
        #expect(d.operands.count == 2)
        #expect(
            d.operands[1] == .immediate(value: 5121, width: 64),
            "expected signed immediate at operand 1",
        )
    }

    @Test func movzWithImmAndShiftAliasToMov() {
        let d = decode(0xD2A0_2460, at: 0)
        #expect(d.mnemonic == .mov)
        if case let .immediate(value, _) = d.operands[1] {
            #expect(value == 0x123 << 16)
        }
    }

    @Test func movzWithImm0AndHwGreaterThan0StaysAsMovz() {
        let d = decode(0xD2C0_0000, at: 0)
        #expect(d.mnemonic == .movz)
        #expect(d.operands.count == 3)
    }

    @Test func movzWithImm0AndHw0IsMovZero() {
        let d = decode(0xD280_0000, at: 0)
        #expect(d.mnemonic == .mov)
        if case let .immediate(value, _) = d.operands[1] {
            #expect(value == 0)
        }
    }

    @Test func movnOfZeroIsMinusOneSigned() {
        let d = decode(0x9280_0000, at: 0)
        #expect(d.mnemonic == .mov)
        if case let .immediate(value, width) = d.operands[1] {
            #expect(value == -1)
            #expect(width == 64)
        }
    }

    @Test func movnOf1IsMinusTwoSigned() {
        let d = decode(0x9280_0020, at: 0)
        #expect(d.mnemonic == .mov)
        if case let .immediate(value, _) = d.operands[1] {
            #expect(value == -2)
        }
    }

    @Test func movn32BitSignExtendsViaInt32() {
        let d = decode(0x1280_0020, at: 0)
        #expect(d.mnemonic == .mov)
        if case let .immediate(value, width) = d.operands[1] {
            #expect(value == -2)
            #expect(width == 32)
        }
    }

    @Test func movnPreservedWhenMOVZCouldProduceSameValue() {
        let d = decode(0x129F_FFE0, at: 0)
        #expect(d.mnemonic == .movn)
        #expect(d.operands.count == 2)
    }

    @Test func movnImm0Hw16StaysAsMovn() {
        let d = decode(0x92A0_0000, at: 0)
        #expect(d.mnemonic == .movn)
        #expect(d.operands.count == 3)
    }

    @Test func movkIsBaseFormAndReadsRd() {
        let d = decode(0xF280_0020, at: 0)
        #expect(d.mnemonic == .movk)
        #expect(d.operands.count == 2)
        #expect(d.semanticReads.contains(.x(0)))
        #expect(d.semanticWrites.contains(.x(0)))
    }

    @Test func movkWithShiftHasThreeOperands() {
        let d = decode(0xF2A0_00A0, at: 0)
        #expect(d.mnemonic == .movk)
        #expect(d.operands.count == 3)
    }

    @Test func movkWithHw32() {
        let d = decode(0xF2C0_00A0, at: 0)
        #expect(d.mnemonic == .movk)
        #expect(d.operands[2] == .shiftAmount(kind: .lsl, amount: 32), "expected shift operand")
    }

    @Test func movkWithHw48() {
        let d = decode(0xF2E0_00A0, at: 0)
        #expect(d.mnemonic == .movk)
        if case let .shiftAmount(_, amount) = d.operands[2] {
            #expect(amount == 48)
        }
    }

    @Test func movz32BitWithHw1() {
        let d = decode(0x52A0_0020, at: 0)
        #expect(d.mnemonic == .mov)
        if case let .immediate(value, _) = d.operands[1] {
            #expect(value == 1 << 16)
        }
    }

    @Test func reserved32BitWithHw2IsUndefined() {
        let d = decode(0x12C0_0020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reserved32BitWithHw3IsUndefined() {
        let d = decode(0x52E0_0020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedOpc01IsUndefined() {
        let d = decode(0x3280_0020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func movnCannotAliasToMOVWhenImm0HwNonZero32Bit() {
        let d = decode(0x12A0_0000, at: 0)
        #expect(d.mnemonic == .movn)
    }

    @Test func movzWritesOnlyRd_NoRn() {
        let d = decode(0xD280_0020, at: 0)
        #expect(d.semanticReads == .empty)
        #expect(d.semanticWrites.contains(.x(0)))
    }

    @Test func movnWritesOnlyRd_NoRn() {
        let d = decode(0x9280_0020, at: 0)
        #expect(d.semanticReads == .empty)
        #expect(d.semanticWrites.contains(.x(0)))
    }
}
