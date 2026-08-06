// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates Logical (immediate) with DecodeBitMasks and TST/MOV-bitmask
/// precedence, including the `isMOVWRepresentable` gate.
@Suite("DPI / Logical-imm decode + aliases")
struct DPILogicalImmTests {
    @Test func baseAnd32Bit() {
        let d = decode(0x1200_0820, at: 0)
        #expect(d.mnemonic == .and)
        #expect(d.flagEffect == .none)
        #expect(d.operands.count == 3)
        #expect(d.semanticReads.contains(.w(1)))
        #expect(d.semanticWrites.contains(.w(0)))
    }

    @Test func baseAnd64Bit() {
        let d = decode(0x9200_E420, at: 0)
        #expect(d.mnemonic == .and)
        #expect(
            d.operands[2] == .unsignedImmediate(value: 0x3333_3333_3333_3333, width: 64),
            "expected unsigned immediate operand",
        )
    }

    @Test func baseOrr() {
        let d = decode(0x3200_0820, at: 0)
        #expect(d.mnemonic == .orr)
    }

    @Test func baseEor() {
        let d = decode(0x5200_0820, at: 0)
        #expect(d.mnemonic == .eor)
    }

    @Test func andsSetsFlags() {
        let d = decode(0xF240_0020, at: 0)
        #expect(d.mnemonic == .ands)
        #expect(d.flagEffect == .nzcv)
    }

    @Test func tstAliasFromAndsRdXZR() {
        let d = decode(0xF240_007F, at: 0)
        #expect(d.mnemonic == .tst)
        #expect(d.operands.count == 2)
        #expect(d.flagEffect == .nzcv)
        #expect(d.semanticWrites == .empty)
        #expect(d.semanticReads.contains(.x(3)))
    }

    @Test func tst32Bit() {
        let d = decode(0x7200_007F, at: 0)
        #expect(d.mnemonic == .tst)
    }

    @Test func movBitmaskAlias64BitWideValue() {
        let d = decode(0xB27F_C7E0, at: 0)
        #expect(d.mnemonic == .mov)
        #expect(d.operands.count == 2)
        #expect(d.semanticReads == .empty)
        #expect(
            d.operands[1] == .immediate(value: 2_251_799_813_685_246, width: 64),
            "expected signed-immediate operand at index 1",
        )
    }

    @Test func movBitmaskAlias32BitSignsExtendsThroughInt32() {
        let d = decode(0x3201_07E0, at: 0)
        #expect(d.mnemonic == .mov)
        #expect(
            d.operands[1] == .immediate(value: -2_147_483_647, width: 32),
            "expected signed-decimal immediate with 32-bit width",
        )
    }

    @Test func movBitmaskNotTriggeredWhenMOVZRepresentable() {
        let d = decode(0x3200_03E0, at: 0)
        #expect(d.mnemonic == .orr)
    }

    @Test func movBitmaskNotTriggeredWhen64BitMOVZRepresentable() {
        let d = decode(0xB240_03E0, at: 0)
        #expect(d.mnemonic == .orr)
    }

    @Test func andEorTstStaysWhenRnXZRButMovBitmaskDoesNotApplyForAND() {
        let d = decode(0x9240_03E0, at: 0)
        #expect(d.mnemonic == .and)
    }

    @Test func reserved32BitWithN1IsUndefined() {
        let d = decode(0x3240_0020, at: 0)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
        #expect(d.operands.isEmpty)
    }

    @Test func reservedAllZerosPatternIsUndefined() {
        let d = decode(0x9200_FC20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedAllOnesElementIsUndefined() {
        let d = decode(0x9240_FC20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func decodeBitMasksLen0CaseReturnsNil() {
        let d = decode(0x1200_F820, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func andsX0XzrNotTSTBecauseRdNotXZR() {
        let d = decode(0xF240_03E0, at: 0)
        #expect(d.mnemonic == .ands)
        #expect(d.flagEffect == .nzcv)
    }

    @Test func eachOpcGetsBaseMnemonic() {
        let pairs: [(UInt32, Mnemonic)] = [
            (0x1200_0820, .and),
            (0x3200_0820, .orr),
            (0x5200_0820, .eor),
            (0x7200_0820, .ands),
        ]
        for (enc, expected) in pairs {
            let d = decode(enc, at: 0)
            #expect(d.mnemonic == expected, "encoding 0x\(String(enc, radix: 16))")
        }
    }
}
