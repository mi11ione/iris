// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the extended-register ADD/SUB forms.
@Suite("DPR / Add/Sub extended-register")
struct DPRAddSubExtendedTests {
    @Test func baseAddExtendedUxtxAtX64() {
        let d = decode(0x8B22_6020, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.flagEffect == .none)
        #expect(Array(d.operands) == [
            .register(.x(0)), .register(.x(1)),
            .extendedRegister(reg: .x(2), extend: .uxtx, shift: 0),
        ])
    }

    @Test func baseAddExtendedUxtwAtX64() {
        let d = decode(0x8B22_4020, at: 0)
        #expect(d.operands[2] == .extendedRegister(reg: .w(2), extend: .uxtw, shift: 0))
    }

    @Test func baseAddExtendedSxtxAtX64WidthIsXn() {
        let d = decode(0x8B22_E020, at: 0)
        #expect(d.operands[2] == .extendedRegister(reg: .x(2), extend: .sxtx, shift: 0))
    }

    @Test func baseAddExtendedSxtxAtSf0WidthIsWn() {
        let d = decode(0x0B22_E020, at: 0)
        #expect(d.operands[2] == .extendedRegister(reg: .w(2), extend: .sxtx, shift: 0))
    }

    @Test func baseAddExtendedUxtxAtSf0WidthIsWn() {
        let d = decode(0x0B22_6020, at: 0)
        #expect(d.operands[2] == .extendedRegister(reg: .w(2), extend: .uxtx, shift: 0))
    }

    @Test func extendKindUxtbDecodes() {
        let d = decode(0x8B22_0020, at: 0)
        #expect(d.operands[2] == .extendedRegister(reg: .w(2), extend: .uxtb, shift: 0))
    }

    @Test func extendKindUxthDecodes() {
        let d = decode(0x8B22_2020, at: 0)
        #expect(d.operands[2] == .extendedRegister(reg: .w(2), extend: .uxth, shift: 0))
    }

    @Test func extendKindSxtbDecodes() {
        let d = decode(0x8B22_8020, at: 0)
        #expect(d.operands[2] == .extendedRegister(reg: .w(2), extend: .sxtb, shift: 0))
    }

    @Test func extendKindSxthDecodes() {
        let d = decode(0x8B22_A020, at: 0)
        #expect(d.operands[2] == .extendedRegister(reg: .w(2), extend: .sxth, shift: 0))
    }

    @Test func extendKindSxtwDecodes() {
        let d = decode(0x8B22_C020, at: 0)
        #expect(d.operands[2] == .extendedRegister(reg: .w(2), extend: .sxtw, shift: 0))
    }

    @Test func extendWithShiftPreservesAmount() {
        let d = decode(0x8B22_4820, at: 0)
        #expect(d.operands[2] == .extendedRegister(reg: .w(2), extend: .uxtw, shift: 2))
    }

    @Test func imm3FivetoSevenReturnsUndefined() {
        for imm3: UInt32 in 5 ... 7 {
            let encoding: UInt32 = 0x8B22_6020 | (imm3 << 10)
            let d = decode(encoding, at: 0)
            #expect(d.mnemonic == .undefined, "imm3=\(imm3) must be reserved")
        }
    }

    @Test func bits23_22NonZeroReturnsUndefined() {
        let d1 = decode(0x8B62_6020, at: 0)
        #expect(d1.mnemonic == .undefined)
        let d2 = decode(0x8BA2_6020, at: 0)
        #expect(d2.mnemonic == .undefined)
        let d3 = decode(0x8BE2_6020, at: 0)
        #expect(d3.mnemonic == .undefined)
    }

    @Test func addToSPUsesSpForm() {
        let d = decode(0x8B22_603F, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.operands[0] == .register(.sp()))
    }

    @Test func addsRd31IsZeroFormPerSBit() {
        let d = decode(0xAB22_603F, at: 0)
        #expect(d.mnemonic == .cmn)
        #expect(Array(d.operands) == [
            .register(.x(1)),
            .extendedRegister(reg: .x(2), extend: .uxtx, shift: 0),
        ])
        #expect(d.flagEffect == .nzcv)
        #expect(d.semanticWrites == .empty)
    }

    @Test func cmpExtendedAlias() {
        let d = decode(0xEB21_63FF, at: 0)
        #expect(d.mnemonic == .cmp)
        #expect(d.operands.count == 2)
        #expect(d.operands[0] == .register(.sp()))
    }

    @Test func subExtendedNoAliasWhenRdIsNotXZR() {
        let d = decode(0xEB23_6041, at: 0)
        #expect(d.mnemonic == .subs)
        #expect(Array(d.operands) == [
            .register(.x(1)), .register(.x(2)),
            .extendedRegister(reg: .x(3), extend: .uxtx, shift: 0),
        ])
    }

    @Test func addsExtendedRdNonZeroStaysAsAdds() {
        let d = decode(0xAB23_6041, at: 0)
        #expect(d.mnemonic == .adds)
        #expect(d.flagEffect == .nzcv)
        #expect(Array(d.operands) == [
            .register(.x(1)), .register(.x(2)),
            .extendedRegister(reg: .x(3), extend: .uxtx, shift: 0),
        ])
    }

    @Test func subExtendedDecodes() {
        let d = decode(0xCB22_6020, at: 0)
        #expect(d.mnemonic == .sub)
        #expect(d.flagEffect == .none)
    }
}
