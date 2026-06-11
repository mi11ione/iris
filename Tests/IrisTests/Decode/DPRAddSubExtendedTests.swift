// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates ADD/ADDS/SUB/SUBS extended-register decode
/// (extended half). Covers the SP-form Rn, the S-conditional Rd form,
/// the per-extend Rm width rule, and the imm3 ∈ {5,6,7} reserved cases.
@Suite("DPR / Add/Sub extended-register")
struct DPRAddSubExtendedTests {
    @Test func baseAddExtendedUxtxAtX64() {
        // ADD x0, x1, x2, UXTX #0. Per-extend width rule: UXTX at sf=1 → Xn.
        let d = decode(0x8B22_6020, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.flagEffect == .none)
        #expect(Array(d.operands) == [
            .register(.x(0)), .register(.x(1)),
            .extendedRegister(reg: .x(2), extend: .uxtx, shift: 0),
        ])
    }

    @Test func baseAddExtendedUxtwAtX64() {
        // ADD x0, x1, w2, UXTW #0 — UXTW at sf=1 → Rm is Wn.
        let d = decode(0x8B22_4020, at: 0)
        #expect(d.operands[2] == .extendedRegister(reg: .w(2), extend: .uxtw, shift: 0))
    }

    @Test func baseAddExtendedSxtxAtX64WidthIsXn() {
        // ADD x0, x1, x2, SXTX — SXTX at sf=1 → Xn.
        let d = decode(0x8B22_E020, at: 0)
        #expect(d.operands[2] == .extendedRegister(reg: .x(2), extend: .sxtx, shift: 0))
    }

    @Test func baseAddExtendedSxtxAtSf0WidthIsWn() {
        // ADD w0, w1, w2, SXTX (sf=0) — SXTX at sf=0 → Wn.
        let d = decode(0x0B22_E020, at: 0)
        #expect(d.operands[2] == .extendedRegister(reg: .w(2), extend: .sxtx, shift: 0))
    }

    @Test func baseAddExtendedUxtxAtSf0WidthIsWn() {
        // ADD w0, w1, w2, UXTX (sf=0).
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
        // ADD x0, x1, w2, UXTW #2 — imm3=2.
        let d = decode(0x8B22_4820, at: 0)
        #expect(d.operands[2] == .extendedRegister(reg: .w(2), extend: .uxtw, shift: 2))
    }

    @Test func imm3FivetoSevenReturnsUndefined() {
        // imm3 ∈ {5,6,7} is reserved.
        for imm3: UInt32 in 5 ... 7 {
            // Base encoding for ADD x0, x1, x2, UXTX + imm3 at bits 12:10.
            let encoding: UInt32 = 0x8B22_6020 | (imm3 << 10)
            let d = decode(encoding, at: 0)
            #expect(d.mnemonic == .undefined, "imm3=\(imm3) must be reserved")
        }
    }

    @Test func bits23_22NonZeroReturnsUndefined() {
        // Bits 23:22 are architecturally fixed at 00.
        // bit 22 set: encoding 0x8B62_6020.
        let d1 = decode(0x8B62_6020, at: 0)
        #expect(d1.mnemonic == .undefined)
        // bit 23 set: encoding 0x8BA2_6020.
        let d2 = decode(0x8BA2_6020, at: 0)
        #expect(d2.mnemonic == .undefined)
        // both set.
        let d3 = decode(0x8BE2_6020, at: 0)
        #expect(d3.mnemonic == .undefined)
    }

    @Test func addToSPUsesSpForm() {
        // ADD sp, x1, x2, UXTX — Rd is SP-form because S=0 + Rd=31.
        let d = decode(0x8B22_603F, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.operands[0] == .register(.sp()))
    }

    @Test func addsRd31IsZeroFormPerSBit() {
        // ADDS xzr, x1, x2, UXTX — S=1 + Rd=31 → CMN alias.
        // (CMN extended dropping Rd → operand list shrinks.)
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
        // SUBS xzr, sp, x1, UXTX → CMP sp, x1.
        let d = decode(0xEB21_63FF, at: 0)
        #expect(d.mnemonic == .cmp)
        #expect(d.operands.count == 2)
        #expect(d.operands[0] == .register(.sp()))
    }

    @Test func subExtendedNoAliasWhenRdIsNotXZR() {
        // SUBS x1, x2, x3, UXTX — Rd != 31 → stays as SUBS.
        let d = decode(0xEB23_6041, at: 0)
        #expect(d.mnemonic == .subs)
        #expect(Array(d.operands) == [
            .register(.x(1)), .register(.x(2)),
            .extendedRegister(reg: .x(3), extend: .uxtx, shift: 0),
        ])
    }

    @Test func addsExtendedRdNonZeroStaysAsAdds() {
        // ADDS x1, x2, x3, UXTX — op=0, S=1, Rd != 31 → no CMN alias.
        let d = decode(0xAB23_6041, at: 0)
        #expect(d.mnemonic == .adds)
        #expect(d.flagEffect == .nzcv)
        #expect(Array(d.operands) == [
            .register(.x(1)), .register(.x(2)),
            .extendedRegister(reg: .x(3), extend: .uxtx, shift: 0),
        ])
    }

    @Test func subExtendedDecodes() {
        // SUB x0, x1, x2, UXTX — op=1, S=0.
        let d = decode(0xCB22_6020, at: 0)
        #expect(d.mnemonic == .sub)
        #expect(d.flagEffect == .none)
    }
}
