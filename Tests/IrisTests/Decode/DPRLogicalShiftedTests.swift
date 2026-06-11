// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates AND/ORR/EOR/ANDS/BIC/ORN/EON/BICS shifted-register decode +
/// MOV/MVN/TST aliases + the shift-kind and reserved-bit edge cases.
@Suite("DPR / Logical shifted-register")
struct DPRLogicalShiftedTests {
    @Test func baseAnd64Bit() {
        // AND x0, x1, x2 — opc=00, N=0.
        let d = decode(0x8A02_0020, at: 0)
        #expect(d.mnemonic == .and)
        #expect(d.flagEffect == .none)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1)), .register(.x(2))])
    }

    @Test func baseOrr64Bit() {
        let d = decode(0xAA02_0020, at: 0)
        #expect(d.mnemonic == .orr)
    }

    @Test func baseEor64Bit() {
        let d = decode(0xCA02_0020, at: 0)
        #expect(d.mnemonic == .eor)
    }

    @Test func baseAndsSetsNzcv() {
        let d = decode(0xEA02_0020, at: 0)
        #expect(d.mnemonic == .ands)
        #expect(d.flagEffect == .nzcv)
    }

    @Test func baseBic() {
        // AND with N=1 → BIC. Encoding bit 21 set.
        let d = decode(0x8A22_0020, at: 0)
        #expect(d.mnemonic == .bic)
    }

    @Test func baseOrn() {
        let d = decode(0xAA22_0020, at: 0)
        #expect(d.mnemonic == .orn)
    }

    @Test func baseEon() {
        let d = decode(0xCA22_0020, at: 0)
        #expect(d.mnemonic == .eon)
    }

    @Test func baseBicsSetsNzcv() {
        let d = decode(0xEA22_0020, at: 0)
        #expect(d.mnemonic == .bics)
        #expect(d.flagEffect == .nzcv)
    }

    @Test func andWithLsrShiftEmitsShiftedRegister() {
        let d = decode(0x8A42_1420, at: 0)
        #expect(d.mnemonic == .and)
        #expect(d.operands[2] == .shiftedRegister(reg: .x(2), shift: .lsr, amount: 5))
    }

    @Test func andWithAsrShiftEmitsShiftedRegister() {
        let d = decode(0x8A82_1420, at: 0)
        #expect(d.operands[2] == .shiftedRegister(reg: .x(2), shift: .asr, amount: 5))
    }

    @Test func andWithRorShiftEmitsShiftedRegister() {
        // ROR is a valid shift kind for logical ops (unlike arithmetic).
        let d = decode(0x8AC2_1420, at: 0)
        #expect(d.mnemonic == .and)
        #expect(d.operands[2] == .shiftedRegister(reg: .x(2), shift: .ror, amount: 5))
    }

    @Test func and32BitImm6High5SetReturnsUndefined() {
        // sf=0 + imm6[5]=1 is reserved (here with ROR shift kind).
        let d = decode(0x0AC2_8020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func movRegisterAliasOnZeroShiftRnXZR() {
        // ORR Rd, XZR, Rm, LSL #0 → MOV Rd, Rm.
        let d = decode(0xAA02_03E0, at: 0)
        #expect(d.mnemonic == .mov)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(2))])
        #expect(d.flagEffect == .none)
    }

    @Test func movRegisterDoesNotAliasWithRorShift() {
        // ORR Rd, XZR, Rm, ROR #5 stays as ORR (MOV needs LSL #0).
        let d = decode(0xAAC2_17E0, at: 0)
        #expect(d.mnemonic == .orr)
    }

    @Test func movRegisterDoesNotAliasWithNonzeroShift() {
        // ORR Rd, XZR, Rm, LSL #3 stays as ORR (alias predicate requires amount=0).
        let d = decode(0xAA02_0FE0, at: 0)
        #expect(d.mnemonic == .orr)
    }

    @Test func movRegisterDoesNotAliasWhenRnIsNonZero() {
        // ORR x0, x1, x2 — Rn != 31 → no MOV alias.
        let d = decode(0xAA02_0020, at: 0)
        #expect(d.mnemonic == .orr)
    }

    @Test func mvnAliasFromOrnRnXZR() {
        // ORN Rd, XZR, Rm → MVN Rd, Rm.
        let d = decode(0xAA22_03E0, at: 0)
        #expect(d.mnemonic == .mvn)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(2))])
    }

    @Test func mvnAliasKeepsShiftAtNonzeroAmount() {
        // ORN Rd, XZR, Rm, LSL #3 → MVN Rd, Rm, LSL #3.
        let d = decode(0xAA22_0FE0, at: 0)
        #expect(d.mnemonic == .mvn)
        #expect(d.operands[1] == .shiftedRegister(reg: .x(2), shift: .lsl, amount: 3))
    }

    @Test func tstAliasFromAndsRdXZR() {
        // ANDS xzr, Rn, Rm → TST Rn, Rm.
        let d = decode(0xEA02_003F, at: 0)
        #expect(d.mnemonic == .tst)
        #expect(Array(d.operands) == [.register(.x(1)), .register(.x(2))])
        #expect(d.flagEffect == .nzcv)
        #expect(d.semanticWrites == .empty)
    }

    @Test func tstAliasKeepsShift() {
        // ANDS xzr, x1, x2, ROR #5 → TST x1, x2, ROR #5.
        let d = decode(0xEAC2_143F, at: 0)
        #expect(d.mnemonic == .tst)
        #expect(d.operands[1] == .shiftedRegister(reg: .x(2), shift: .ror, amount: 5))
    }

    @Test func andsWithRdNonZeroStaysAsAnds() {
        // ANDS x1, x2, x3 — Rd != 31 → no TST alias.
        let d = decode(0xEA03_0041, at: 0)
        #expect(d.mnemonic == .ands)
    }

    @Test func base32BitDecodesWithW() {
        let d = decode(0x0A02_0020, at: 0)
        #expect(d.mnemonic == .and)
        #expect(Array(d.operands) == [.register(.w(0)), .register(.w(1)), .register(.w(2))])
    }
}
