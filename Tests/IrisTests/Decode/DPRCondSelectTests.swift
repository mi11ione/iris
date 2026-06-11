// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates CSEL/CSINC/CSINV/CSNEG decode + CSET/CSETM/CINC/CINV/CNEG
/// alias precedence. Includes the cond-invertable rule (AL/NV suppress
/// aliases) and CNEG's special allowance for Rn=XZR (no CSET-precedence
/// override).
@Suite("DPR / Conditional select")
struct DPRCondSelectTests {
    @Test func baseCsel64Bit() {
        // CSEL x0, x1, x2, EQ.
        let d = decode(0x9A82_0020, at: 0)
        #expect(d.mnemonic == .csel)
        #expect(d.flagEffect == .readsNZCV)
        #expect(d.operands.count == 4)
        #expect(d.operands[3] == .conditionCode(.eq))
    }

    @Test func baseCsinc64Bit() {
        // CSINC x0, x1, x2, EQ — op2=01.
        let d = decode(0x9A82_0420, at: 0)
        #expect(d.mnemonic == .csinc)
    }

    @Test func baseCsinv64Bit() {
        // CSINV x0, x1, x2, EQ — op=1, op2=00.
        let d = decode(0xDA82_0020, at: 0)
        #expect(d.mnemonic == .csinv)
    }

    @Test func baseCsneg64Bit() {
        // CSNEG x0, x1, x2, EQ — op=1, op2=01.
        let d = decode(0xDA82_0420, at: 0)
        #expect(d.mnemonic == .csneg)
    }

    @Test func base32BitWidth() {
        let d = decode(0x1A82_0020, at: 0)
        #expect(d.mnemonic == .csel)
        #expect(d.operands[0] == .register(.w(0)))
    }

    @Test func csetAliasFromCsincRnRmXZR() {
        // CSINC x0, xzr, xzr, EQ → CSET x0, NE (invert EQ).
        let d = decode(0x9A9F_07E0, at: 0)
        #expect(d.mnemonic == .cset)
        #expect(d.operands.count == 2)
        #expect(d.operands[0] == .register(.x(0)))
        #expect(d.operands[1] == .conditionCode(.ne))
    }

    @Test func csetmAliasFromCsinvRnRmXZR() {
        // CSINV x0, xzr, xzr, EQ → CSETM x0, NE. op2=00 (CSINV), not 01.
        let d = decode(0xDA9F_03E0, at: 0)
        #expect(d.mnemonic == .csetm)
        #expect(Array(d.operands) == [.register(.x(0)), .conditionCode(.ne)])
    }

    @Test func cincAliasFromCsincRnEqualRmNonXZR() {
        // CSINC x0, x1, x1, EQ → CINC x0, x1, NE.
        let d = decode(0x9A81_0420, at: 0)
        #expect(d.mnemonic == .cinc)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1)), .conditionCode(.ne)])
    }

    @Test func cinvAliasFromCsinvRnEqualRmNonXZR() {
        // CSINV x0, x1, x1, EQ → CINV x0, x1, NE. op2=00.
        let d = decode(0xDA81_0020, at: 0)
        #expect(d.mnemonic == .cinv)
        if case let .register(reg) = d.operands[1] {
            #expect(reg.canonicalIndex == 1)
        }
    }

    @Test func cnegAliasFromCsnegRnEqualRm() {
        // CSNEG x0, x1, x1, EQ → CNEG x0, x1, NE.
        let d = decode(0xDA81_0420, at: 0)
        #expect(d.mnemonic == .cneg)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1)), .conditionCode(.ne)])
    }

    @Test func cnegAllowsRnEqualXZR() {
        // CSNEG x0, xzr, xzr, EQ → CNEG x0, xzr, NE.
        // (CINC/CINV require Rn != 31; CNEG does NOT.)
        let d = decode(0xDA9F_07E0, at: 0)
        #expect(d.mnemonic == .cneg)
        if case let .register(reg) = d.operands[1] {
            #expect(reg.isZeroRegister)
        }
    }

    @Test func cincDoesNotTriggerForCsincWithRnRmXZRAtCondInvertable() {
        // CSINC x0, xzr, xzr, EQ — Rn=Rm=31 → CSET (more specific), NOT CINC.
        let d = decode(0x9A9F_07E0, at: 0)
        #expect(d.mnemonic == .cset, "CSET takes precedence over CINC at Rn=Rm=31")
    }

    @Test func csetSuppressedAtALCondition() {
        // CSINC x0, xzr, xzr, AL — cond=1110 → not invertable → base CSINC.
        let d = decode(0x9A9F_E7E0, at: 0)
        #expect(d.mnemonic == .csinc)
        if case let .conditionCode(c) = d.operands[3] {
            #expect(c == .al, "base mnemonic keeps original cond")
        }
    }

    @Test func csetSuppressedAtNVCondition() {
        // CSINC x0, xzr, xzr, NV — cond=1111 → not invertable → base CSINC.
        let d = decode(0x9A9F_F7E0, at: 0)
        #expect(d.mnemonic == .csinc)
    }

    @Test func csetmSuppressedAtALCondition() {
        // CSINV x0, xzr, xzr, AL — base CSINV retained.
        let d = decode(0xDA9F_E3E0, at: 0)
        #expect(d.mnemonic == .csinv)
    }

    @Test func csetmSuppressedAtNVCondition() {
        let d = decode(0xDA9F_F3E0, at: 0)
        #expect(d.mnemonic == .csinv)
    }

    @Test func cincSuppressedAtALCondition() {
        // CSINC x0, x1, x1, AL — base CSINC retained.
        let d = decode(0x9A81_E420, at: 0)
        #expect(d.mnemonic == .csinc)
    }

    @Test func cincSuppressedAtNVCondition() {
        let d = decode(0x9A81_F420, at: 0)
        #expect(d.mnemonic == .csinc)
    }

    @Test func cinvSuppressedAtALCondition() {
        // CSINV x0, x1, x1, AL — base CSINV retained (op2=00).
        let d = decode(0xDA81_E020, at: 0)
        #expect(d.mnemonic == .csinv)
    }

    @Test func cinvSuppressedAtNVCondition() {
        let d = decode(0xDA81_F020, at: 0)
        #expect(d.mnemonic == .csinv)
    }

    @Test func cnegSuppressedAtALCondition() {
        // CSNEG x0, x1, x1, AL — base CSNEG retained.
        let d = decode(0xDA81_E420, at: 0)
        #expect(d.mnemonic == .csneg)
    }

    @Test func cnegSuppressedAtNVCondition() {
        let d = decode(0xDA81_F420, at: 0)
        #expect(d.mnemonic == .csneg)
    }

    @Test func cincRequiresRnNotXZR() {
        // CSINC x0, x1, x1, EQ → CINC (Rn=Rm general).
        // CSINC x0, xzr, xzr, EQ → CSET (Rn=Rm=31). The CINC-with-XZR
        // case never happens because CSET pre-empts. Verified above.
        let d = decode(0x9A81_0420, at: 0)
        #expect(d.mnemonic == .cinc)
        if case let .register(reg) = d.operands[1] {
            #expect(reg.isZeroRegister == false)
        }
    }

    @Test func baseCselWhenRnRmDiffer() {
        // CSEL x0, x1, x2, EQ — Rn != Rm → no alias.
        let d = decode(0x9A82_0020, at: 0)
        #expect(d.mnemonic == .csel)
    }

    @Test func sBitSetReturnsUndefined() {
        // S=1 is reserved for conditional select.
        let d = decode(0x9A82_0020 | (1 << 29), at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func op2EqualsTwoReturnsUndefined() {
        // bits 11:10 = 10 reserved.
        let d = decode(0x9A82_0820, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func op2EqualsThreeReturnsUndefined() {
        let d = decode(0x9A82_0C20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func everyConditionCodeBranches() {
        // Drive every cond through CSEL to cover the cond decode branch.
        for raw: UInt32 in 0 ... 15 {
            let encoding: UInt32 = 0x9A82_0020 | (raw << 12)
            let d = decode(encoding, at: 0)
            #expect(d.mnemonic == .csel)
            if case let .conditionCode(c) = d.operands[3] {
                #expect(c.rawValue == UInt8(raw))
            }
        }
    }
}
