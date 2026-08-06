// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates CSEL/CSINC/CSINV/CSNEG with CSET/CSETM/CINC/CINV/CNEG precedence,
/// the AL/NV suppression rule, and CNEG's Rn=XZR allowance.
@Suite("DPR / Conditional select")
struct DPRCondSelectTests {
    @Test func baseCsel64Bit() {
        let d = decode(0x9A82_0020, at: 0)
        #expect(d.mnemonic == .csel)
        #expect(d.flagEffect == .readsNZCV)
        #expect(d.operands.count == 4)
        #expect(d.operands[3] == .conditionCode(.eq))
    }

    @Test func baseCsinc64Bit() {
        let d = decode(0x9A82_0420, at: 0)
        #expect(d.mnemonic == .csinc)
    }

    @Test func baseCsinv64Bit() {
        let d = decode(0xDA82_0020, at: 0)
        #expect(d.mnemonic == .csinv)
    }

    @Test func baseCsneg64Bit() {
        let d = decode(0xDA82_0420, at: 0)
        #expect(d.mnemonic == .csneg)
    }

    @Test func base32BitWidth() {
        let d = decode(0x1A82_0020, at: 0)
        #expect(d.mnemonic == .csel)
        #expect(d.operands[0] == .register(.w(0)))
    }

    @Test func csetAliasFromCsincRnRmXZR() {
        let d = decode(0x9A9F_07E0, at: 0)
        #expect(d.mnemonic == .cset)
        #expect(d.operands.count == 2)
        #expect(d.operands[0] == .register(.x(0)))
        #expect(d.operands[1] == .conditionCode(.ne))
    }

    @Test func csetmAliasFromCsinvRnRmXZR() {
        let d = decode(0xDA9F_03E0, at: 0)
        #expect(d.mnemonic == .csetm)
        #expect(Array(d.operands) == [.register(.x(0)), .conditionCode(.ne)])
    }

    @Test func cincAliasFromCsincRnEqualRmNonXZR() {
        let d = decode(0x9A81_0420, at: 0)
        #expect(d.mnemonic == .cinc)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1)), .conditionCode(.ne)])
    }

    @Test func cinvAliasFromCsinvRnEqualRmNonXZR() {
        let d = decode(0xDA81_0020, at: 0)
        #expect(d.mnemonic == .cinv)
        if case let .register(reg) = d.operands[1] {
            #expect(reg.canonicalIndex == 1)
        }
    }

    @Test func cnegAliasFromCsnegRnEqualRm() {
        let d = decode(0xDA81_0420, at: 0)
        #expect(d.mnemonic == .cneg)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1)), .conditionCode(.ne)])
    }

    @Test func cnegAllowsRnEqualXZR() {
        let d = decode(0xDA9F_07E0, at: 0)
        #expect(d.mnemonic == .cneg)
        if case let .register(reg) = d.operands[1] {
            #expect(reg.isZeroRegister)
        }
    }

    @Test func cincDoesNotTriggerForCsincWithRnRmXZRAtCondInvertable() {
        let d = decode(0x9A9F_07E0, at: 0)
        #expect(d.mnemonic == .cset, "CSET takes precedence over CINC at Rn=Rm=31")
    }

    @Test func csetSuppressedAtALCondition() {
        let d = decode(0x9A9F_E7E0, at: 0)
        #expect(d.mnemonic == .csinc)
        if case let .conditionCode(c) = d.operands[3] {
            #expect(c == .al, "base mnemonic keeps original cond")
        }
    }

    @Test func csetSuppressedAtNVCondition() {
        let d = decode(0x9A9F_F7E0, at: 0)
        #expect(d.mnemonic == .csinc)
    }

    @Test func csetmSuppressedAtALCondition() {
        let d = decode(0xDA9F_E3E0, at: 0)
        #expect(d.mnemonic == .csinv)
    }

    @Test func csetmSuppressedAtNVCondition() {
        let d = decode(0xDA9F_F3E0, at: 0)
        #expect(d.mnemonic == .csinv)
    }

    @Test func cincSuppressedAtALCondition() {
        let d = decode(0x9A81_E420, at: 0)
        #expect(d.mnemonic == .csinc)
    }

    @Test func cincSuppressedAtNVCondition() {
        let d = decode(0x9A81_F420, at: 0)
        #expect(d.mnemonic == .csinc)
    }

    @Test func cinvSuppressedAtALCondition() {
        let d = decode(0xDA81_E020, at: 0)
        #expect(d.mnemonic == .csinv)
    }

    @Test func cinvSuppressedAtNVCondition() {
        let d = decode(0xDA81_F020, at: 0)
        #expect(d.mnemonic == .csinv)
    }

    @Test func cnegSuppressedAtALCondition() {
        let d = decode(0xDA81_E420, at: 0)
        #expect(d.mnemonic == .csneg)
    }

    @Test func cnegSuppressedAtNVCondition() {
        let d = decode(0xDA81_F420, at: 0)
        #expect(d.mnemonic == .csneg)
    }

    @Test func cincRequiresRnNotXZR() {
        let d = decode(0x9A81_0420, at: 0)
        #expect(d.mnemonic == .cinc)
        if case let .register(reg) = d.operands[1] {
            #expect(reg.isZeroRegister == false)
        }
    }

    @Test func baseCselWhenRnRmDiffer() {
        let d = decode(0x9A82_0020, at: 0)
        #expect(d.mnemonic == .csel)
    }

    @Test func sBitSetReturnsUndefined() {
        let d = decode(0x9A82_0020 | (1 << 29), at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func op2EqualsTwoReturnsUndefined() {
        let d = decode(0x9A82_0820, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func op2EqualsThreeReturnsUndefined() {
        let d = decode(0x9A82_0C20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func everyConditionCodeBranches() {
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
