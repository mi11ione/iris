// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates CCMP/CCMN register and immediate forms, exercising every reserved
/// path.
@Suite("DPR / Conditional compare")
struct DPRCondCompareTests {
    @Test func ccmpRegisterForm64Bit() {
        let d = decode(0xFA42_0025, at: 0)
        #expect(d.mnemonic == .ccmp)
        #expect(d.flagEffect == [.nzcv, .readsNZCV])
        #expect(d.operands.count == 4)
        #expect(d.operands[0] == .register(.x(1)))
        #expect(d.operands[1] == .register(.x(2)))
        #expect(d.operands[2] == .unsignedImmediate(value: 5, width: 4))
        #expect(d.operands[3] == .conditionCode(.eq))
    }

    @Test func ccmpImmediateForm64Bit() {
        let d = decode(0xFA40_0825, at: 0)
        #expect(d.mnemonic == .ccmp)
        #expect(d.operands[0] == .register(.x(1)))
        #expect(d.operands[1] == .unsignedImmediate(value: 0, width: 5))
        #expect(d.operands[2] == .unsignedImmediate(value: 5, width: 4))
        #expect(d.operands[3] == .conditionCode(.eq))
    }

    @Test func ccmnRegisterForm() {
        let d = decode(0xBA42_1045, at: 0)
        #expect(d.mnemonic == .ccmn)
        #expect(d.flagEffect == [.nzcv, .readsNZCV])
    }

    @Test func ccmnImmediateForm() {
        let d = decode(0xBA41_C822, at: 0)
        #expect(d.mnemonic == .ccmn)
        if case let .unsignedImmediate(value, width) = d.operands[1] {
            #expect(value == 1)
            #expect(width == 5)
        }
    }

    @Test func ccmp32BitWidth() {
        let d = decode(0x7A42_0025, at: 0)
        #expect(d.mnemonic == .ccmp)
        #expect(d.operands[0] == .register(.w(1)))
    }

    @Test func everyConditionCodeDecodes() {
        for raw: UInt32 in 0 ... 15 {
            let encoding: UInt32 = 0xFA42_0020 | (raw << 12)
            let d = decode(encoding, at: 0)
            #expect(d.mnemonic == .ccmp)
            if case let .conditionCode(c) = d.operands[3] {
                #expect(c.rawValue == UInt8(raw))
            }
        }
    }

    @Test func sNotOneReturnsUndefined() {
        let d = decode(0xFA42_0045 & ~(1 << 29), at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func o3SetReturnsUndefined() {
        let d = decode(0xFA42_0045 | (1 << 4), at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func o2EqualsOneReturnsUndefined() {
        let d = decode(0xFA42_0445, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func o2EqualsThreeReturnsUndefined() {
        let d = decode(0xFA42_0C45, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func nzcvFieldDecodesAcrossWholeRange() {
        for nzcv: UInt32 in [0, 5, 15] {
            let encoding: UInt32 = 0xFA42_0040 | nzcv
            let d = decode(encoding, at: 0)
            if case let .unsignedImmediate(value, _) = d.operands[2] {
                #expect(value == UInt64(nzcv))
            }
        }
    }

    @Test func imm5FieldDecodesAcrossWholeRange() {
        for imm5: UInt32 in [0, 1, 31] {
            let encoding: UInt32 = 0xFA40_0820 | (imm5 << 16)
            let d = decode(encoding, at: 0)
            if case let .unsignedImmediate(value, width) = d.operands[1] {
                #expect(value == UInt64(imm5))
                #expect(width == 5)
            }
        }
    }
}
