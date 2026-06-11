// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates CCMP/CCMN register-form and immediate-form decode.
/// Exercises every fixed-field reserved path: S != 1, o3 != 0,
/// o2 ∈ {01, 11}.
@Suite("DPR / Conditional compare")
struct DPRCondCompareTests {
    @Test func ccmpRegisterForm64Bit() {
        // CCMP x1, x2, #5, EQ — register form, o2=00. Rn=1, Rm=2.
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
        // CCMP x1, #0, #5, EQ — immediate form, o2=10.
        let d = decode(0xFA40_0825, at: 0)
        #expect(d.mnemonic == .ccmp)
        #expect(d.operands[0] == .register(.x(1)))
        #expect(d.operands[1] == .unsignedImmediate(value: 0, width: 5))
        #expect(d.operands[2] == .unsignedImmediate(value: 5, width: 4))
        #expect(d.operands[3] == .conditionCode(.eq))
    }

    @Test func ccmnRegisterForm() {
        // CCMN x1, x2, #5, NE — op=0.
        let d = decode(0xBA42_1045, at: 0)
        #expect(d.mnemonic == .ccmn)
        #expect(d.flagEffect == [.nzcv, .readsNZCV])
    }

    @Test func ccmnImmediateForm() {
        // CCMN x1, #1, #2, GT.
        let d = decode(0xBA41_C822, at: 0)
        #expect(d.mnemonic == .ccmn)
        if case let .unsignedImmediate(value, width) = d.operands[1] {
            #expect(value == 1)
            #expect(width == 5)
        }
    }

    @Test func ccmp32BitWidth() {
        // CCMP w1, w2, #5, EQ — Rn=1, Rm=2.
        let d = decode(0x7A42_0025, at: 0)
        #expect(d.mnemonic == .ccmp)
        #expect(d.operands[0] == .register(.w(1)))
    }

    @Test func everyConditionCodeDecodes() {
        for raw: UInt32 in 0 ... 15 {
            // CCMP x1, x2, #0, <cond>: cond at bits 15:12.
            let encoding: UInt32 = 0xFA42_0020 | (raw << 12)
            let d = decode(encoding, at: 0)
            #expect(d.mnemonic == .ccmp)
            if case let .conditionCode(c) = d.operands[3] {
                #expect(c.rawValue == UInt8(raw))
            }
        }
    }

    @Test func sNotOneReturnsUndefined() {
        // S=0 is reserved for conditional compare.
        let d = decode(0xFA42_0045 & ~(1 << 29), at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func o3SetReturnsUndefined() {
        // o3 (bit 4) must be 0.
        let d = decode(0xFA42_0045 | (1 << 4), at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func o2EqualsOneReturnsUndefined() {
        // bits 11:10 = 01 reserved.
        let d = decode(0xFA42_0445, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func o2EqualsThreeReturnsUndefined() {
        // bits 11:10 = 11 reserved.
        let d = decode(0xFA42_0C45, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func nzcvFieldDecodesAcrossWholeRange() {
        // nzcv at bits 3:0 — try min, mid, max.
        for nzcv: UInt32 in [0, 5, 15] {
            let encoding: UInt32 = 0xFA42_0040 | nzcv
            let d = decode(encoding, at: 0)
            if case let .unsignedImmediate(value, _) = d.operands[2] {
                #expect(value == UInt64(nzcv))
            }
        }
    }

    @Test func imm5FieldDecodesAcrossWholeRange() {
        // imm5 at bits 20:16 — 0, 1, 31.
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
