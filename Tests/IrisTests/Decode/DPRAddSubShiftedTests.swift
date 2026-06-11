// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates ADD/ADDS/SUB/SUBS shifted-register decode + CMP/CMN/NEG/NEGS
/// alias precedence (shifted half) and the reserved-shift / reserved-bit
/// edge cases. Pins encoding → mnemonic + operand-tuple + flagEffect +
/// reads/writes.
@Suite("DPR / Add/Sub shifted-register")
struct DPRAddSubShiftedTests {
    @Test func baseAdd64Bit() {
        // ADD x0, x1, x2 — sf=1, op=0, S=0, shift=LSL, imm6=0.
        let d = decode(0x8B02_0020, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.flagEffect == .none)
        #expect(d.category == .dataProcessingRegister)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1)), .register(.x(2))])
        #expect(d.semanticReads.contains(.x(1)))
        #expect(d.semanticReads.contains(.x(2)))
        #expect(d.semanticWrites.contains(.x(0)))
    }

    @Test func baseAdd32Bit() {
        // ADD w0, w1, w2 — sf=0.
        let d = decode(0x0B02_0020, at: 0)
        #expect(d.mnemonic == .add)
        #expect(Array(d.operands) == [.register(.w(0)), .register(.w(1)), .register(.w(2))])
    }

    @Test func baseSub64Bit() {
        // SUB x0, x1, x2 — op=1.
        let d = decode(0xCB02_0020, at: 0)
        #expect(d.mnemonic == .sub)
        #expect(d.flagEffect == .none)
    }

    @Test func addsSetsNzcv() {
        // ADDS x0, x1, x2 — S=1.
        let d = decode(0xAB02_0020, at: 0)
        #expect(d.mnemonic == .adds)
        #expect(d.flagEffect == .nzcv)
    }

    @Test func subsSetsNzcv() {
        // SUBS x0, x1, x2.
        let d = decode(0xEB02_0020, at: 0)
        #expect(d.mnemonic == .subs)
        #expect(d.flagEffect == .nzcv)
    }

    @Test func addWithLslShiftEmitsShiftedRegister() {
        // ADD x0, x1, x2, LSL #3 — shift=LSL, imm6=3.
        let d = decode(0x8B02_0C20, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.operands[2] == .shiftedRegister(reg: .x(2), shift: .lsl, amount: 3))
    }

    @Test func addWithLsrShiftEmitsShiftedRegister() {
        // ADD x0, x1, x2, LSR #3 — shift=LSR.
        let d = decode(0x8B42_0C20, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.operands[2] == .shiftedRegister(reg: .x(2), shift: .lsr, amount: 3))
    }

    @Test func addWithAsrShiftEmitsShiftedRegister() {
        // ADD x0, x1, x2, ASR #3 — shift=ASR.
        let d = decode(0x8B82_0C20, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.operands[2] == .shiftedRegister(reg: .x(2), shift: .asr, amount: 3))
    }

    @Test func addWithRorShiftReturnsUndefined() {
        // ROR shift (shift=11) is reserved for arithmetic add/sub.
        let d = decode(0x8BC2_0020, at: 0)
        #expect(d.mnemonic == .undefined)
        #expect(d.encoding == 0x8BC2_0020)
    }

    @Test func add32BitImm6High5SetReturnsUndefined() {
        // sf=0 + imm6[5]=1 is reserved.
        let d = decode(0x0B02_8020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func add64BitImm6FullRangeAccepted() {
        // sf=1 allows imm6 up to 63 — no reserved violation at top end.
        let d = decode(0x8B02_FC20, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.operands[2] == .shiftedRegister(reg: .x(2), shift: .lsl, amount: 63))
    }

    @Test func cmpAliasDropsRdFromOperandList() {
        // SUBS xzr, x1, x2 → CMP x1, x2 (Rd=31, S=1, op=1).
        let d = decode(0xEB02_003F, at: 0)
        #expect(d.mnemonic == .cmp)
        #expect(Array(d.operands) == [.register(.x(1)), .register(.x(2))])
        #expect(d.flagEffect == .nzcv)
        #expect(d.semanticWrites == .empty, "Rd=XZR dropped from writes")
    }

    @Test func cmnAliasDropsRdFromOperandList() {
        // ADDS xzr, x1, x2 → CMN x1, x2 (Rd=31, S=1, op=0).
        let d = decode(0xAB02_003F, at: 0)
        #expect(d.mnemonic == .cmn)
        #expect(Array(d.operands) == [.register(.x(1)), .register(.x(2))])
        #expect(d.flagEffect == .nzcv)
    }

    @Test func cmpWithShiftKeepsShiftOperand() {
        // SUBS xzr, x1, x2, LSL #5 → CMP x1, x2, LSL #5.
        let d = decode(0xEB02_143F, at: 0)
        #expect(d.mnemonic == .cmp)
        #expect(d.operands[1] == .shiftedRegister(reg: .x(2), shift: .lsl, amount: 5))
    }

    @Test func negAliasDropsRnFromOperandList() {
        // SUB x0, xzr, x1 → NEG x0, x1 (Rn=31, S=0, op=1).
        let d = decode(0xCB01_03E0, at: 0)
        #expect(d.mnemonic == .neg)
        #expect(d.flagEffect == .none)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1))])
    }

    @Test func negsAliasFlagSetting() {
        // SUBS x0, xzr, x1 → NEGS x0, x1.
        let d = decode(0xEB01_03E0, at: 0)
        #expect(d.mnemonic == .negs)
        #expect(d.flagEffect == .nzcv)
    }

    @Test func negWithShiftKeepsShiftOperand() {
        // SUB x0, xzr, x1, LSL #3 → NEG x0, x1, LSL #3.
        let d = decode(0xCB01_0FE0, at: 0)
        #expect(d.mnemonic == .neg)
        #expect(d.operands[1] == .shiftedRegister(reg: .x(1), shift: .lsl, amount: 3))
    }

    @Test func cmpAlias32Bit() {
        // SUBS wzr, w1, w2 → CMP w1, w2.
        let d = decode(0x6B02_003F, at: 0)
        #expect(d.mnemonic == .cmp)
        #expect(Array(d.operands) == [.register(.w(1)), .register(.w(2))])
    }

    @Test func addRn31IsTreatedAsXZRNotSP() {
        // For shifted-register arithmetic, encoding-31 means
        // ZR (not SP). ADD x0, xzr, x2 is a valid (if odd) instruction.
        let d = decode(0x8B02_03E0, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.operands[1] == .register(.xzr()))
    }

    @Test func subsRdNotXZRStaysAsBaseSubs() {
        // SUBS x1, x3, x5 — Rd != 31 → no CMP alias.
        let d = decode(0xEB05_0061, at: 0)
        #expect(d.mnemonic == .subs)
        #expect(Array(d.operands) == [.register(.x(1)), .register(.x(3)), .register(.x(5))])
    }

    @Test func encodingAndAddressArePropagated() {
        let d = decode(0x8B02_0020, at: 0xCAFE)
        #expect(d.encoding == 0x8B02_0020)
        #expect(d.address == 0xCAFE)
    }
}
