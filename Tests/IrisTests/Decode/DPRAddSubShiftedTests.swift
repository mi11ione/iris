// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates shifted-register ADD/SUB with CMP/CMN/NEG/NEGS precedence and the
/// reserved-shift edges, pinning mnemonic, operands, flags and register.
@Suite("DPR / Add/Sub shifted-register")
struct DPRAddSubShiftedTests {
    @Test func baseAdd64Bit() {
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
        let d = decode(0x0B02_0020, at: 0)
        #expect(d.mnemonic == .add)
        #expect(Array(d.operands) == [.register(.w(0)), .register(.w(1)), .register(.w(2))])
    }

    @Test func baseSub64Bit() {
        let d = decode(0xCB02_0020, at: 0)
        #expect(d.mnemonic == .sub)
        #expect(d.flagEffect == .none)
    }

    @Test func addsSetsNzcv() {
        let d = decode(0xAB02_0020, at: 0)
        #expect(d.mnemonic == .adds)
        #expect(d.flagEffect == .nzcv)
    }

    @Test func subsSetsNzcv() {
        let d = decode(0xEB02_0020, at: 0)
        #expect(d.mnemonic == .subs)
        #expect(d.flagEffect == .nzcv)
    }

    @Test func addWithLslShiftEmitsShiftedRegister() {
        let d = decode(0x8B02_0C20, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.operands[2] == .shiftedRegister(reg: .x(2), shift: .lsl, amount: 3))
    }

    @Test func addWithLsrShiftEmitsShiftedRegister() {
        let d = decode(0x8B42_0C20, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.operands[2] == .shiftedRegister(reg: .x(2), shift: .lsr, amount: 3))
    }

    @Test func addWithAsrShiftEmitsShiftedRegister() {
        let d = decode(0x8B82_0C20, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.operands[2] == .shiftedRegister(reg: .x(2), shift: .asr, amount: 3))
    }

    @Test func addWithRorShiftReturnsUndefined() {
        let d = decode(0x8BC2_0020, at: 0)
        #expect(d.mnemonic == .undefined)
        #expect(d.encoding == 0x8BC2_0020)
    }

    @Test func add32BitImm6High5SetReturnsUndefined() {
        let d = decode(0x0B02_8020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func add64BitImm6FullRangeAccepted() {
        let d = decode(0x8B02_FC20, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.operands[2] == .shiftedRegister(reg: .x(2), shift: .lsl, amount: 63))
    }

    @Test func cmpAliasDropsRdFromOperandList() {
        let d = decode(0xEB02_003F, at: 0)
        #expect(d.mnemonic == .cmp)
        #expect(Array(d.operands) == [.register(.x(1)), .register(.x(2))])
        #expect(d.flagEffect == .nzcv)
        #expect(d.semanticWrites == .empty, "Rd=XZR dropped from writes")
    }

    @Test func cmnAliasDropsRdFromOperandList() {
        let d = decode(0xAB02_003F, at: 0)
        #expect(d.mnemonic == .cmn)
        #expect(Array(d.operands) == [.register(.x(1)), .register(.x(2))])
        #expect(d.flagEffect == .nzcv)
    }

    @Test func cmpWithShiftKeepsShiftOperand() {
        let d = decode(0xEB02_143F, at: 0)
        #expect(d.mnemonic == .cmp)
        #expect(d.operands[1] == .shiftedRegister(reg: .x(2), shift: .lsl, amount: 5))
    }

    @Test func negAliasDropsRnFromOperandList() {
        let d = decode(0xCB01_03E0, at: 0)
        #expect(d.mnemonic == .neg)
        #expect(d.flagEffect == .none)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1))])
    }

    @Test func negsAliasFlagSetting() {
        let d = decode(0xEB01_03E0, at: 0)
        #expect(d.mnemonic == .negs)
        #expect(d.flagEffect == .nzcv)
    }

    @Test func negWithShiftKeepsShiftOperand() {
        let d = decode(0xCB01_0FE0, at: 0)
        #expect(d.mnemonic == .neg)
        #expect(d.operands[1] == .shiftedRegister(reg: .x(1), shift: .lsl, amount: 3))
    }

    @Test func cmpAlias32Bit() {
        let d = decode(0x6B02_003F, at: 0)
        #expect(d.mnemonic == .cmp)
        #expect(Array(d.operands) == [.register(.w(1)), .register(.w(2))])
    }

    @Test func addRn31IsTreatedAsXZRNotSP() {
        let d = decode(0x8B02_03E0, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.operands[1] == .register(.xzr()))
    }

    @Test func subsRdNotXZRStaysAsBaseSubs() {
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
