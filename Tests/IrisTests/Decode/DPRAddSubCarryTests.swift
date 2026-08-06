// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates ADC/ADCS/SBC/SBCS with NGC/NGCS aliases; the opcode2 != 0 guard
/// doubles as the FlagM gate.
@Suite("DPR / Add/Sub with carry")
struct DPRAddSubCarryTests {
    @Test func baseAdc64Bit() {
        let d = decode(0x9A02_0020, at: 0)
        #expect(d.mnemonic == .adc)
        #expect(d.flagEffect == .readsC)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1)), .register(.x(2))])
    }

    @Test func baseAdcs64BitSetsNzcv() {
        let d = decode(0xBA02_0020, at: 0)
        #expect(d.mnemonic == .adcs)
        #expect(d.flagEffect == [.nzcv, .readsC])
    }

    @Test func baseSbc64Bit() {
        let d = decode(0xDA02_0020, at: 0)
        #expect(d.mnemonic == .sbc)
    }

    @Test func baseSbcs64BitSetsNzcv() {
        let d = decode(0xFA02_0020, at: 0)
        #expect(d.mnemonic == .sbcs)
        #expect(d.flagEffect == [.nzcv, .readsC])
    }

    @Test func base32BitWidthAtSf0() {
        let d = decode(0x1A02_0020, at: 0)
        #expect(d.mnemonic == .adc)
        #expect(Array(d.operands) == [.register(.w(0)), .register(.w(1)), .register(.w(2))])
    }

    @Test func ngcAliasDropsRn() {
        let d = decode(0xDA01_03E0, at: 0)
        #expect(d.mnemonic == .ngc)
        #expect(d.flagEffect == .readsC)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1))])
        #expect(d.semanticReads.contains(.x(1)))
    }

    @Test func ngcsAliasFlagSetting() {
        let d = decode(0xFA01_03E0, at: 0)
        #expect(d.mnemonic == .ngcs)
        #expect(d.flagEffect == [.nzcv, .readsC])
    }

    @Test func adcDoesNotAliasNgcEvenWithRn31() {
        let d = decode(0x9A01_03E0, at: 0)
        #expect(d.mnemonic == .adc)
    }

    @Test func opcode2NonZeroReturnsUndefined() {
        let d = decode(0x9A02_0420, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func rmifMaskZeroDecodesAndWritesNoFlags() {
        let d = decode(0xBA00_0400, at: 0)
        #expect(d.mnemonic == .rmif)
        #expect(d.flagEffect == .none)
    }

    @Test func rmifFullMaskWritesAllFourFlags() {
        let d = decode(0xBA01_842F, at: 0)
        #expect(d.mnemonic == .rmif)
        #expect(d.flagEffect == [.writesN, .writesZ, .writesC, .writesV])
        #expect(d.text == "rmif x1, #3, #15")
    }

    @Test func setf8AndSetf16DecodeAndSetNZV() {
        let f8 = decode(0x3A00_082D, at: 0)
        #expect(f8.mnemonic == .setf8)
        #expect(f8.category == .dataProcessingRegister)
        #expect(Array(f8.operands) == [.register(.w(1))])
        #expect(f8.flagEffect == [.writesN, .writesZ, .writesV])
        #expect(f8.semanticReads.contains(.w(1)))
        #expect(f8.semanticWrites.isEmpty)
        #expect(f8.text == "setf8 w1")
        let f16 = decode(0x3A00_482D, at: 0)
        #expect(f16.mnemonic == .setf16)
        #expect(f16.text == "setf16 w1")
    }

    @Test func addptAndSubptDecodeWithOptionalShift() {
        let addpt = decode(0x9A02_2020, at: 0)
        #expect(addpt.mnemonic == .addpt)
        #expect(addpt.category == .dataProcessingRegister)
        #expect(Array(addpt.operands) == [
            .register(.x(0)), .register(.x(1)), .register(.x(2)),
        ])
        #expect(addpt.semanticReads.contains(.x(1)) && addpt.semanticReads.contains(.x(2)))
        #expect(addpt.semanticWrites.contains(.x(0)))
        #expect(addpt.flagEffect == FlagEffect.none)
        #expect(addpt.text == "addpt x0, x1, x2")
        let subpt = decode(0xDA02_2820, at: 0)
        #expect(subpt.mnemonic == .subpt)
        #expect(Array(subpt.operands) == [
            .register(.x(0)), .register(.x(1)),
            .shiftedRegister(reg: .x(2), shift: .lsl, amount: 2),
        ])
        #expect(subpt.text == "subpt x0, x1, x2, lsl #2")
    }
}
