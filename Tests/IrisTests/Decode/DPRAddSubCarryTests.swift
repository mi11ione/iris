// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates ADC/ADCS/SBC/SBCS decode + NGC/NGCS alias
/// + the reserved opcode2 != 0 tier. The opcode2 != 0 guard also acts
/// as the FlagM (RMIF/SETF8/SETF16) gate.
@Suite("DPR / Add/Sub with carry")
struct DPRAddSubCarryTests {
    @Test func baseAdc64Bit() {
        // ADC x0, x1, x2.
        let d = decode(0x9A02_0020, at: 0)
        #expect(d.mnemonic == .adc)
        #expect(d.flagEffect == .readsC)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1)), .register(.x(2))])
    }

    @Test func baseAdcs64BitSetsNzcv() {
        // ADCS x0, x1, x2.
        let d = decode(0xBA02_0020, at: 0)
        #expect(d.mnemonic == .adcs)
        #expect(d.flagEffect == [.nzcv, .readsC])
    }

    @Test func baseSbc64Bit() {
        // SBC x0, x1, x2.
        let d = decode(0xDA02_0020, at: 0)
        #expect(d.mnemonic == .sbc)
    }

    @Test func baseSbcs64BitSetsNzcv() {
        // SBCS x0, x1, x2.
        let d = decode(0xFA02_0020, at: 0)
        #expect(d.mnemonic == .sbcs)
        #expect(d.flagEffect == [.nzcv, .readsC])
    }

    @Test func base32BitWidthAtSf0() {
        // ADC w0, w1, w2.
        let d = decode(0x1A02_0020, at: 0)
        #expect(d.mnemonic == .adc)
        #expect(Array(d.operands) == [.register(.w(0)), .register(.w(1)), .register(.w(2))])
    }

    @Test func ngcAliasDropsRn() {
        // SBC x0, xzr, x1 → NGC x0, x1 (op=1, S=0, Rn=31).
        let d = decode(0xDA01_03E0, at: 0)
        #expect(d.mnemonic == .ngc)
        #expect(d.flagEffect == .readsC)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1))])
        #expect(d.semanticReads.contains(.x(1)))
    }

    @Test func ngcsAliasFlagSetting() {
        // SBCS x0, xzr, x1 → NGCS x0, x1 (op=1, S=1, Rn=31).
        let d = decode(0xFA01_03E0, at: 0)
        #expect(d.mnemonic == .ngcs)
        #expect(d.flagEffect == [.nzcv, .readsC])
    }

    @Test func adcDoesNotAliasNgcEvenWithRn31() {
        // ADC x0, xzr, x1 (op=0 + Rn=31) — NGC requires op=1. Stays ADC.
        let d = decode(0x9A01_03E0, at: 0)
        #expect(d.mnemonic == .adc)
    }

    @Test func opcode2NonZeroReturnsUndefined() {
        // opcode2 (bits 15:10) != 0 is reserved. The FlagM ops
        // (RMIF/SETF8/SETF16) land in this space.
        let d = decode(0x9A02_0420, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func rmifMaskZeroDecodesAndWritesNoFlags() {
        // RMIF x0, #0, #0 — FEAT_FlagM, in scope. The imm4 mask is 0, so it
        // selects no flag and writes none.
        let d = decode(0xBA00_0400, at: 0)
        #expect(d.mnemonic == .rmif)
        #expect(d.flagEffect == .none)
    }

    @Test func rmifFullMaskWritesAllFourFlags() {
        // imm4 mask = 1111 selects N, Z, C and V.
        let d = decode(0xBA01_842F, at: 0)
        #expect(d.mnemonic == .rmif)
        #expect(d.flagEffect == [.writesN, .writesZ, .writesC, .writesV])
        #expect(d.text == "rmif x1, #3, #15")
    }

    @Test func setf8AndSetf16DecodeAndSetNZV() {
        // FEAT_FlagM SETF8/SETF16 share the carry tier: read Wn, set
        // N/Z/V from the operand, preserve C, write no GP register.
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
        // FEAT_CPA checked-pointer arithmetic shares the carry tier
        // (sf=1, S=0, bits 15:13 = 001).
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
        // Non-zero amount renders the LSL shift operand.
        let subpt = decode(0xDA02_2820, at: 0)
        #expect(subpt.mnemonic == .subpt)
        #expect(Array(subpt.operands) == [
            .register(.x(0)), .register(.x(1)),
            .shiftedRegister(reg: .x(2), shift: .lsl, amount: 2),
        ])
        #expect(subpt.text == "subpt x0, x1, x2, lsl #2")
    }
}
