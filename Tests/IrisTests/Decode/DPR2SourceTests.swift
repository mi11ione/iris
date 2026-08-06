// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the 2-source family and CRC32 with their reserved-field rules;
/// variable-shift forms always canonicalize to the DPI mnemonics.
@Suite("DPR / 2-source + CRC32")
struct DPR2SourceTests {
    @Test func udiv64Bit() {
        let d = decode(0x9AC2_0820, at: 0)
        #expect(d.mnemonic == .udiv)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1)), .register(.x(2))])
    }

    @Test func udiv32Bit() {
        let d = decode(0x1AC2_0820, at: 0)
        #expect(d.mnemonic == .udiv)
        #expect(d.operands[0] == .register(.w(0)))
    }

    @Test func sdiv64Bit() {
        let d = decode(0x9AC2_0C20, at: 0)
        #expect(d.mnemonic == .sdiv)
    }

    @Test func lslvCanonicalisesToLsl() {
        let d = decode(0x9AC2_2020, at: 0)
        #expect(d.mnemonic == .lsl)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1)), .register(.x(2))])
    }

    @Test func lsrvCanonicalisesToLsr() {
        let d = decode(0x9AC2_2420, at: 0)
        #expect(d.mnemonic == .lsr)
    }

    @Test func asrvCanonicalisesToAsr() {
        let d = decode(0x9AC2_2820, at: 0)
        #expect(d.mnemonic == .asr)
    }

    @Test func rorvCanonicalisesToRor() {
        let d = decode(0x9AC2_2C20, at: 0)
        #expect(d.mnemonic == .ror)
    }

    @Test func crc32bSf0() {
        let d = decode(0x1AC2_4020, at: 0)
        #expect(d.mnemonic == .crc32b)
        #expect(Array(d.operands) == [.register(.w(0)), .register(.w(1)), .register(.w(2))])
    }

    @Test func crc32hSf0() {
        let d = decode(0x1AC2_4420, at: 0)
        #expect(d.mnemonic == .crc32h)
    }

    @Test func crc32wSf0() {
        let d = decode(0x1AC2_4820, at: 0)
        #expect(d.mnemonic == .crc32w)
    }

    @Test func crc32xSf1WithMixedWidth() {
        let d = decode(0x9AC2_4C20, at: 0)
        #expect(d.mnemonic == .crc32x)
        #expect(Array(d.operands) == [.register(.w(0)), .register(.w(1)), .register(.x(2))])
    }

    @Test func crc32cbSf0() {
        let d = decode(0x1AC2_5020, at: 0)
        #expect(d.mnemonic == .crc32cb)
    }

    @Test func crc32chSf0() {
        let d = decode(0x1AC2_5420, at: 0)
        #expect(d.mnemonic == .crc32ch)
    }

    @Test func crc32cwSf0() {
        let d = decode(0x1AC2_5820, at: 0)
        #expect(d.mnemonic == .crc32cw)
    }

    @Test func crc32cxSf1() {
        let d = decode(0x9AC2_5C20, at: 0)
        #expect(d.mnemonic == .crc32cx)
    }

    @Test func crc32bAtSf1ReturnsUndefined() {
        let d = decode(0x9AC2_4020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func crc32xAtSf0ReturnsUndefined() {
        let d = decode(0x1AC2_4C20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func sBitSetReturnsUndefined() {
        let d = decode(0x9AC2_0820 | (1 << 29), at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func undefinedOpc6ReturnsUndefined() {
        let d = decode(0x9AC2_0420, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func opc6_000111GapReturnsUndefined() {
        let d = decode(0x9AC2_1C20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func opc6_010100ButSf1ReturnsUndefined() {
        let d = decode(0x9AC2_5020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func crc32hAtSf1ReturnsUndefined() {
        let d = decode(0x9AC2_4420, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func crc32wAtSf1ReturnsUndefined() {
        let d = decode(0x9AC2_4820, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func crc32chAtSf1ReturnsUndefined() {
        let d = decode(0x9AC2_5420, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func crc32cwAtSf1ReturnsUndefined() {
        let d = decode(0x9AC2_5820, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func crc32cxAtSf0ReturnsUndefined() {
        let d = decode(0x1AC2_5C20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func csscMinMaxRegisterFormsDecodeAtBothWidths() {
        let rows: [(word: UInt32, mnemonic: Mnemonic, text: String)] = [
            (0x9AC2_6020, .smax, "smax x0, x1, x2"),
            (0x9AC2_6420, .umax, "umax x0, x1, x2"),
            (0x9AC2_6820, .smin, "smin x0, x1, x2"),
            (0x9AC2_6C20, .umin, "umin x0, x1, x2"),
            (0x1AC2_6020, .smax, "smax w0, w1, w2"),
        ]
        for row in rows {
            let d = decode(row.word, at: 0)
            #expect(d.mnemonic == row.mnemonic)
            #expect(d.category == .dataProcessingRegister)
            #expect(d.semanticReads.contains(.x(1)) && d.semanticReads.contains(.x(2)))
            #expect(d.semanticWrites.contains(.x(0)))
            #expect(d.text == row.text)
        }
    }
}
