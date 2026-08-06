// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates data-processing 1-source decode and its reserved encodings.
@Suite("DPR / 1-source data processing")
struct DPR1SourceTests {
    @Test func rbit64Bit() {
        let d = decode(0xDAC0_0020, at: 0)
        #expect(d.mnemonic == .rbit)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1))])
    }

    @Test func rbit32Bit() {
        let d = decode(0x5AC0_0020, at: 0)
        #expect(d.mnemonic == .rbit)
        #expect(d.operands[0] == .register(.w(0)))
    }

    @Test func rev16_64Bit() {
        let d = decode(0xDAC0_0420, at: 0)
        #expect(d.mnemonic == .rev16)
    }

    @Test func revAtSf0() {
        let d = decode(0x5AC0_0820, at: 0)
        #expect(d.mnemonic == .rev)
    }

    @Test func rev32AtSf1() {
        let d = decode(0xDAC0_0820, at: 0)
        #expect(d.mnemonic == .rev32)
    }

    @Test func revAtSf1() {
        let d = decode(0xDAC0_0C20, at: 0)
        #expect(d.mnemonic == .rev)
    }

    @Test func opc011AtSf0ReturnsUndefined() {
        let d = decode(0x5AC0_0C20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func clz() {
        let d = decode(0xDAC0_1020, at: 0)
        #expect(d.mnemonic == .clz)
    }

    @Test func cls() {
        let d = decode(0xDAC0_1420, at: 0)
        #expect(d.mnemonic == .cls)
    }

    @Test func opcode2NonZeroReturnsUndefined() {
        let d = decode(0xDAC2_0020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func pacStandaloneOpc6_001100ReturnsUndefined() {
        let d = decode(0xDAC0_3020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func pacStandaloneOpc6_001111ReturnsUndefined() {
        let d = decode(0xDAC0_3C20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func opc6_001000DecodesCsscAbs() {
        let d = decode(0xDAC0_2020, at: 0)
        #expect(d.mnemonic == .abs)
    }

    @Test func opc6_000110DecodesCsscCtz() {
        let d = decode(0xDAC0_1820, at: 0)
        #expect(d.mnemonic == .ctz)
    }

    @Test func unallocated1SourceOpc6RangeIsUndefined() {
        for opc6: UInt32 in 0b001001 ... 0b001111 {
            let encoding: UInt32 = 0xDAC0_0020 | (opc6 << 10)
            let d = decode(encoding, at: 0)
            #expect(d.mnemonic == .undefined, "opc6=\(String(opc6, radix: 2)) must be undefined")
            #expect(d.encoding == encoding, "encoding must be preserved verbatim")
        }
    }

    @Test func csscCntDecodesAsScalarPopulationCount() {
        let d = decode(0xDAC0_1C20, at: 0)
        #expect(d.mnemonic == .cnt)
        #expect(d.category == .dataProcessingRegister)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1))])
        #expect(d.semanticReads.contains(.x(1)))
        #expect(d.semanticWrites.contains(.x(0)))
        #expect(d.text == "cnt x0, x1")
    }
}
