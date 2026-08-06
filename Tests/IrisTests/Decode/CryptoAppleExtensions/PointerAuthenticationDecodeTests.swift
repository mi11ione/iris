// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the PAC standalone decoder across the 1-source, zero-source, XPAC
/// and PACGA rows.
@Suite("CryptoAppleExtensions / PointerAuthenticationDecode")
struct PointerAuthenticationDecodeTests {
    @Test func paciaRegisterSource() {
        let d = decode(0xDAC1_0020, at: 0)
        #expect(d.mnemonic == .pacia)
        #expect(d.category == .pointerAuthentication)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1))])
    }

    @Test func pacibRegisterSource() {
        let d = decode(0xDAC1_0420, at: 0)
        #expect(d.mnemonic == .pacib)
    }

    @Test func pacdaRegisterSource() {
        let d = decode(0xDAC1_0820, at: 0)
        #expect(d.mnemonic == .pacda)
    }

    @Test func pacdbRegisterSource() {
        let d = decode(0xDAC1_0C20, at: 0)
        #expect(d.mnemonic == .pacdb)
    }

    @Test func autiaRegisterSource() {
        let d = decode(0xDAC1_1020, at: 0)
        #expect(d.mnemonic == .autia)
        #expect(d.semanticReads.contains(.x(0)) == true)
        #expect(d.semanticReads.contains(.x(1)) == true)
    }

    @Test func autibRegisterSource() {
        let d = decode(0xDAC1_1420, at: 0)
        #expect(d.mnemonic == .autib)
    }

    @Test func autdaRegisterSource() {
        let d = decode(0xDAC1_1820, at: 0)
        #expect(d.mnemonic == .autda)
    }

    @Test func autdbRegisterSource() {
        let d = decode(0xDAC1_1C20, at: 0)
        #expect(d.mnemonic == .autdb)
    }

    @Test func paciaWithRnEqualXZRStaysAsPaciaNotPaciza() {
        let d = decode(0xDAC1_03E0, at: 0)
        #expect(d.mnemonic == .pacia)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.sp())])
        #expect(d.text == "pacia x0, sp")
    }

    @Test func pacizaZeroSource() {
        let d = decode(0xDAC1_23E0, at: 0)
        #expect(d.mnemonic == .paciza)
        #expect(d.category == .pointerAuthentication)
        #expect(Array(d.operands) == [.register(.x(0))])
    }

    @Test func pacizbZeroSource() {
        let d = decode(0xDAC1_27E0, at: 0)
        #expect(d.mnemonic == .pacizb)
    }

    @Test func pacdzaZeroSource() {
        let d = decode(0xDAC1_2BE0, at: 0)
        #expect(d.mnemonic == .pacdza)
    }

    @Test func pacdzbZeroSource() {
        let d = decode(0xDAC1_2FE0, at: 0)
        #expect(d.mnemonic == .pacdzb)
    }

    @Test func autizaZeroSource() {
        let d = decode(0xDAC1_33E0, at: 0)
        #expect(d.mnemonic == .autiza)
        #expect(d.semanticReads.contains(.x(0)) == true)
    }

    @Test func autizbZeroSource() {
        let d = decode(0xDAC1_37E0, at: 0)
        #expect(d.mnemonic == .autizb)
    }

    @Test func autdzaZeroSource() {
        let d = decode(0xDAC1_3BE0, at: 0)
        #expect(d.mnemonic == .autdza)
    }

    @Test func autdzbZeroSource() {
        let d = decode(0xDAC1_3FE0, at: 0)
        #expect(d.mnemonic == .autdzb)
    }

    @Test func zeroSourceWithRnNotXZRReturnsNil() {
        let d = decode(0xDAC1_2020, at: 0)
        #expect(d.category != .pointerAuthentication)
    }

    @Test func xpaciStripsInstructionPointer() {
        let d = decode(0xDAC1_43E0, at: 0)
        #expect(d.mnemonic == .xpaci)
        #expect(Array(d.operands) == [.register(.x(0))])
        #expect(d.semanticReads.contains(.x(0)) == true)
        #expect(d.semanticWrites.contains(.x(0)) == true)
    }

    @Test func xpacdStripsDataPointer() {
        let d = decode(0xDAC1_47E0, at: 0)
        #expect(d.mnemonic == .xpacd)
    }

    @Test func xpaciWithRnNotXZRReturnsNil() {
        let d = decode(0xDAC1_4020, at: 0)
        #expect(d.category != .pointerAuthentication)
    }

    @Test func xpacdWithRnNotXZRReturnsNil() {
        let d = decode(0xDAC1_4420, at: 0)
        #expect(d.category != .pointerAuthentication)
    }

    @Test func wrongTopPrefixReturnsNil() {
        #expect(decode(0x5AC1_0020, at: 0).category != .pointerAuthentication)
        #expect(decode(0xDAC0_0020, at: 0).category != .pointerAuthentication)
        #expect(decode(0xDAC2_0020, at: 0).category != .pointerAuthentication)
        #expect(decode(0xFAC1_0020, at: 0).category != .pointerAuthentication)
    }

    @Test func opc6AboveReservedXPACRangeReturnsNil() {
        let encoding: UInt32 = 0xDAC1_0000 | (0b010010 << 10) | (0b11111 << 5)
        let d = decode(encoding, at: 0)
        #expect(d.category != .pointerAuthentication)
    }

    @Test func pacgaDecodesCorrectly() {
        let d = decode(0x9AC2_3020, at: 0)
        #expect(d.mnemonic == .pacga)
        #expect(d.category == .pointerAuthentication)
        #expect(d.operands.count == 3)
    }

    @Test func pacgaReadsRnAndRm() {
        let d = decode(0x9AC2_3020, at: 0)
        #expect(d.semanticReads.contains(.x(1)) == true)
        #expect(d.semanticReads.contains(.x(2)) == true)
        #expect(d.semanticWrites.contains(.x(0)) == true)
    }

    @Test func pacgaWithWrongOpc6ReturnsNil() {
        let encoding: UInt32 = 0x9AC2_0000 | (0b010000 << 10)
        let d = decode(encoding, at: 0)
        #expect(d.category != .pointerAuthentication)
    }

    @Test func pacgaWithWrongPrefixReturnsNil() {
        #expect(decode(0x1AC2_3020, at: 0).category != .pointerAuthentication)
        #expect(decode(0xDAC2_3020, at: 0).category != .pointerAuthentication)
    }
}
