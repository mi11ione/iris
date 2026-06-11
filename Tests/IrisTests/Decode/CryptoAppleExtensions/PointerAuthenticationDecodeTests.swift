// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the PAC standalone decoder (DPR 1-source register-source,
/// zero-source, XPAC, and the DPR 2-source PACGA row). Encoding-driven
/// mnemonic selection — PACIA vs PACIZA distinguished by the Z bit, NOT
/// by Rn==XZR.
@Suite("CryptoAppleExtensions / PointerAuthenticationDecode")
struct PointerAuthenticationDecodeTests {
    @Test func paciaRegisterSource() {
        // PACIA x0, x1 = 0xDAC10020.
        let d = decode(0xDAC1_0020, at: 0)
        #expect(d.mnemonic == .pacia)
        #expect(d.category == .pointerAuthentication)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1))])
    }

    @Test func pacibRegisterSource() {
        // PACIB x0, x1 = 0xDAC10420.
        let d = decode(0xDAC1_0420, at: 0)
        #expect(d.mnemonic == .pacib)
    }

    @Test func pacdaRegisterSource() {
        // PACDA x0, x1 = 0xDAC10820.
        let d = decode(0xDAC1_0820, at: 0)
        #expect(d.mnemonic == .pacda)
    }

    @Test func pacdbRegisterSource() {
        // PACDB x0, x1 = 0xDAC10C20.
        let d = decode(0xDAC1_0C20, at: 0)
        #expect(d.mnemonic == .pacdb)
    }

    @Test func autiaRegisterSource() {
        // AUTIA x0, x1 = 0xDAC11020.
        let d = decode(0xDAC1_1020, at: 0)
        #expect(d.mnemonic == .autia)
        // AUT* reads Rd (the authenticated pointer) as well as Rn.
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
        // Critical: PACIA with register-source Rn=XZR(11111) still
        // computes AddPACIA(Xd, SP-semantics), NOT zero. The mnemonic
        // is chosen by the Z bit (bit 13), not by Rn==31. The
        // SP-allowed Rn form must preserve as `sp`, not collapse to
        // `xzr` — the encoded Rn=11111 in a `.spOrGeneral` slot is SP.
        // PACIA x0, sp = 0xDAC1_03E0.
        let d = decode(0xDAC1_03E0, at: 0)
        #expect(d.mnemonic == .pacia)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.sp())])
        #expect(d.text == "pacia x0, sp")
    }

    @Test func pacizaZeroSource() {
        // PACIZA x0 = 0xDAC123E0 (opc6=001000, Rn=11111).
        let d = decode(0xDAC1_23E0, at: 0)
        #expect(d.mnemonic == .paciza)
        #expect(d.category == .pointerAuthentication)
        // Zero-source emits a single-operand draft (Rd only).
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
        // AUTIZA reads Rd (the authenticated pointer).
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
        // Zero-source PAC requires Rn = 11111; other values are reserved.
        let d = decode(0xDAC1_2020, at: 0)
        #expect(d.category != .pointerAuthentication)
    }

    @Test func xpaciStripsInstructionPointer() {
        // XPACI x0 = 0xDAC143E0.
        let d = decode(0xDAC1_43E0, at: 0)
        #expect(d.mnemonic == .xpaci)
        #expect(Array(d.operands) == [.register(.x(0))])
        // XPAC reads and writes Rd.
        #expect(d.semanticReads.contains(.x(0)) == true)
        #expect(d.semanticWrites.contains(.x(0)) == true)
    }

    @Test func xpacdStripsDataPointer() {
        // XPACD x0 = 0xDAC147E0.
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
        // sf=0:
        #expect(decode(0x5AC1_0020, at: 0).category != .pointerAuthentication)
        // opcode2 != 00001:
        #expect(decode(0xDAC0_0020, at: 0).category != .pointerAuthentication)
        #expect(decode(0xDAC2_0020, at: 0).category != .pointerAuthentication)
        // S != 0:
        #expect(decode(0xFAC1_0020, at: 0).category != .pointerAuthentication)
    }

    @Test func opc6AboveReservedXPACRangeReturnsNil() {
        // opc6 = 010010 or above (reserved beyond XPACI/XPACD).
        let encoding: UInt32 = 0xDAC1_0000 | (0b010010 << 10) | (0b11111 << 5)
        let d = decode(encoding, at: 0)
        #expect(d.category != .pointerAuthentication)
    }

    @Test func pacgaDecodesCorrectly() {
        // PACGA x0, x1, x2 = 0x9AC23020.
        let d = decode(0x9AC2_3020, at: 0)
        #expect(d.mnemonic == .pacga)
        #expect(d.category == .pointerAuthentication)
        #expect(d.operands.count == 3)
    }

    @Test func pacgaReadsRnAndRm() {
        let d = decode(0x9AC2_3020, at: 0)
        #expect(d.semanticReads.contains(.x(1)) == true) // Rn
        #expect(d.semanticReads.contains(.x(2)) == true) // Rm
        #expect(d.semanticWrites.contains(.x(0)) == true) // Rd
    }

    @Test func pacgaWithWrongOpc6ReturnsNil() {
        // opc6 != 001100. Set opc6 = 010000 (CRC32B range, owned by DPR).
        let encoding: UInt32 = 0x9AC2_0000 | (0b010000 << 10)
        let d = decode(encoding, at: 0)
        #expect(d.category != .pointerAuthentication)
    }

    @Test func pacgaWithWrongPrefixReturnsNil() {
        // sf=0:
        #expect(decode(0x1AC2_3020, at: 0).category != .pointerAuthentication)
        // bit 30 = 1 (DPR 1-source row):
        #expect(decode(0xDAC2_3020, at: 0).category != .pointerAuthentication)
    }
}
