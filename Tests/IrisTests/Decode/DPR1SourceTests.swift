// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates data-processing 1-source decode (1-source
/// half) plus its reserved-encoding edge cases. Covers
/// RBIT/REV16/REV/REV32/CLZ/CLS + opcode2 != 0 reserved + REV at sf=0
/// opc=11 reserved + the PAC standalone slot range.
@Suite("DPR / 1-source data processing")
struct DPR1SourceTests {
    @Test func rbit64Bit() {
        // RBIT x0, x1 — opc6=000000.
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
        // REV16 x0, x1 — opc6=000001.
        let d = decode(0xDAC0_0420, at: 0)
        #expect(d.mnemonic == .rev16)
    }

    @Test func revAtSf0() {
        // REV w0, w1 — sf=0, opc6=000010 → REV (full 32-bit byte-swap).
        let d = decode(0x5AC0_0820, at: 0)
        #expect(d.mnemonic == .rev)
    }

    @Test func rev32AtSf1() {
        // REV32 x0, x1 — sf=1, opc6=000010 → REV32 (per-32 byte-swap of 64-bit).
        let d = decode(0xDAC0_0820, at: 0)
        #expect(d.mnemonic == .rev32)
    }

    @Test func revAtSf1() {
        // REV x0, x1 — sf=1, opc6=000011 → REV (full 64-bit byte-swap).
        let d = decode(0xDAC0_0C20, at: 0)
        #expect(d.mnemonic == .rev)
    }

    @Test func opc011AtSf0ReturnsUndefined() {
        // REV at sf=0 opc=000011 is reserved.
        let d = decode(0x5AC0_0C20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func clz() {
        // CLZ x0, x1 — opc6=000100.
        let d = decode(0xDAC0_1020, at: 0)
        #expect(d.mnemonic == .clz)
    }

    @Test func cls() {
        // CLS x0, x1 — opc6=000101.
        let d = decode(0xDAC0_1420, at: 0)
        #expect(d.mnemonic == .cls)
    }

    @Test func opcode2NonZeroReturnsUndefined() {
        // opcode2 (bits 20:16) != 0 is reserved for the standard
        // 1-source ops. (PAC standalone uses opcode2=00001 and is owned
        // by the crypto/Apple-extensions family — exercised by separate
        // tests.) opcode2=00010 is truly reserved in both families.
        let d = decode(0xDAC2_0020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func pacStandaloneOpc6_001100ReturnsUndefined() {
        // opc6=001100 lies in the PAC-standalone slot range; without
        // PAC's opcode2=00001 the word is reserved → UNDEFINED.
        let d = decode(0xDAC0_3020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func pacStandaloneOpc6_001111ReturnsUndefined() {
        // AUTDB at opc6=001111 — same deferred treatment.
        let d = decode(0xDAC0_3C20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func opc6_001000DecodesCsscAbs() {
        // opc6=001000 is FEAT_CSSC scalar ABS (in scope) — not PAC/undefined.
        let d = decode(0xDAC0_2020, at: 0)
        #expect(d.mnemonic == .abs)
    }

    @Test func opc6_000110DecodesCsscCtz() {
        // opc6=000110 is FEAT_CSSC scalar CTZ (in scope) — not an unallocated gap.
        let d = decode(0xDAC0_1820, at: 0)
        #expect(d.mnemonic == .ctz)
    }

    @Test func unallocated1SourceOpc6RangeIsUndefined() {
        // opc6 001001..001111 in the 1-source space is unallocated → UNDEFINED,
        // raw encoding preserved. (opc6 001000 is FEAT_CSSC ABS — covered above.)
        for opc6: UInt32 in 0b001001 ... 0b001111 {
            let encoding: UInt32 = 0xDAC0_0020 | (opc6 << 10)
            let d = decode(encoding, at: 0)
            #expect(d.mnemonic == .undefined, "opc6=\(String(opc6, radix: 2)) must be undefined")
            #expect(d.encoding == encoding, "encoding must be preserved verbatim")
        }
    }

    @Test func csscCntDecodesAsScalarPopulationCount() {
        // FEAT_CSSC CNT (scalar) shares the 1-source tier.
        let d = decode(0xDAC0_1C20, at: 0)
        #expect(d.mnemonic == .cnt)
        #expect(d.category == .dataProcessingRegister)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1))])
        #expect(d.semanticReads.contains(.x(1)))
        #expect(d.semanticWrites.contains(.x(0)))
        #expect(d.text == "cnt x0, x1")
    }
}
