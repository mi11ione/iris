// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates EXTR decoding + the ROR alias predicate (Rn==Rm) + the reserved
/// encodings (N != sf, bit 21 != 0, sf=0 imms[5]=1).
@Suite("DPI / EXTR + ROR alias")
struct DPIExtractTests {
    @Test func extrBaseFormWithDistinctRegs() {
        let d = decode(0x93C2_1420, at: 0)
        #expect(d.mnemonic == .extr)
        #expect(d.operands.count == 4)
        #expect(d.semanticReads.contains(.x(1)))
        #expect(d.semanticReads.contains(.x(2)))
    }

    @Test func rorAliasWhenRnEqualsRm() {
        let d = decode(0x93C1_1420, at: 0)
        #expect(d.mnemonic == .ror)
        #expect(d.operands.count == 3)
    }

    @Test func extr32Bit() {
        let d = decode(0x1382_1420, at: 0)
        #expect(d.mnemonic == .extr)
    }

    @Test func ror32Bit() {
        let d = decode(0x1381_1420, at: 0)
        #expect(d.mnemonic == .ror)
    }

    @Test func reservedNMismatchSF0N1() {
        let d = decode(0x13C0_0020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedNMismatchSF1N0() {
        let d = decode(0x9380_0020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedBit21NotZero() {
        let d = decode(0x93E0_0000, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedSF0WithImmsHighBitSet() {
        let d = decode(0x1380_8000, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedOpcNot00() {
        let d = decode(0x33C0_0020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func extrWritesRdOnly() {
        let d = decode(0x93C2_1420, at: 0)
        #expect(d.semanticWrites.contains(.x(0)))
        #expect(!d.semanticReads.contains(.x(0)))
    }

    @Test func rorRdIsXZRWhenEncoded31() {
        let d = decode(0x93C1_143F, at: 0)
        #expect(d.mnemonic == .ror)
        if case let .register(rd) = d.operands[0] {
            #expect(rd.isZeroRegister)
        }
    }
}
