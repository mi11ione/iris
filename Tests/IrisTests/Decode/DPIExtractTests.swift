// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates EXTR decoding + the ROR alias predicate (Rn==Rm) + the
/// reserved encodings (N != sf, bit 21 != 0, sf=0 imms[5]=1).
@Suite("DPI / EXTR + ROR alias")
struct DPIExtractTests {
    @Test func extrBaseFormWithDistinctRegs() {
        // EXTR x0, x1, x2, #5
        let d = decode(0x93C2_1420, at: 0)
        #expect(d.mnemonic == .extr)
        #expect(d.operands.count == 4)
        // Reads Rn AND Rm (both source registers).
        #expect(d.semanticReads.contains(.x(1)))
        #expect(d.semanticReads.contains(.x(2)))
    }

    @Test func rorAliasWhenRnEqualsRm() {
        // EXTR x0, x1, x1, #5 → ROR x0, x1, #5
        let d = decode(0x93C1_1420, at: 0)
        #expect(d.mnemonic == .ror)
        #expect(d.operands.count == 3)
    }

    @Test func extr32Bit() {
        // EXTR w0, w1, w2, #5 (sf=0, N=0)
        let d = decode(0x1382_1420, at: 0)
        #expect(d.mnemonic == .extr)
    }

    @Test func ror32Bit() {
        // EXTR w0, w1, w1, #5 → ROR w0, w1, #5 (sf=0, Rm=Rn=1)
        let d = decode(0x1381_1420, at: 0)
        #expect(d.mnemonic == .ror)
    }

    @Test func reservedNMismatchSF0N1() {
        // EXTR sf=0 N=1 → reserved
        let d = decode(0x13C0_0020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedNMismatchSF1N0() {
        // EXTR sf=1 N=0 → reserved
        let d = decode(0x9380_0020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedBit21NotZero() {
        // EXTR with bit 21 (o0) = 1 → reserved
        // sf=1, N=1, bit 21=1, Rm=0, imms=0, Rn=0, Rd=0
        // = 1_00_100111_1_1_00000_000000_00000_00000 = 0x93E0_0000
        let d = decode(0x93E0_0000, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedSF0WithImmsHighBitSet() {
        // EXTR sf=0 N=0 with imms[5]=1 → reserved (32-bit imms must fit 5 bits)
        // sf=0, N=0, bit 21=0, Rm=0, imms=32 (0x20), Rn=0, Rd=0
        // = 0_00_100111_0_0_00000_100000_00000_00000 = 0x1380_8000
        let d = decode(0x1380_8000, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedOpcNot00() {
        // EXTR requires opc bits 30:29 == 00. Top bits with opc=01: encoding
        // = 0_01_100111_... = 0x33C0_0000 area. Should be reserved.
        let d = decode(0x33C0_0020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func extrWritesRdOnly() {
        // EXTR Rd is fully overwritten — NOT in read set.
        let d = decode(0x93C2_1420, at: 0)
        #expect(d.semanticWrites.contains(.x(0)))
        #expect(!d.semanticReads.contains(.x(0)))
    }

    @Test func rorRdIsXZRWhenEncoded31() {
        // ROR xzr, x1, #5 — Rd=31 means XZR (EXTR Rd is ZR-form).
        // EXTR x_, x1, x1, #5 with Rd=31: encoding adjusted to Rd=11111.
        // Rd=31 → bits 4:0 = 11111. Take 0x93C11420 and OR in 0x1F: 0x93C1143F.
        let d = decode(0x93C1_143F, at: 0)
        #expect(d.mnemonic == .ror)
        if case let .register(rd) = d.operands[0] {
            #expect(rd.isZeroRegister)
        }
    }
}
