// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates ADR / ADRP decoding — ADR uses
/// `.label(byteOffset:)` for PC-relative byte-precise offsets; ADRP
/// uses `.pageLabel(byteOffset:)` for page-relative offsets. The
/// distinction is critical for downstream data-flow analysis.
@Suite("DPI / PC-relative ADR/ADRP")
struct DPIPCRelTests {
    @Test func adrZeroOffset() {
        // ADR x0, #0 (immlo=00, immhi=0)
        let d = decode(0x1000_0000, at: 0)
        #expect(d.mnemonic == .adr)
        #expect(d.operands.count == 2)
        #expect(d.operands[1] == .label(byteOffset: 0), "ADR must emit .label operand")
    }

    @Test func adrPositiveOffsetFromImmlo() {
        // ADR x0, #4 (immlo=01 → encoding bit 30=0 bit 29=1; that's 0x20 high nibble)
        let d = decode(0x3000_0000, at: 0)
        #expect(d.mnemonic == .adr)
        if case let .label(byteOffset) = d.operands[1] {
            #expect(byteOffset == 1)
        }
    }

    @Test func adrNegativeOffsetSignExtends() {
        // ADR with all immhi bits set + immlo=11 → sign-extended negative.
        // Encoding 0x70FFFFFF: op=0, immlo=11 (bits 30:29), immhi all 1s.
        let d = decode(0x70FF_FFE0, at: 0)
        #expect(d.mnemonic == .adr)
        if case let .label(byteOffset) = d.operands[1] {
            #expect(byteOffset < 0)
        }
    }

    @Test func adrRdIsXZRWhenEncoded31() {
        // ADR xzr, #0 (Rd=31). ADR Rd is ZR-form (no SP form).
        let d = decode(0x1000_001F, at: 0)
        #expect(d.mnemonic == .adr)
        #expect(d.operands[0] == .register(.xzr()), "expected register operand at 0")
    }

    @Test func adrRdIsRegularWhenEncoded0_30() {
        // ADR x16, #0 (Rd=16)
        let d = decode(0x1000_0010, at: 0)
        if case let .register(rd) = d.operands[0] {
            #expect(rd.canonicalIndex == 16)
            #expect(!rd.isZeroRegister)
            #expect(!rd.isStackPointer)
        }
    }

    @Test func adrpUsesPageLabelNotLabel() {
        // ADRP x0, #0 (op=1) — MUST emit .pageLabel, not .label
        let d = decode(0x9000_0000, at: 0)
        #expect(d.mnemonic == .adrp)
        #expect(d.operands[1] == .pageLabel(byteOffset: 0), "ADRP must emit .pageLabel (NOT .label)")
    }

    @Test func adrpPositivePageOffset() {
        // ADRP x0, #12288 (immlo=11, immhi=0 → 21-bit signed value 3 → << 12 = 12288)
        let d = decode(0xF000_0000, at: 0)
        #expect(d.mnemonic == .adrp)
        if case let .pageLabel(byteOffset) = d.operands[1] {
            #expect(byteOffset == 12288)
        }
    }

    @Test func adrpNegativeOffsetSignExtends() {
        // ADRP x0, #-16384 (sign-extended)
        let d = decode(0x90FF_FFE0, at: 0)
        #expect(d.mnemonic == .adrp)
        if case let .pageLabel(byteOffset) = d.operands[1] {
            #expect(byteOffset == -16384)
        }
    }

    @Test func adrpRdIsXZRWhenEncoded31() {
        let d = decode(0x9000_001F, at: 0)
        if case let .register(rd) = d.operands[0] {
            #expect(rd.isZeroRegister)
        }
    }

    @Test func neitherAdrNorAdrpReadsAnyRegister() {
        let d = decode(0x1000_0020, at: 0)
        #expect(d.semanticReads == .empty)
    }

    @Test func adrWritesRdWhenNotXZR() {
        let d = decode(0x1000_0010, at: 0)
        // Rd=16 (X16) is written.
        #expect(d.semanticWrites.contains(.x(16)))
    }

    @Test func adrWritesNothingForXZR() {
        let d = decode(0x1000_001F, at: 0)
        // Rd=31=XZR is omitted from the write set (the zero register
        // is not state).
        #expect(d.semanticWrites == .empty)
    }

    @Test func adrMaximumPositiveOffset() {
        // ADR x0 with bit 20 set in raw (largest positive 21-bit value).
        // immhi all 1s except top bit, immlo=11 → value = +0xFFFFF = 1048575 (2^20 - 1).
        // Encoding: 0x707FFFE0 (op=0, immlo=11, immhi = 0_111_1111_1111_1111_1111)
        let d = decode(0x707F_FFE0, at: 0)
        #expect(d.mnemonic == .adr)
        if case let .label(byteOffset) = d.operands[1] {
            #expect(byteOffset == 1_048_575)
        }
    }
}
