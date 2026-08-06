// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates ADR and ADRP.
@Suite("DPI / PC-relative ADR/ADRP")
struct DPIPCRelTests {
    @Test func adrZeroOffset() {
        let d = decode(0x1000_0000, at: 0)
        #expect(d.mnemonic == .adr)
        #expect(d.operands.count == 2)
        #expect(d.operands[1] == .label(byteOffset: 0), "ADR must emit .label operand")
    }

    @Test func adrPositiveOffsetFromImmlo() {
        let d = decode(0x3000_0000, at: 0)
        #expect(d.mnemonic == .adr)
        if case let .label(byteOffset) = d.operands[1] {
            #expect(byteOffset == 1)
        }
    }

    @Test func adrNegativeOffsetSignExtends() {
        let d = decode(0x70FF_FFE0, at: 0)
        #expect(d.mnemonic == .adr)
        if case let .label(byteOffset) = d.operands[1] {
            #expect(byteOffset < 0)
        }
    }

    @Test func adrRdIsXZRWhenEncoded31() {
        let d = decode(0x1000_001F, at: 0)
        #expect(d.mnemonic == .adr)
        #expect(d.operands[0] == .register(.xzr()), "expected register operand at 0")
    }

    @Test func adrRdIsRegularWhenEncoded0_30() {
        let d = decode(0x1000_0010, at: 0)
        if case let .register(rd) = d.operands[0] {
            #expect(rd.canonicalIndex == 16)
            #expect(!rd.isZeroRegister)
            #expect(!rd.isStackPointer)
        }
    }

    @Test func adrpUsesPageLabelNotLabel() {
        let d = decode(0x9000_0000, at: 0)
        #expect(d.mnemonic == .adrp)
        #expect(d.operands[1] == .pageLabel(byteOffset: 0), "ADRP must emit .pageLabel (NOT .label)")
    }

    @Test func adrpPositivePageOffset() {
        let d = decode(0xF000_0000, at: 0)
        #expect(d.mnemonic == .adrp)
        if case let .pageLabel(byteOffset) = d.operands[1] {
            #expect(byteOffset == 12288)
        }
    }

    @Test func adrpNegativeOffsetSignExtends() {
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
        #expect(d.semanticWrites.contains(.x(16)))
    }

    @Test func adrWritesNothingForXZR() {
        let d = decode(0x1000_001F, at: 0)
        #expect(d.semanticWrites == .empty)
    }

    @Test func adrMaximumPositiveOffset() {
        let d = decode(0x707F_FFE0, at: 0)
        #expect(d.mnemonic == .adr)
        if case let .label(byteOffset) = d.operands[1] {
            #expect(byteOffset == 1_048_575)
        }
    }
}
