// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the L7 unscaled-immediate class — LDUR / STUR
/// and the byte/halfword/sign-extend variants plus PRFUM. The imm9 field
/// is signed and NOT scaled; checks mnemonic, width, and displacement.
@Suite("L/S unscaled-immediate decode")
struct LSUnscaledTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func sturWordForm() {
        // 0xb8000000 = stur w0, [x0].
        let d = decode(0xB800_0000)
        #expect(d.mnemonic == .stur)
        #expect(Array(d.operands) == [
            .register(.w(0)),
            .memory(MemoryOperand(base: .register(.x(0)))),
        ])
        #expect(d.memoryAccess == .store)
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites == .empty)
    }

    @Test func ldurDoublewordForm() {
        // 0xf8400000 = ldur x0, [x0].
        let d = decode(0xF840_0000)
        #expect(d.mnemonic == .ldur)
        #expect(d.memoryAccess == .load)
        #expect(d.operands.first == .register(.x(0)))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func sturbAndLdurbByteForms() {
        #expect(decode(0x3800_0000).mnemonic == .sturb) // sturb w0, [x0]
        #expect(decode(0x3840_0000).mnemonic == .ldurb) // ldurb w0, [x0]
    }

    @Test func sturhHalfwordForm() {
        // 0x78000000 = sturh w0, [x0].
        #expect(decode(0x7800_0000).mnemonic == .sturh)
    }

    @Test func ldursbSignExtendsToXt() {
        // 0x38800000 = ldursb x0, [x0] — opc=10 sign-extends into Xt.
        let d = decode(0x3880_0000)
        #expect(d.mnemonic == .ldursb)
        #expect(d.operands.first == .register(.x(0)))
    }

    @Test func imm9IsUnscaledAndNotShifted() {
        // 0x38001000 = sturb w0, [x0, #1] — imm9=1 renders as #1, no scale.
        let d = decode(0x3800_1000)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), displacement: 1)))
    }

    @Test func prfumCarriesPrefetchOperand() {
        // 0xf8800000 = prfum pldl1keep, [x0].
        let d = decode(0xF880_0000)
        #expect(d.mnemonic == .prfum)
        #expect(d.operands.first == .prefetchOperation(PrefetchOperation(rawValue: 0)))
        #expect(d.memoryAccess == .prefetch)
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites == .empty)
    }

    @Test func reservedSizeOpcReturnsUndefined() {
        // 0xb8c00000 — size=10, opc=11 has no unscaled instruction.
        #expect(decode(0xB8C0_0000).mnemonic == .undefined)
    }
}
