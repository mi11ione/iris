// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the L9 unprivileged class — LDTR / STTR and
/// the byte/halfword/sign-extend variants. Shares the LDUR shell but
/// with bits[11:10] = 10; no writeback, no prefetch variant.
@Suite("L/S unprivileged (LDTR) decode")
struct LSUnprivilegedTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func sttrWordStore() {
        // 0xb8000800 = sttr w0, [x0].
        let d = decode(0xB800_0800)
        #expect(d.mnemonic == .sttr)
        #expect(Array(d.operands) == [
            .register(.w(0)),
            .memory(MemoryOperand(base: .register(.x(0)))),
        ])
        #expect(d.memoryAccess == .store)
        #expect(d.memoryOrdering == [])
        #expect(d.semanticWrites == .empty)
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
    }

    @Test func ldtrDoublewordLoad() {
        // 0xf8400800 = ldtr x0, [x0].
        let d = decode(0xF840_0800)
        #expect(d.mnemonic == .ldtr)
        #expect(d.memoryAccess == .load)
        #expect(d.operands.first == .register(.x(0)))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func ldtrbAndSttrbByteForms() {
        #expect(decode(0x3840_0800).mnemonic == .ldtrb) // ldtrb w0, [x0]
        #expect(decode(0x3800_0800).mnemonic == .sttrb) // sttrb w0, [x0]
    }

    @Test func ldtrhHalfwordForm() {
        // 0x78400800 = ldtrh w0, [x0].
        #expect(decode(0x7840_0800).mnemonic == .ldtrh)
    }

    @Test func ldtrsbSignExtendsToXt() {
        // 0x38800800 = ldtrsb x0, [x0] — opc=10 selects the Xt width.
        let d = decode(0x3880_0800)
        #expect(d.mnemonic == .ldtrsb)
        #expect(d.operands.first == .register(.x(0)))
    }

    @Test func ldtrshWidthFollowsOpcNotSize() {
        // opc=10 → Xt, opc=11 → Wt; the mnemonic stays LDTRSH.
        let xtForm = decode(0x7880_0800) // ldtrsh x0, [x0]
        #expect(xtForm.mnemonic == .ldtrsh)
        #expect(xtForm.operands.first == .register(.x(0)))
        let wtForm = decode(0x78C0_0800) // ldtrsh w0, [x0]
        #expect(wtForm.mnemonic == .ldtrsh)
        #expect(wtForm.operands.first == .register(.w(0)))
    }

    @Test func ldtrswForm() {
        // 0xb8800800 = ldtrsw x0, [x0].
        let d = decode(0xB880_0800)
        #expect(d.mnemonic == .ldtrsw)
        #expect(d.operands.first == .register(.x(0)))
    }

    @Test func reservedUnprivilegedEncodingReturnsUndefined() {
        // 0xb8c00800 — size=10, opc=11 has no unprivileged instruction.
        #expect(decode(0xB8C0_0800).mnemonic == .undefined)
    }
}
