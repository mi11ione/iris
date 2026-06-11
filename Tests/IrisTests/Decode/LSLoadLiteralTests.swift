// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the L1 load-register-literal class — the
/// PC-relative `LDR`/`LDRSW`/`PRFM` literal forms. Checks mnemonic, the
/// typed `.memory(.pc, …)` operand carrying the imm19<<2 byte offset,
/// memory-access classification, and the sign-extended displacement.
@Suite("L/S load-literal decode")
struct LSLoadLiteralTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func ldrWordLiteral() {
        // 0x18000000 = ldr w0, #0.
        let d = decode(0x1800_0000)
        #expect(d.mnemonic == .ldr)
        #expect(Array(d.operands) == [
            .register(.w(0)),
            .memory(MemoryOperand(base: .pc, displacement: 0)),
        ])
        #expect(d.memoryAccess == .load)
        #expect(d.memoryOrdering == [])
        #expect(d.semanticReads == .empty)
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
        #expect(d.category == .loadsAndStores)
        #expect(d.branchClass == .none)
        #expect(d.flagEffect == .none)
    }

    @Test func ldrDoublewordLiteral() {
        // 0x58000000 = ldr x0, #0 — opc=01 selects the 64-bit Xt form.
        let d = decode(0x5800_0000)
        #expect(d.mnemonic == .ldr)
        #expect(Array(d.operands) == [
            .register(.x(0)),
            .memory(MemoryOperand(base: .pc, displacement: 0)),
        ])
        #expect(d.memoryAccess == .load)
    }

    @Test func ldrswLiteralWritesXt() {
        // 0x98000000 = ldrsw x0, #0 — opc=10 sign-extends 32→64 into Xt.
        let d = decode(0x9800_0000)
        #expect(d.mnemonic == .ldrsw)
        #expect(Array(d.operands) == [
            .register(.x(0)),
            .memory(MemoryOperand(base: .pc, displacement: 0)),
        ])
        #expect(d.memoryAccess == .load)
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func prfmLiteralCarriesPrefetchOperand() {
        // 0xd8000000 = prfm pldl1keep, #0 — opc=11; Rt slot is the prfop.
        let d = decode(0xD800_0000)
        #expect(d.mnemonic == .prfm)
        #expect(Array(d.operands) == [
            .prefetchOperation(PrefetchOperation(rawValue: 0)),
            .memory(MemoryOperand(base: .pc, displacement: 0)),
        ])
        #expect(d.memoryAccess == .prefetch)
        // PRFM writes nothing and reads nothing through the register file.
        #expect(d.semanticWrites == .empty)
        #expect(d.semanticReads == .empty)
    }

    @Test func negativeImm19SignExtends() {
        // 0x18ffffe0 = ldr w0, #-4 — imm19 all-ones → -1, ×4 → -4.
        let d = decode(0x18FF_FFE0)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .pc, displacement: -4)))
    }

    @Test func positiveImm19ScalesByFour() {
        // 0x18000020 = ldr w0, #4 — imm19=1, ×4 → +4.
        let d = decode(0x1800_0020)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .pc, displacement: 4)))
    }

    @Test func zeroRegisterDestinationDropsFromWriteMask() {
        // 0x1800001f = ldr wzr, #0 — WZR write is a semantic no-op.
        let d = decode(0x1800_001F)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands.first == .register(.wzr()))
        #expect(d.semanticWrites == .empty)
    }
}
