// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the PC-relative literal forms.
@Suite("L/S load-literal decode")
struct LSLoadLiteralTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func ldrWordLiteral() {
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
        let d = decode(0x5800_0000)
        #expect(d.mnemonic == .ldr)
        #expect(Array(d.operands) == [
            .register(.x(0)),
            .memory(MemoryOperand(base: .pc, displacement: 0)),
        ])
        #expect(d.memoryAccess == .load)
    }

    @Test func ldrswLiteralWritesXt() {
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
        let d = decode(0xD800_0000)
        #expect(d.mnemonic == .prfm)
        #expect(Array(d.operands) == [
            .prefetchOperation(PrefetchOperation(rawValue: 0)),
            .memory(MemoryOperand(base: .pc, displacement: 0)),
        ])
        #expect(d.memoryAccess == .prefetch)
        #expect(d.semanticWrites == .empty)
        #expect(d.semanticReads == .empty)
    }

    @Test func negativeImm19SignExtends() {
        let d = decode(0x18FF_FFE0)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .pc, displacement: -4)))
    }

    @Test func positiveImm19ScalesByFour() {
        let d = decode(0x1800_0020)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .pc, displacement: 4)))
    }

    @Test func zeroRegisterDestinationDropsFromWriteMask() {
        let d = decode(0x1800_001F)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands.first == .register(.wzr()))
        #expect(d.semanticWrites == .empty)
    }
}
