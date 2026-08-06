// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the load/store-pair class across all four indexing forms.
@Suite("L/S load/store-pair decode")
struct LSLoadStorePairTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func storeNoAllocatePairWordForm() {
        let d = decode(0x2800_0000)
        #expect(d.mnemonic == .stnp)
        #expect(Array(d.operands) == [
            .register(.w(0)), .register(.w(0)),
            .memory(MemoryOperand(base: .register(.x(0)))),
        ])
        #expect(d.memoryAccess == .store)
        #expect(d.memoryOrdering == [])
        #expect(d.semanticWrites == .empty)
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
    }

    @Test func loadNoAllocatePairDoublewordForm() {
        let d = decode(0xA840_0000)
        #expect(d.mnemonic == .ldnp)
        #expect(d.memoryAccess == .load)
        #expect(d.operands.first == .register(.x(0)))
    }

    @Test func signedOffsetPairWordForm() {
        let d = decode(0x2940_0000)
        #expect(d.mnemonic == .ldp)
        #expect(d.memoryAccess == .load)
        #expect(d.operands[2] == .memory(MemoryOperand(base: .register(.x(0)))))
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func signedOffsetScalesImm7ByEightForDoublewordPair() {
        let d = decode(0xA941_0000)
        #expect(d.mnemonic == .ldp)
        #expect(d.operands[2] == .memory(MemoryOperand(base: .register(.x(0)), displacement: 16)))
    }

    @Test func preIndexedPairWritesBackBase() {
        let d = decode(0xA9C0_0000)
        #expect(d.mnemonic == .ldp)
        #expect(d.operands[2] == .memory(MemoryOperand(base: .register(.x(0)), writeback: .preIndex)))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func postIndexedPairStoreWritesBackBaseOnly() {
        let d = decode(0x2880_0000)
        #expect(d.mnemonic == .stp)
        #expect(d.operands[2] == .memory(MemoryOperand(base: .register(.x(0)), writeback: .postIndex)))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func ldpswSignExtendsIntoXtPair() {
        let d = decode(0x68C0_0000)
        #expect(d.mnemonic == .ldpsw)
        #expect(d.operands.first == .register(.x(0)))
        #expect(d.memoryAccess == .load)
    }

    @Test func stgpDecodesAtOpcOne() {
        let d = decode(0x6880_0000)
        #expect(d.mnemonic == .stgp)
        #expect(d.memoryAccess == .store)
    }

    @Test func opcElevenNoAllocateDecodesSttnp() {
        #expect(decode(0xE800_0000).mnemonic == .sttnp)
    }

    @Test func opcElevenSignedOffsetDecodesSttp() {
        let d = decode(0xE900_0861)
        #expect(d.mnemonic == .sttp)
        #expect(d.memoryAccess == .store)
        #expect(Array(d.operands) == [
            .register(.x(1)), .register(.x(2)),
            .memory(MemoryOperand(base: .register(.x(3)))),
        ])
        #expect(d.text == "sttp x1, x2, [x3]")
    }

    @Test func ldpswNoAllocateFormReservedReturnsUndefined() {
        let d = decode(0x6800_0000)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
    }

    @Test func distinctRegistersProveTheLoadPairMasks() {
        let d = decode(0xA8C1_0861)
        #expect(d.mnemonic == .ldp)
        #expect(Array(d.operands) == [
            .register(.x(1)), .register(.x(2)),
            .memory(MemoryOperand(base: .register(.x(3)), displacement: 16, writeback: .postIndex)),
        ])
        #expect(d.semanticReads.mask == UInt64(1) << 3)
        #expect(d.semanticWrites.mask == (UInt64(1) << 1) | (UInt64(1) << 2) | (UInt64(1) << 3))
    }

    @Test func distinctRegistersProveTheStorePairMasks() {
        let d = decode(0x2800_0861)
        #expect(d.mnemonic == .stnp)
        #expect(Array(d.operands) == [
            .register(.w(1)), .register(.w(2)),
            .memory(MemoryOperand(base: .register(.x(3)))),
        ])
        #expect(d.semanticReads.mask == (UInt64(1) << 1) | (UInt64(1) << 2) | (UInt64(1) << 3))
        #expect(d.semanticWrites == .empty)
    }
}
