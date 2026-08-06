// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the exclusive-pair class at both widths.
@Suite("L/S exclusive-pair decode")
struct LSExclusivePairTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func storeExclusivePairWordForm() {
        let d = decode(0x8820_0000)
        #expect(d.mnemonic == .stxp)
        #expect(Array(d.operands) == [
            .register(.w(0)), .register(.w(0)), .register(.w(0)),
            .memory(MemoryOperand(base: .register(.x(0)))),
        ])
        #expect(d.memoryAccess == .exclusiveStore)
        #expect(d.memoryOrdering == [])
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func loadExclusivePairDoublewordForm() {
        let d = decode(0xC87F_0440)
        #expect(d.mnemonic == .ldxp)
        #expect(Array(d.operands) == [
            .register(.x(0)), .register(.x(1)),
            .memory(MemoryOperand(base: .register(.x(2)))),
        ])
        #expect(d.memoryAccess == .exclusiveLoad)
        #expect(d.memoryOrdering == [])
        #expect(d.semanticReads.mask == (UInt64(1) << 2))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0) | (UInt64(1) << 1))
    }

    @Test func storeExclusivePairDoublewordReadsDataPair() {
        let d = decode(0xC820_0861)
        #expect(d.mnemonic == .stxp)
        #expect(Array(d.operands) == [
            .register(.w(0)), .register(.x(1)), .register(.x(2)),
            .memory(MemoryOperand(base: .register(.x(3)))),
        ])
        #expect(d.semanticReads.mask == (UInt64(1) << 1) | (UInt64(1) << 2) | (UInt64(1) << 3))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func storeReleaseExclusivePairCarriesRelease() {
        let d = decode(0x8820_8000)
        #expect(d.mnemonic == .stlxp)
        #expect(d.memoryAccess == .exclusiveStore)
        #expect(d.memoryOrdering == [.release])
    }

    @Test func loadAcquireExclusivePairCarriesAcquire() {
        let d = decode(0x887F_8000)
        #expect(d.mnemonic == .ldaxp)
        #expect(d.memoryAccess == .exclusiveLoad)
        #expect(d.memoryOrdering == [.acquire])
    }
}
