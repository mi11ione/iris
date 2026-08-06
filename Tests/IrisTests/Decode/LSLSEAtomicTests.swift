// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the LSE atomics.
@Suite("L/S LSE atomic decode")
struct LSLSEAtomicTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func ldaddByteBaseForm() {
        let d = decode(0x3820_0000)
        #expect(d.mnemonic == .ldaddb)
        #expect(Array(d.operands) == [
            .register(.w(0)), .register(.w(0)),
            .memory(MemoryOperand(base: .register(.x(0)))),
        ])
        #expect(d.memoryAccess == .atomic)
        #expect(d.memoryOrdering == [])
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func ldaddWordAndDoublewordForms() {
        #expect(decode(0xB820_0000).mnemonic == .ldadd)
        let dword = decode(0xF820_0000)
        #expect(dword.mnemonic == .ldadd)
        #expect(dword.operands.first == .register(.x(0)))
    }

    @Test func ldsetSelectsTheRightOperation() {
        #expect(decode(0xB820_3000).mnemonic == .ldset)
    }

    @Test func swpDecodesAndCarriesAtomicAccess() {
        let d = decode(0xF820_8000)
        #expect(d.mnemonic == .swp)
        #expect(d.memoryAccess == .atomic)
    }

    @Test func acquireSuffixForm() {
        let d = decode(0x38A0_0000)
        #expect(d.mnemonic == .ldaddab)
        #expect(d.memoryOrdering == [.acquire])
    }

    @Test func acquireReleaseSuffixForms() {
        #expect(decode(0x38E0_0000).mnemonic == .ldaddalb)
        let d = decode(0xF8E0_0000)
        #expect(d.mnemonic == .ldaddal)
        #expect(d.memoryOrdering == [.acquire, .release])
    }

    @Test func zeroDestinationCollapsesToStoreAlias() {
        let d = decode(0x3820_001F)
        #expect(d.mnemonic == .staddb)
        #expect(Array(d.operands) == [
            .register(.w(0)),
            .memory(MemoryOperand(base: .register(.x(0)))),
        ])
        #expect(d.memoryAccess == .atomic)
        #expect(d.semanticWrites == .empty)
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
    }

    @Test func releaseStoreAliasForm() {
        let d = decode(0xB860_001F)
        #expect(d.mnemonic == .staddl)
        #expect(d.memoryOrdering == [.release])
        #expect(d.operands.count == 2)
    }

    @Test func swpDoesNotCollapseEvenWithZeroDestination() {
        let d = decode(0x3820_801F)
        #expect(d.mnemonic == .swpb)
        #expect(d.operands.count == 3)
    }

    @Test func acquireBitSuppressesTheStoreAlias() {
        let d = decode(0x38A0_001F)
        #expect(d.mnemonic == .ldaddab)
        #expect(d.operands.count == 3)
    }

    @Test func opField1001DecodesRcwClear() {
        let d = decode(0x3820_9000)
        #expect(d.mnemonic == .rcwclr)
        #expect(d.category == .loadsAndStores)
    }

    @Test func distinctRegistersProveTheAtomicReadWriteRoles() {
        let d = decode(0xB821_0062)
        #expect(d.mnemonic == .ldadd)
        #expect(Array(d.operands) == [
            .register(.w(1)), .register(.w(2)),
            .memory(MemoryOperand(base: .register(.x(3)))),
        ])
        #expect(d.semanticReads.mask == (UInt64(1) << 1) | (UInt64(1) << 3))
        #expect(d.semanticWrites.mask == UInt64(1) << 2)
    }
}
