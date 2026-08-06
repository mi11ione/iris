// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates load/store-exclusive, load-acquire/store-release and the FEAT_LOR
/// forms.
@Suite("L/S exclusive + ordered decode")
struct LSExclusiveAndOrderedTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func storeExclusiveStatusRegisterIsWritten() {
        let d = decode(0xC800_7C41)
        #expect(d.mnemonic == .stxr)
        #expect(Array(d.operands) == [.register(.w(0)), .register(.x(1)), .memory(MemoryOperand(base: .register(.x(2))))])
        #expect(d.memoryAccess == .exclusiveStore)
        #expect(d.memoryOrdering == [])
        #expect(d.semanticReads.mask == (UInt64(1) << 1) | (UInt64(1) << 2))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func storeReleaseExclusiveCarriesReleaseOrdering() {
        let d = decode(0xC800_FC41)
        #expect(d.mnemonic == .stlxr)
        #expect(d.memoryAccess == .exclusiveStore)
        #expect(d.memoryOrdering == [.release])
    }

    @Test func loadExclusiveWritesRtReadsBase() {
        let d = decode(0xC85F_7C00)
        #expect(d.mnemonic == .ldxr)
        #expect(Array(d.operands) == [.register(.x(0)), .memory(MemoryOperand(base: .register(.x(0))))])
        #expect(d.memoryAccess == .exclusiveLoad)
        #expect(d.memoryOrdering == [])
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func loadAcquireExclusiveCarriesAcquireOrdering() {
        let d = decode(0xC85F_FC00)
        #expect(d.mnemonic == .ldaxr)
        #expect(d.memoryAccess == .exclusiveLoad)
        #expect(d.memoryOrdering == [.acquire])
    }

    @Test func byteExclusiveFormsUseTheSuffixMnemonic() {
        #expect(decode(0x0800_7C00).mnemonic == .stxrb)
        #expect(decode(0x085F_7C00).mnemonic == .ldxrb)
    }

    @Test func loadAcquireIsAPlainOrderedLoadNotExclusive() {
        let d = decode(0xC8DF_FC00)
        #expect(d.mnemonic == .ldar)
        #expect(d.memoryAccess == .load)
        #expect(d.memoryOrdering == [.acquire])
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func storeReleaseIsAPlainOrderedStore() {
        let d = decode(0xC89F_FC00)
        #expect(d.mnemonic == .stlr)
        #expect(d.memoryAccess == .store)
        #expect(d.memoryOrdering == [.release])
        #expect(d.semanticWrites == .empty)
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
    }

    @Test func wordOrderedFormsUseTheBareMnemonic() {
        #expect(decode(0x88DF_FC00).mnemonic == .ldar)
        #expect(decode(0x889F_FC00).mnemonic == .stlr)
    }

    @Test func lorLoadAcquireDecodesAsLdlar() {
        let d = decode(0xC8DF_7C00)
        #expect(d.mnemonic == .ldlar)
        #expect(d.memoryAccess == .load)
        #expect(d.memoryOrdering == [.acquire])
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func lorStoreReleaseDecodesAsStllr() {
        let d = decode(0xC89F_7C00)
        #expect(d.mnemonic == .stllr)
        #expect(d.memoryAccess == .store)
        #expect(d.memoryOrdering == [.release])
        #expect(d.semanticWrites == .empty)
    }

    @Test func halfwordOrderedAndLorForms() {
        #expect(decode(0x48DF_FC00).mnemonic == .ldarh)
        #expect(decode(0x48DF_7C00).mnemonic == .ldlarh)
    }
}
