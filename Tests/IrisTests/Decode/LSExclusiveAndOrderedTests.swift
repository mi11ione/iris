// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the L2/L4/L4c shell — load/store-exclusive
/// register, load-acquire/store-release, and the FEAT_LOR LDLAR/STLLR
/// forms. Checks the (o2, L, o0) → mnemonic map, exclusive/ordered
/// memory-access classification, acquire/release ordering, and the
/// status-register vs data-register read/write split.
@Suite("L/S exclusive + ordered decode")
struct LSExclusiveAndOrderedTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func storeExclusiveStatusRegisterIsWritten() {
        // 0xc8007c41 = stxr w0, x1, [x2] — Rs=w0 (status), Rt=x1, Rn=x2.
        let d = decode(0xC800_7C41)
        #expect(d.mnemonic == .stxr)
        #expect(Array(d.operands) == [.register(.w(0)), .register(.x(1)), .memory(MemoryOperand(base: .register(.x(2))))])
        #expect(d.memoryAccess == .exclusiveStore)
        #expect(d.memoryOrdering == [])
        // Reads Rt + Rn (the data + base); writes Rs (the status).
        #expect(d.semanticReads.mask == (UInt64(1) << 1) | (UInt64(1) << 2))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func storeReleaseExclusiveCarriesReleaseOrdering() {
        // 0xc800fc41 = stlxr w0, x1, [x2].
        let d = decode(0xC800_FC41)
        #expect(d.mnemonic == .stlxr)
        #expect(d.memoryAccess == .exclusiveStore)
        #expect(d.memoryOrdering == [.release])
    }

    @Test func loadExclusiveWritesRtReadsBase() {
        // 0xc85f7c00 = ldxr x0, [x0].
        let d = decode(0xC85F_7C00)
        #expect(d.mnemonic == .ldxr)
        #expect(Array(d.operands) == [.register(.x(0)), .memory(MemoryOperand(base: .register(.x(0))))])
        #expect(d.memoryAccess == .exclusiveLoad)
        #expect(d.memoryOrdering == [])
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func loadAcquireExclusiveCarriesAcquireOrdering() {
        // 0xc85ffc00 = ldaxr x0, [x0].
        let d = decode(0xC85F_FC00)
        #expect(d.mnemonic == .ldaxr)
        #expect(d.memoryAccess == .exclusiveLoad)
        #expect(d.memoryOrdering == [.acquire])
    }

    @Test func byteExclusiveFormsUseTheSuffixMnemonic() {
        // 0x08007c00 = stxrb w0, w0, [x0]; 0x085f7c00 = ldxrb w0, [x0].
        #expect(decode(0x0800_7C00).mnemonic == .stxrb)
        #expect(decode(0x085F_7C00).mnemonic == .ldxrb)
    }

    @Test func loadAcquireIsAPlainOrderedLoadNotExclusive() {
        // 0xc8dffc00 = ldar x0, [x0] — LDAR is .load + .acquire (not atomic).
        let d = decode(0xC8DF_FC00)
        #expect(d.mnemonic == .ldar)
        #expect(d.memoryAccess == .load)
        #expect(d.memoryOrdering == [.acquire])
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func storeReleaseIsAPlainOrderedStore() {
        // 0xc89ffc00 = stlr x0, [x0] — STLR is .store + .release, writes nothing.
        let d = decode(0xC89F_FC00)
        #expect(d.mnemonic == .stlr)
        #expect(d.memoryAccess == .store)
        #expect(d.memoryOrdering == [.release])
        #expect(d.semanticWrites == .empty)
        // STLR reads the data register Rt and the base Rn.
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
    }

    @Test func wordOrderedFormsUseTheBareMnemonic() {
        // 0x88dffc00 = ldar w0, [x0]; 0x889ffc00 = stlr w0, [x0].
        #expect(decode(0x88DF_FC00).mnemonic == .ldar)
        #expect(decode(0x889F_FC00).mnemonic == .stlr)
    }

    @Test func lorLoadAcquireDecodesAsLdlar() {
        // 0xc8df7c00 = ldlar x0, [x0] — FEAT_LOR; .load + .acquire.
        let d = decode(0xC8DF_7C00)
        #expect(d.mnemonic == .ldlar)
        #expect(d.memoryAccess == .load)
        #expect(d.memoryOrdering == [.acquire])
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func lorStoreReleaseDecodesAsStllr() {
        // 0xc89f7c00 = stllr x0, [x0] — FEAT_LOR; .store + .release.
        let d = decode(0xC89F_7C00)
        #expect(d.mnemonic == .stllr)
        #expect(d.memoryAccess == .store)
        #expect(d.memoryOrdering == [.release])
        #expect(d.semanticWrites == .empty)
    }

    @Test func halfwordOrderedAndLorForms() {
        // 0x48dffc00 = ldarh w0, [x0]; 0x48df7c00 = ldlarh w0, [x0].
        #expect(decode(0x48DF_FC00).mnemonic == .ldarh)
        #expect(decode(0x48DF_7C00).mnemonic == .ldlarh)
    }
}
