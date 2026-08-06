// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates L/S dispatch through the public surface.
@Suite("L/S dispatcher routing")
struct LSDispatcherTests {
    @Test func gprLoadStoreOp0PartitionsAttributeToTheFamily() {
        #expect(decode(0x8800_7C00).category == .loadsAndStores)
        #expect(decode(0xF940_0021).category == .loadsAndStores)
    }

    @Test func vEqualsOneIsDelegatedToSIMDFP() {
        let d = decode(0x0C00_0000, at: 0)
        #expect(d.category == .simdAndFP)
        #expect(d.mnemonic == .st4)
    }

    @Test func loadLiteralRoute() {
        #expect(decode(0x1800_0000, at: 0).mnemonic == .ldr)
    }

    @Test func exclusiveAndOrderedRoute() {
        #expect(decode(0x8800_7C00, at: 0).mnemonic == .stxr)
    }

    @Test func compareAndSwapRoute() {
        #expect(decode(0x88A0_7C00, at: 0).mnemonic == .cas)
    }

    @Test func compareAndSwapPairRoute() {
        #expect(decode(0x0820_7C00, at: 0).mnemonic == .casp)
    }

    @Test func exclusivePairRoute() {
        #expect(decode(0xC87F_0440, at: 0).mnemonic == .ldxp)
    }

    @Test func loadStorePairRoute() {
        #expect(decode(0x2800_0000, at: 0).mnemonic == .stnp)
    }

    @Test func unscaledRoute() {
        #expect(decode(0xB800_0000, at: 0).mnemonic == .stur)
    }

    @Test func postIndexedRoute() {
        let d = decode(0xB840_0400, at: 0)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), writeback: .postIndex)))
    }

    @Test func unprivilegedRoute() {
        #expect(decode(0xB800_0800, at: 0).mnemonic == .sttr)
    }

    @Test func preIndexedRoute() {
        let d = decode(0xF840_0C00, at: 0)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), writeback: .preIndex)))
    }

    @Test func ldaprRoute() {
        #expect(decode(0x38BF_C000, at: 0).mnemonic == .ldaprb)
    }

    @Test func lseAtomicRoute() {
        #expect(decode(0x3820_0000, at: 0).mnemonic == .ldaddb)
    }

    @Test func registerOffsetRoute() {
        #expect(decode(0x3820_4800, at: 0).mnemonic == .strb)
    }

    @Test func unsignedOffsetRoute() {
        #expect(decode(0xB900_0000, at: 0).mnemonic == .str)
    }

    @Test func lrcpc2Route() {
        #expect(decode(0x9900_0000, at: 0).mnemonic == .stlur)
    }

    @Test func ldraRouteUnderArm64E() {
        #expect(decode(0xF820_0400, at: 0, features: .arm64e).mnemonic == .ldraa)
    }

    @Test func ldraIsUndefinedOutsideArm64E() {
        let d = decode(0xF820_0400, at: 0)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
    }

    @Test func ldraPreIndexRouteUnderArm64E() {
        #expect(decode(0xF820_0C00, at: 0, features: .arm64e).mnemonic == .ldraa)
    }

    @Test func unroutedSecondLevelDiscriminatorReturnsUndefined() {
        let d = decode(0x0900_0000, at: 0)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
    }

    @Test func addressAndEncodingPropagateToDraft() {
        let d = decode(0x1800_0000, at: 0xFEED)
        #expect(d.address == 0xFEED)
        #expect(d.encoding == 0x1800_0000)
    }

    @Test func undefinedDraftPreservesRawEncoding() {
        let d = decode(0x0C00_0000, at: 0)
        #expect(d.encoding == 0x0C00_0000)
    }
}

/// Verifies the standard composition routes the x1x0 slab to L/S, asserted
/// through public category attribution; the V=1 halves delegate to SIMD/FP.
@Suite("L/S standard family registration")
struct LSStandardDecoderSetTests {
    @Test func everyLoadStoreOp0RoutesToTheFamily() {
        #expect(decode(0x8800_7C00).category == .loadsAndStores)
        #expect(decode(0xF940_0021).category == .loadsAndStores)
        #expect(decode(0x0C00_0000).category == .simdAndFP)
        #expect(decode(0x3DC0_0000).category == .simdAndFP)
    }

    @Test func machineCodeDispatchRoutesLoadStoreEncodings() {
        let d = decode(0x1800_0000, at: 0)
        #expect(d.mnemonic == .ldr)
        #expect(d.category == .loadsAndStores)
    }
}
