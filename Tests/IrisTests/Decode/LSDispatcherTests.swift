// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the L/S family's dispatch behavior through the public
/// surface: op0 routing into the family, the V=1 deferral, and the
/// second-level (bits 29:24, bit 21, bits 11:10, bit 23/31)
/// sub-dispatch to every per-class sub-decoder.
@Suite("L/S dispatcher routing")
struct LSDispatcherTests {
    @Test func gprLoadStoreOp0PartitionsAttributeToTheFamily() {
        // V=0 witnesses in the x1x0 slab: STXR (op0=0x4), LDR (op0=0xC).
        #expect(decode(0x8800_7C00).category == .loadsAndStores)
        #expect(decode(0xF940_0021).category == .loadsAndStores)
    }

    @Test func vEqualsOneIsDelegatedToSIMDFP() {
        // op0=0x6 carries bit26=V=1; the L/S decoder delegates to
        // SIMDAndFPDecoder.decodeVectorLoadStore. The exact encoding
        // 0x0C000000 decodes as a NEON LD/ST multi-structure form: ST4
        // {V0.8B, V1.8B, V2.8B, V3.8B}, [X0]. The L/S → SIMD/FP delegation
        // means the returned draft has category == .simdAndFP, NOT .undefined
        // (the old V=1 deferral behaviour).
        let d = decode(0x0C00_0000, at: 0)
        #expect(d.category == .simdAndFP)
        #expect(d.mnemonic == .st4)
    }

    @Test func loadLiteralRoute() {
        // 0x18000000 = ldr w0, #0 — bits[29:24] = 011000.
        #expect(decode(0x1800_0000, at: 0).mnemonic == .ldr)
    }

    @Test func exclusiveAndOrderedRoute() {
        // 0x88007c00 = stxr w0, w0, [x0] — bits[29:24]=001000, bit21=0.
        #expect(decode(0x8800_7C00, at: 0).mnemonic == .stxr)
    }

    @Test func compareAndSwapRoute() {
        // 0x88a07c00 = cas w0, w0, [x0] — 001000, bit21=1, bit23=1.
        #expect(decode(0x88A0_7C00, at: 0).mnemonic == .cas)
    }

    @Test func compareAndSwapPairRoute() {
        // 0x08207c00 = casp w0, w1, w0, w1, [x0] — 001000, bit21=1, bit23=0, bit31=0.
        #expect(decode(0x0820_7C00, at: 0).mnemonic == .casp)
    }

    @Test func exclusivePairRoute() {
        // 0xc87f0440 = ldxp x0, x1, [x2] — 001000, bit21=1, bit23=0, bit31=1.
        #expect(decode(0xC87F_0440, at: 0).mnemonic == .ldxp)
    }

    @Test func loadStorePairRoute() {
        // 0x28000000 = stnp w0, w0, [x0] — bits[29:24]=101000.
        #expect(decode(0x2800_0000, at: 0).mnemonic == .stnp)
    }

    @Test func unscaledRoute() {
        // 0xb8000000 = stur w0, [x0] — 111000, bit21=0, bits11:10=00.
        #expect(decode(0xB800_0000, at: 0).mnemonic == .stur)
    }

    @Test func postIndexedRoute() {
        // 0xb8400400 = ldr w0, [x0], #0 — 111000, bit21=0, bits11:10=01.
        let d = decode(0xB840_0400, at: 0)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), writeback: .postIndex)))
    }

    @Test func unprivilegedRoute() {
        // 0xb8000800 = sttr w0, [x0] — 111000, bit21=0, bits11:10=10.
        #expect(decode(0xB800_0800, at: 0).mnemonic == .sttr)
    }

    @Test func preIndexedRoute() {
        // 0xf8400c00 = ldr x0, [x0, #0]! — 111000, bit21=0, bits11:10=11.
        let d = decode(0xF840_0C00, at: 0)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), writeback: .preIndex)))
    }

    @Test func ldaprRoute() {
        // 0x38bfc000 = ldaprb w0, [x0] — 111000, bit21=1, bits11:10=00, LDAPR pattern.
        #expect(decode(0x38BF_C000, at: 0).mnemonic == .ldaprb)
    }

    @Test func lseAtomicRoute() {
        // 0x38200000 = ldaddb w0, w0, [x0] — 111000, bit21=1, bits11:10=00, not LDAPR.
        #expect(decode(0x3820_0000, at: 0).mnemonic == .ldaddb)
    }

    @Test func registerOffsetRoute() {
        // 0x38204800 = strb w0, [x0, w0, uxtw] — 111000, bit21=1, bits11:10=10.
        #expect(decode(0x3820_4800, at: 0).mnemonic == .strb)
    }

    @Test func unsignedOffsetRoute() {
        // 0xb9000000 = str w0, [x0] — bits[29:24] = 111001.
        #expect(decode(0xB900_0000, at: 0).mnemonic == .str)
    }

    @Test func lrcpc2Route() {
        // 0x99000000 = stlur w0, [x0] — bits[29:24] = 011001.
        #expect(decode(0x9900_0000, at: 0).mnemonic == .stlur)
    }

    @Test func ldraRouteUnderArm64E() {
        // 0xf8200400 = ldraa x0, [x0] — 111000, bit21=1, bits11:10=01.
        #expect(decode(0xF820_0400, at: 0, features: .arm64e).mnemonic == .ldraa)
    }

    @Test func ldraIsUndefinedOutsideArm64E() {
        // The LDRAA encoding is unallocated on plain ARM64.
        let d = decode(0xF820_0400, at: 0)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
    }

    @Test func ldraPreIndexRouteUnderArm64E() {
        // 0xf8200c00 = ldraa x0, [x0, #0]! — bits11:10=11.
        #expect(decode(0xF820_0C00, at: 0, features: .arm64e).mnemonic == .ldraa)
    }

    @Test func unroutedSecondLevelDiscriminatorReturnsUndefined() {
        // op0=0x4, bit29=0, bit24=1, V=0 → bits[29:24]=001001, which no
        // L/S sub-class claims → the dispatcher's terminal UNDEFINED.
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

/// Verifies the standard family composition routes the full x1x0 slab
/// (op0 ∈ {0x4, 0x6, 0xC, 0xE}) to the L/S family — asserted through
/// public category attribution (the V=1 halves of the slab delegate to
/// the SIMD/FP family by design).
@Suite("L/S standard family registration")
struct LSStandardDecoderSetTests {
    @Test func everyLoadStoreOp0RoutesToTheFamily() {
        // V=0 witnesses at op0 0x4 / 0xC attribute to L/S; the V=1
        // op0 0x6 / 0xE witnesses surface as SIMD/FP (delegated).
        #expect(decode(0x8800_7C00).category == .loadsAndStores) // op0=0x4 stxr
        #expect(decode(0xF940_0021).category == .loadsAndStores) // op0=0xC ldr
        #expect(decode(0x0C00_0000).category == .simdAndFP) //     op0=0x6 V=1
        #expect(decode(0x3DC0_0000).category == .simdAndFP) //     op0=0xE V=1
    }

    @Test func machineCodeDispatchRoutesLoadStoreEncodings() {
        let d = decode(0x1800_0000, at: 0)
        #expect(d.mnemonic == .ldr)
        #expect(d.category == .loadsAndStores)
    }
}
