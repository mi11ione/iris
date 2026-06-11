// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

@_spi(Validation) import Iris
import Testing

/// Validates the shared L/S op0 predicate `isLoadStoreEncoding` in
/// `LSCommon.swift` — membership in the x1x0 (bits[28:25]) encoding slab.
@Suite("L/S common helpers")
struct LSCommonHelperTests {
    @Test func isLoadStoreEncodingMatchesTheX1X0Op0Slab() {
        // op0 (bits[28:25]) ∈ {0x4, 0x6, 0xC, 0xE} is the L/S slab.
        for op0: UInt32 in 0 ... 15 {
            let encoding = op0 << 25
            let expected = (op0 == 0x4 || op0 == 0x6 || op0 == 0xC || op0 == 0xE)
            #expect(isLoadStoreEncoding(encoding) == expected, "op0=\(op0)")
        }
    }

    @Test func isLoadStoreEncodingAcceptsRealLoadStoreWords() {
        // Corpus-verified L/S encodings across several op0 values.
        #expect(isLoadStoreEncoding(0x8800_7C00)) // stxr — op0 0x4
        #expect(isLoadStoreEncoding(0xB800_0000)) // stur — op0 0xC
        #expect(isLoadStoreEncoding(0x1800_0000)) // ldr literal — op0 0xC
    }

    @Test func isLoadStoreEncodingRejectsOtherFamilies() {
        #expect(!isLoadStoreEncoding(0x8B02_0020)) // add — op0 0x5
        #expect(!isLoadStoreEncoding(0x1400_0000)) // b — op0 0x2
    }
}
