// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisValidation
import Testing

/// Validates the shared L/S op0 predicate `isLoadStoreEncoding` in
/// `LSCommon.swift`.
@Suite("L/S common helpers")
struct LSCommonHelperTests {
    @Test func isLoadStoreEncodingMatchesTheX1X0Op0Slab() {
        for op0: UInt32 in 0 ... 15 {
            let encoding = op0 << 25
            let expected = (op0 == 0x4 || op0 == 0x6 || op0 == 0xC || op0 == 0xE)
            #expect(isLoadStoreEncoding(encoding) == expected, "op0=\(op0)")
        }
    }

    @Test func isLoadStoreEncodingAcceptsRealLoadStoreWords() {
        #expect(isLoadStoreEncoding(0x8800_7C00))
        #expect(isLoadStoreEncoding(0xB800_0000))
        #expect(isLoadStoreEncoding(0x1800_0000))
    }

    @Test func isLoadStoreEncodingRejectsOtherFamilies() {
        #expect(!isLoadStoreEncoding(0x8B02_0020))
        #expect(!isLoadStoreEncoding(0x1400_0000))
    }
}
