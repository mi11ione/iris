// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import IrisCLICore
import Testing

/// Validates the address-keyed symbol index: exact and
/// closest-preceding lookup, range queries, first-wins deduplication,
/// and the empty index.
@Suite("Symbol index lookup")
struct SymbolIndexTests {
    let index = SymbolIndex(symbols: [
        (0x1000, "_alpha"),
        (0x1040, "_beta"),
        (0x1100, "_gamma"),
    ])

    @Test func exactLookup() {
        #expect(index.name(at: 0x1000) == "_alpha")
        #expect(index.name(at: 0x1040) == "_beta")
        #expect(index.name(at: 0x1100) == "_gamma")
        #expect(index.name(at: 0x1041) == nil)
        #expect(index.name(at: 0x0FFF) == nil)
        #expect(index.name(at: 0x2000) == nil)
        #expect(index.count == 3)
    }

    /// Whether an optional `(address, name)` pair equals the expectation.
    func matches(_ pair: (address: UInt64, name: String)?, _ address: UInt64, _ name: String) -> Bool {
        pair?.address == address && pair?.name == name
    }

    @Test func closestPrecedingLookup() {
        #expect(matches(index.nearest(atOrBefore: 0x1000), 0x1000, "_alpha"))
        #expect(matches(index.nearest(atOrBefore: 0x103F), 0x1000, "_alpha"))
        #expect(matches(index.nearest(atOrBefore: 0x1040), 0x1040, "_beta"))
        #expect(matches(index.nearest(atOrBefore: 0xFFFF_FFFF), 0x1100, "_gamma"))
        #expect(index.nearest(atOrBefore: 0x0FFF) == nil)
    }

    @Test func rangeQuery() {
        let middle = index.symbols(in: 0x1001 ..< 0x1100)
        #expect(middle.count == 1)
        #expect(matches(middle.first, 0x1040, "_beta"))
        let all = index.symbols(in: 0 ..< UInt64.max)
        #expect(all.map(\.name) == ["_alpha", "_beta", "_gamma"])
        #expect(index.symbols(in: 0x2000 ..< 0x3000).isEmpty)
    }

    @Test func firstEntryWinsSharedAddress() {
        let dup = SymbolIndex(symbols: [(0x10, "_external"), (0x10, "ltmp0"), (0x20, "_other")])
        #expect(dup.count == 2)
        #expect(dup.name(at: 0x10) == "_external")
    }

    @Test func unsortedInputIsIndexed() {
        let shuffled = SymbolIndex(symbols: [(0x30, "_c"), (0x10, "_a"), (0x20, "_b")])
        #expect(shuffled.symbols(in: 0 ..< 0x40).map(\.name) == ["_a", "_b", "_c"])
        #expect(matches(shuffled.nearest(atOrBefore: 0x25), 0x20, "_b"))
    }

    @Test func emptyIndex() {
        #expect(SymbolIndex.empty.count == 0)
        #expect(SymbolIndex.empty.name(at: 0) == nil)
        #expect(SymbolIndex.empty.nearest(atOrBefore: .max) == nil)
        #expect(SymbolIndex.empty.symbols(in: 0 ..< .max).isEmpty)
    }
}
