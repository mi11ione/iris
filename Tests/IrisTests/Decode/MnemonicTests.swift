// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates Mnemonic — UInt16 raw-value wrapper, the three decoder
/// sentinels, and the public per-family raw-value range allocation
/// table.
@Suite("Mnemonic / decoder sentinels and raw-value round-trip")
struct MnemonicSentinelTests {
    @Test func undefinedSentinelHasRawZero() {
        #expect(Mnemonic.undefined.rawValue == 0)
    }

    @Test func dataMarkerSentinelHasRawOne() {
        #expect(Mnemonic.dataMarker.rawValue == 1)
    }

    @Test func truncatedTailSentinelHasRawTwo() {
        #expect(Mnemonic.truncatedTail.rawValue == 2)
    }

    @Test func arbitraryRawValueRoundTrips() {
        for raw: UInt16 in [0, 1, 2, 42, 256, 1024, 6144, 12288, 16383, 65535] {
            #expect(Mnemonic(rawValue: raw).rawValue == raw)
        }
    }

    @Test func sentinelsAreDistinct() {
        #expect(Mnemonic.undefined != Mnemonic.dataMarker)
        #expect(Mnemonic.dataMarker != Mnemonic.truncatedTail)
        #expect(Mnemonic.undefined != Mnemonic.truncatedTail)
    }

    @Test func equalMnemonicsHashEqual() {
        let a = Mnemonic(rawValue: 42)
        let b = Mnemonic(rawValue: 42)
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }
}

/// Validates Mnemonic.allocations — the per-family raw-value range
/// table the slab allocation publishes.
@Suite("Mnemonic / per-family range allocations")
struct MnemonicAllocationTests {
    @Test func sentinelRangeContainsAllThreeSentinels() {
        let range = Mnemonic.allocations.first(where: { $0.label == "Sentinels & UDF" })?.range
        #expect(range != nil)
        #expect(range?.contains(Mnemonic.undefined.rawValue) == true)
        #expect(range?.contains(Mnemonic.dataMarker.rawValue) == true)
        #expect(range?.contains(Mnemonic.truncatedTail.rawValue) == true)
    }

    @Test func sevenAllocationsExist() {
        #expect(Mnemonic.allocations.count == 7)
    }

    @Test func allocationLabelsAreDistinct() {
        let labels = Mnemonic.allocations.map(\.label)
        #expect(Set(labels).count == labels.count)
    }

    @Test func allocationRangesDoNotOverlap() {
        let sorted = Mnemonic.allocations.sorted { $0.range.lowerBound < $1.range.lowerBound }
        for i in 1 ..< sorted.count {
            #expect(sorted[i].range.lowerBound > sorted[i - 1].range.upperBound,
                    "ranges \(sorted[i - 1].label) and \(sorted[i].label) overlap or touch")
        }
    }

    @Test func sentinelRangeStartsAtZero() {
        let sentinels = Mnemonic.allocations.first(where: { $0.label == "Sentinels & UDF" })
        #expect(sentinels?.range.lowerBound == 0)
    }

    @Test func everyAllocationLabelIsItsFamilyName() {
        // Labels are family names — exactly as published, in order.
        let labels = [
            "Sentinels & UDF",
            "Data Processing — Immediate",
            "Branches, Exception, System",
            "Loads & Stores",
            "Data Processing — Register",
            "SIMD & Floating-Point",
            "Crypto + Apple Extensions",
        ]
        #expect(Mnemonic.allocations.map(\.label) == labels)
    }

    @Test func allocationRangesArePinnedToExactBoundaries() {
        // Pin the exact range bounds (literal expectations — not recomputed
        // from the source — so any reshuffle is caught at the range
        // boundary, not at the first mnemonic declaration in the slab).
        let expected: [(label: String, lower: UInt16, upper: UInt16)] = [
            ("Sentinels & UDF", 0, 255),
            ("Data Processing — Immediate", 256, 1023),
            ("Branches, Exception, System", 1024, 2047),
            ("Loads & Stores", 2048, 4095),
            ("Data Processing — Register", 4096, 6143),
            ("SIMD & Floating-Point", 6144, 12287),
            ("Crypto + Apple Extensions", 12288, 16383),
        ]
        #expect(Mnemonic.allocations.count == expected.count)
        for (i, (label, lower, upper)) in expected.enumerated() {
            let actual = Mnemonic.allocations[i]
            #expect(actual.label == label, "label mismatch at index \(i)")
            #expect(actual.range.lowerBound == lower, "lowerBound mismatch at index \(i)")
            #expect(actual.range.upperBound == upper, "upperBound mismatch at index \(i)")
        }
    }
}
