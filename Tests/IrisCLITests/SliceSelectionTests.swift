// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisCLICore
import Testing

/// Validates fat-binary slice selection: the documented default
/// preference (arm64e, then arm64, then any ARM64-cputype slice),
/// strict `--arch` matching, fat64 headers, and the little-endian fat
/// container shapes no Apple tool emits but the walker still survives.
@Suite("Fat slice selection")
struct SliceSelectionTests {
    @Test func defaultPrefersARM64E() throws {
        let binary = try #require(walkedBinary(cliFixturePath("hello-fat")))
        #expect(binary.architecture == "arm64e")
        #expect(binary.features == .arm64e)
    }

    @Test func explicitSelectionPicksEachSlice() throws {
        let arm64 = try #require(walkedBinary(cliFixturePath("hello-fat"), arch: .arm64))
        #expect(arm64.architecture == "arm64")
        #expect(arm64.features == [])
        let arm64e = try #require(walkedBinary(cliFixturePath("hello-fat"), arch: .arm64e))
        #expect(arm64e.architecture == "arm64e")
        #expect(arm64e.features == .arm64e)
    }

    @Test func fat64HeadersWalkIdentically() throws {
        let fat32 = try #require(walkedBinary(cliFixturePath("hello-fat")))
        let fat64 = try #require(walkedBinary(cliFixturePath("hello-fat64")))
        #expect(fat64.architecture == fat32.architecture)
        #expect(fat64.codeSections.map(\.displayName) == fat32.codeSections.map(\.displayName))
        #expect(fat64.functionStarts == fat32.functionStarts)

        let explicit = try #require(walkedBinary(cliFixturePath("hello-fat64"), arch: .arm64))
        #expect(explicit.architecture == "arm64")
    }

    @Test func selectionFallsBackToPlainARM64() throws {
        // A fat holding only an arm64 slice: the arm64e preference
        // misses, the arm64 preference selects.
        let slice = minimalBinary(words: [0xD503_201F])
        let binary = try #require(walkedBinary(bytes: littleEndianFat(slices: [(0x0100_000C, 0, slice)])))
        #expect(binary.architecture == "arm64")
    }

    @Test func selectionFallsBackToUnknownARM64Subtype() throws {
        // A fat holding only an unknown-subtype ARM64 slice: both named
        // preferences miss; the cputype fallback decodes it as base ISA
        // and its name reveals the oddity.
        var slice = minimalBinary(words: [0xD503_201F])
        slice.replaceSubrange(8 ..< 12, with: [9, 0, 0, 0]) // cpusubtype 9
        let binary = try #require(walkedBinary(bytes: littleEndianFat(slices: [(0x0100_000C, 9, slice)])))
        #expect(binary.architecture == "arm64 (subtype 9)")
        #expect(binary.features == [])
    }

    @Test func defaultRejectsNonARMFat() throws {
        let slice = minimalBinary(words: [0xD503_201F])
        let fat = littleEndianFat(slices: [(0x0100_0007, 3, slice)])
        let unavailable = try #require(archUnavailableOutcome(walkBytes(fat)))
        #expect(unavailable.requested == nil)
        #expect(unavailable.available == ["x86_64"])
    }

    @Test func littleEndianFat64Walks() throws {
        // The 64-bit little-endian container (cafebabf written LE): the
        // remaining corner of the four magic/endianness combinations.
        let slice = minimalBinary(words: [0xD503_201F])
        let binary = try #require(walkedBinary(bytes: littleEndianFat(slices: [(0x0100_000C, 0, slice)], is64: true)))
        #expect(binary.architecture == "arm64")
    }

    @Test func availableNamesEveryUnselectableSlice() throws {
        let outcome = MachOWalker.walk(path: cliFixturePath("hello-fat"), arch: nil)
        let binary = try #require(binaryOutcome(outcome))
        #expect(binary.architecture == "arm64e")

        let slice = minimalBinary(words: [0xD503_201F])
        let fat = littleEndianFat(slices: [(0x0100_0007, 3, slice), (0x0000_000C, 9, slice)])
        let unavailable = try #require(archUnavailableOutcome(walkBytes(fat)))
        #expect(unavailable.available == ["x86_64", "arm"])
    }

    @Test func archSelectionFeatureMapping() {
        #expect(ArchSelection.arm64.features == [])
        #expect(ArchSelection.arm64e.features == .arm64e)
        #expect(ArchSelection(rawValue: "arm64") == .arm64)
        #expect(ArchSelection(rawValue: "arm64e") == .arm64e)
        #expect(ArchSelection(rawValue: "armv7") == nil)
        #expect(ArchSelection.allCases == [.arm64, .arm64e])
    }
}

/// Assemble a little-endian fat container (a shape no Apple tool emits;
/// real fat headers are big-endian) holding the given
/// `(cputype, cpusubtype, slice)` triples back to back.
func littleEndianFat(slices: [(cputype: UInt32, cpusubtype: UInt32, bytes: [UInt8])], is64: Bool = false) -> [UInt8] {
    var a = MachOAssembler(bigEndian: false)
    a.u32(is64 ? 0xCAFE_BABF : 0xCAFE_BABE)
    a.u32(UInt32(slices.count))
    let archSize = is64 ? 32 : 20
    var offset = 8 + archSize * slices.count
    for slice in slices {
        a.u32(slice.cputype)
        a.u32(slice.cpusubtype)
        if is64 {
            a.u64(UInt64(offset))
            a.u64(UInt64(slice.bytes.count))
            a.u32(0) // align
            a.u32(0) // reserved
        } else {
            a.u32(UInt32(offset))
            a.u32(UInt32(slice.bytes.count))
            a.u32(0) // align
        }
        offset += slice.bytes.count
    }
    for slice in slices {
        a.bytes.append(contentsOf: slice.bytes)
    }
    return a.bytes
}
