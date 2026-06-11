// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisCLICore
import Testing

/// Validates `LC_FUNCTION_STARTS` ULEB128 decoding: anchoring at the
/// `__TEXT` vmaddr, multi-byte deltas, the zero-delta terminator, and
/// the malformed-stream degradations (oversized values, truncation
/// mid-value, cumulative overflow, missing anchor segment).
@Suite("Function starts decoding")
struct FunctionStartsTests {
    /// A one-section binary (`__TEXT` at `textAddr`) whose
    /// `LC_FUNCTION_STARTS` payload is exactly `uleb`.
    func binaryWithStarts(uleb: [UInt8], textAddr: UInt64 = 0x1000) -> WalkedBinary? {
        let bytes = minimalBinary(words: [0xD503_201F], textAddr: textAddr, extraSize: 16, extraCommands: { a in
            a.linkeditDataCommand(cmd: 0x26, dataoff: 264, datasize: UInt32(uleb.count))
        }, trailer: { a in
            a.pad(to: 264)
            a.bytes.append(contentsOf: uleb)
        })
        return walkedBinary(bytes: bytes)
    }

    @Test func fixtureStartsMatchSymbolAddresses() throws {
        let binary = try #require(walkedBinary(cliFixturePath("hello-arm64")))
        #expect(binary.functionStarts == binary.functionStarts.sorted())
        let labels = binary.functionStarts.compactMap { binary.symbols.name(at: $0) }
        #expect(labels.sorted() == ["_add42", "_helper", "_main", "_sum_to"])
    }

    @Test func singleByteDeltasAccumulate() throws {
        let binary = try #require(binaryWithStarts(uleb: [0x10, 0x08, 0x04, 0x00]))
        #expect(binary.functionStarts == [0x1010, 0x1018, 0x101C])
    }

    @Test func multiByteDeltaDecodes() throws {
        // 0xE8 0x07 = 0x3E8 = 1000.
        let binary = try #require(binaryWithStarts(uleb: [0xE8, 0x07, 0x00]))
        #expect(binary.functionStarts == [0x1000 + 1000 as UInt64])
    }

    @Test func zeroDeltaTerminatesEarly() throws {
        let binary = try #require(binaryWithStarts(uleb: [0x08, 0x00, 0x10, 0x10]))
        #expect(binary.functionStarts == [0x1008])
        #expect(binary.diagnostics.isEmpty)
    }

    @Test func streamWithoutTerminatorStopsAtEnd() throws {
        // No zero delta: the loop consumes the whole region and stops.
        let binary = try #require(binaryWithStarts(uleb: [0x08, 0x04]))
        #expect(binary.functionStarts == [0x1008, 0x100C])
        #expect(binary.diagnostics.isEmpty)
    }

    @Test func valueWiderThan64BitsIsDiagnosed() throws {
        // Ten 0x80 continuation bytes push shift past 63 before any
        // terminator: the walker keeps what it has and diagnoses.
        let uleb: [UInt8] = [0x08] + [UInt8](repeating: 0x80, count: 10) + [0x01]
        let binary = try #require(binaryWithStarts(uleb: uleb))
        let diagnostic = try #require(binary.diagnostics.first { $0.kind == .functionStartsMalformed })
        #expect(diagnostic.detail == "ULEB128 value exceeds 64 bits; keeping the 1 addresses decoded so far")
        #expect(binary.functionStarts == [0x1008])
    }

    @Test func truncationMidValueIsDiagnosed() throws {
        // The last byte carries a continuation bit with nothing after it.
        let binary = try #require(binaryWithStarts(uleb: [0x08, 0x80]))
        let diagnostic = try #require(binary.diagnostics.first { $0.kind == .functionStartsMalformed })
        #expect(diagnostic.detail == "ULEB128 stream ends mid-value; keeping the 1 addresses decoded so far")
        #expect(binary.functionStarts == [0x1008])
    }

    @Test func cumulativeOverflowIsDiagnosed() throws {
        // __TEXT vmaddr at the top of the address space; one delta of
        // 0x80 (0x80 0x01) overflows the cumulative address.
        let binary = try #require(binaryWithStarts(uleb: [0x80, 0x01], textAddr: UInt64.max - 0x40))
        let diagnostic = try #require(binary.diagnostics.first { $0.kind == .functionStartsMalformed })
        #expect(diagnostic.detail == "cumulative address overflows UInt64; keeping the 0 addresses decoded so far")
        #expect(binary.functionStarts.isEmpty)
    }

    @Test func missingTextSegmentLeavesStartsUnanchored() throws {
        // The deltas are anchored at __TEXT's vmaddr; without that
        // segment the chain is meaningless and is dropped, diagnosed.
        var a = MachOAssembler()
        a.machHeader64(ncmds: 2, sizeofcmds: 72 + 80 + 16)
        a.segmentCommand64(name: "__CODE", vmaddr: 0x1000, nsects: 1, cmdsize: 72 + 80)
        a.section64(sectname: "__text", segname: "__CODE", addr: 0x1000, size: 4, offset: 256, flags: someInstructions)
        a.linkeditDataCommand(cmd: 0x26, dataoff: 260, datasize: 2)
        a.pad(to: 256)
        a.u32(0xD503_201F)
        a.bytes.append(contentsOf: [0x08, 0x00])
        let binary = try #require(walkedBinary(bytes: a.bytes))
        let diagnostic = try #require(binary.diagnostics.first { $0.kind == .functionStartsUnanchored })
        #expect(diagnostic.detail == "LC_FUNCTION_STARTS present but the slice has no __TEXT segment; ignored")
        #expect(binary.functionStarts.isEmpty)
    }

    @Test func emptyRegionYieldsNoStarts() throws {
        let binary = try #require(binaryWithStarts(uleb: []))
        #expect(binary.functionStarts.isEmpty)
        #expect(binary.diagnostics.isEmpty)
    }
}
