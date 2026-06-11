// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisCLICore
import Testing

/// Validates `LC_DATA_IN_CODE` handling: rebase into section buffer
/// space under both offset conventions (file offsets in linked images,
/// section-address-space offsets in MH_OBJECT), span kinds, straddling
/// and degenerate entries, and the resulting data-marker records.
@Suite("Data-in-code rebase")
struct DataInCodeRebaseTests {
    @Test func objectFileSpansUseSectionAddressSpace() throws {
        let binary = try #require(walkedBinary(cliFixturePath("dic-arm64.o")))
        let text = try #require(binary.codeSections.first { $0.sectionName == "__text" })
        #expect(text.dataInCode == [
            DataInCodeSpan(offset: 0x48, length: 4, kind: .jumpTable8),
            DataInCodeSpan(offset: 0x4C, length: 4, kind: .data),
        ])
    }

    @Test func linkedImageSpansUseFileOffsets() throws {
        let binary = try #require(walkedBinary(cliFixturePath("dic-linked")))
        let text = try #require(binary.codeSections.first { $0.sectionName == "__text" })
        // Same code, same in-section placement — the rebase result is
        // identical even though the on-disk convention differs.
        #expect(text.dataInCode == [
            DataInCodeSpan(offset: 0x48, length: 4, kind: .jumpTable8),
            DataInCodeSpan(offset: 0x4C, length: 4, kind: .data),
        ])
    }

    @Test func markedWordsDecodeAsDataNotGarbage() throws {
        let binary = try #require(walkedBinary(cliFixturePath("dic-linked")))
        let text = try #require(binary.codeSections.first { $0.sectionName == "__text" })
        let stream = text.instructions(features: binary.features)
        let markers = stream.filter { $0.category == .dataInCodeMarker }
        #expect(markers.count == 2)
        #expect(markers.map(\.encoding) == [0x0604_0200, 0xDEAD_BEEF])
        // 0xdeadbeef would otherwise decode as an instruction-like word;
        // the marker proves loader knowledge overrode byte plausibility.
        #expect(markers.allSatisfy { $0.text.hasPrefix(".long ") })
    }

    @Test func straddlingEntryIsClampedWithDiagnostic() throws {
        // One 8-byte DIC entry whose second half runs past the section's
        // end: the in-section half is kept, the loss is diagnosed.
        let bytes = minimalBinary(words: [0xD503_201F, 0x0000_002A], extraSize: 16, extraCommands: { a in
            a.linkeditDataCommand(cmd: 0x29, dataoff: 264, datasize: 8)
        }, trailer: { a in
            a.pad(to: 264)
            a.dataInCodeEntry(offset: 260, length: 8, kind: 1)
        })
        let binary = try #require(walkedBinary(bytes: bytes))
        let diagnostic = try #require(binary.diagnostics.first { $0.kind == .dataInCodeEntryClamped })
        #expect(diagnostic.detail == "data-in-code entry 0 [260, +8) straddles a code-section boundary; kept 4 bytes")
        let text = try #require(binary.codeSections.first)
        #expect(text.dataInCode == [DataInCodeSpan(offset: 4, length: 4, kind: .data)])
    }

    @Test func zeroLengthEntryIsIgnored() throws {
        let bytes = minimalBinary(words: [0xD503_201F], extraSize: 16, extraCommands: { a in
            a.linkeditDataCommand(cmd: 0x29, dataoff: 264, datasize: 8)
        }, trailer: { a in
            a.pad(to: 264)
            a.dataInCodeEntry(offset: 256, length: 0, kind: 1)
        })
        let binary = try #require(walkedBinary(bytes: bytes))
        let text = try #require(binary.codeSections.first)
        #expect(text.dataInCode.isEmpty)
        #expect(!binary.diagnostics.map(\.kind).contains(.dataInCodeEntryOutsideCode))
    }

    @Test func raggedTableDecodesWholeEntries() throws {
        // datasize 12 is one whole entry plus four stray bytes: the
        // floor prefix decodes, the remainder is diagnosed.
        let bytes = minimalBinary(words: [0xD503_201F, 0x0000_002A], extraSize: 16, extraCommands: { a in
            a.linkeditDataCommand(cmd: 0x29, dataoff: 264, datasize: 12)
        }, trailer: { a in
            a.pad(to: 264)
            a.dataInCodeEntry(offset: 260, length: 4, kind: 4)
            a.u32(0xFFFF_FFFF)
        })
        let binary = try #require(walkedBinary(bytes: bytes))
        let diagnostic = try #require(binary.diagnostics.first { $0.kind == .dataInCodeRegionTruncated })
        #expect(diagnostic.detail == "LC_DATA_IN_CODE datasize 12 is not a multiple of 8; decoding 1 whole entries")
        let text = try #require(binary.codeSections.first)
        #expect(text.dataInCode == [DataInCodeSpan(offset: 4, length: 4, kind: .jumpTable32)])
    }

    @Test func unknownKindRoundTrips() throws {
        let bytes = minimalBinary(words: [0xD503_201F, 0x1234_5678], extraSize: 16, extraCommands: { a in
            a.linkeditDataCommand(cmd: 0x29, dataoff: 264, datasize: 8)
        }, trailer: { a in
            a.pad(to: 264)
            a.dataInCodeEntry(offset: 260, length: 4, kind: 0x99)
        })
        let binary = try #require(walkedBinary(bytes: bytes))
        let text = try #require(binary.codeSections.first)
        #expect(text.dataInCode == [DataInCodeSpan(offset: 4, length: 4, kind: .unknown(rawValue: 0x99))])
    }

    @Test func entryCoveringTwoSectionsSplits() throws {
        // Two adjacent code sections with one DIC entry spanning the
        // boundary: each section receives its in-bounds part, no
        // diagnostic (every byte is accounted for).
        var a = MachOAssembler()
        a.machHeader64(ncmds: 2, sizeofcmds: 72 + 160 + 16)
        a.segmentCommand64(name: "__TEXT", vmaddr: 0x1000, nsects: 2, cmdsize: 72 + 160)
        a.section64(sectname: "__text", segname: "__TEXT", addr: 0x1000, size: 8, offset: 512, flags: someInstructions)
        a.section64(sectname: "__more", segname: "__TEXT", addr: 0x1008, size: 8, offset: 520, flags: someInstructions)
        a.linkeditDataCommand(cmd: 0x29, dataoff: 528, datasize: 8)
        a.pad(to: 512)
        for word in [0xD503_201F, 0x0000_002A, 0x0000_002B, 0xD65F_03C0] as [UInt32] {
            a.u32(word)
        }
        a.dataInCodeEntry(offset: 516, length: 8, kind: 1)
        let binary = try #require(walkedBinary(bytes: a.bytes))
        #expect(binary.diagnostics.isEmpty)
        #expect(binary.codeSections.count == 2)
        #expect(binary.codeSections[0].dataInCode == [DataInCodeSpan(offset: 4, length: 4, kind: .data)])
        #expect(binary.codeSections[1].dataInCode == [DataInCodeSpan(offset: 0, length: 4, kind: .data)])
    }

    @Test func emptyTableProducesNoSpans() throws {
        let bytes = minimalBinary(words: [0xD503_201F], extraSize: 16, extraCommands: { a in
            a.linkeditDataCommand(cmd: 0x29, dataoff: 0, datasize: 0)
        })
        let binary = try #require(walkedBinary(bytes: bytes))
        let text = try #require(binary.codeSections.first)
        #expect(text.dataInCode.isEmpty)
        #expect(binary.diagnostics.isEmpty)
    }

    @Test func listingRendersKindVocabulary() {
        let renderer = ListingRenderer(palette: Palette(enabled: false), includeSemantics: false)
        #expect(renderer.kindName(.data) == "data")
        #expect(renderer.kindName(.jumpTable8) == "jump-table-8")
        #expect(renderer.kindName(.jumpTable16) == "jump-table-16")
        #expect(renderer.kindName(.jumpTable32) == "jump-table-32")
        #expect(renderer.kindName(.absoluteJumpTable32) == "abs-jump-table-32")
        #expect(renderer.kindName(.unknown(rawValue: 0x99)) == "kind-0x99")
    }
}
