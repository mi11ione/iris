// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisCLICore
import Testing

/// Validates listing mechanics the goldens cannot isolate.
@Suite("Listing renderer mechanics")
struct ListingRenderingTests {
    let plain = ListingRenderer(palette: Palette(enabled: false), includeSemantics: false)

    @Test func truncatedTailShowsResidualBytes() {
        let run = runCLI(["--bytes", "1f 20 03 d5 aa bb"])
        #expect(run.status == CLI.exitSuccess)
        #expect(run.stdout == "0: d503201f  nop\n4: bbaa      .byte 0xaa, 0xbb ; truncated tail\n")
    }

    @Test func oneByteTailColumn() {
        let run = runCLI(["--bytes", "1f 20 03 d5 7f"])
        #expect(run.stdout.contains("4: 7f        .byte 0x7f ; truncated tail\n"))
    }

    @Test func undefinedWordRendersAsSentinel() {
        let run = runCLI(["0x02000000"])
        #expect(run.stdout == "0: 02000000  .long 0x2000000 ; undefined\n")
    }

    @Test func undefinedWordInAnAllocatedTierIsAnnotatedToo() {
        let stream = InstructionStream(bytes: [0xFE, 0xB1, 0xDE, 0x80] as [UInt8])
        #expect(stream[0].isUndefined)
        #expect(stream[0].category != .undefined)
        let run = runCLI(["--bytes", "fe b1 de 80 86 47 be ef"])
        #expect(run.stdout == """
        0: 80deb1fe  .long 0x80deb1fe ; undefined
        4: efbe4786  .long 0xefbe4786 ; undefined

        """)
    }

    @Test func markerLineWithoutContextOmitsKind() throws {
        let binary = try #require(walkedBinary(cliFixturePath("dic-linked")))
        let text = try #require(binary.codeSections.first { $0.sectionName == "__text" })
        let stream = text.instructions(features: binary.features)
        let marker = try #require(stream.first { $0.category == .dataInCodeMarker })
        let line = plain.line(for: marker, addressWidth: 9, context: nil)
        #expect(line == "100003fb0: 06040200  .long 0x6040200")

        let context = ListingRenderer.Context(section: text, symbols: binary.symbols, sections: binary.codeSections)
        let annotated = plain.line(for: marker, addressWidth: 9, context: context)
        #expect(annotated == "100003fb0: 06040200  .long 0x6040200 ; data-in-code (jump-table-8)")
    }

    @Test func contextlessBranchIsNotSymbolicated() throws {
        let binary = try #require(walkedBinary(cliFixturePath("hello-arm64")))
        let text = try #require(binary.codeSections.first { $0.sectionName == "__text" })
        let stream = text.instructions(features: binary.features)
        let call = try #require(stream.first { $0.isCall })
        let bare = plain.line(for: call, addressWidth: 9, context: nil)
        #expect(bare.contains("bl 0x"))
        #expect(!bare.contains(";"))
    }

    @Test func crossSectionNearestSymbolIsSuppressed() throws {
        var a = MachOAssembler()
        a.machHeader64(ncmds: 2, sizeofcmds: 72 + 160 + 24)
        a.segmentCommand64(name: "__TEXT", vmaddr: 0x1000, nsects: 2, cmdsize: 72 + 160)
        a.section64(sectname: "__text", segname: "__TEXT", addr: 0x1000, size: 8, offset: 512, flags: someInstructions)
        a.section64(sectname: "__stubs", segname: "__TEXT", addr: 0x1008, size: 8, offset: 520, flags: someInstructions)
        a.symtabCommand(symoff: 528, nsyms: 1, stroff: 544, strsize: 8)
        a.pad(to: 512)
        a.u32(0x1400_0003)
        a.u32(0xD503_201F)
        a.u32(0xD503_201F)
        a.u32(0xD65F_03C0)
        a.nlist64(strx: 1, type: 0x0F, value: 0x1000)
        a.fixedString("\0_first\0", length: 8)
        let binary = try #require(walkedBinary(bytes: a.bytes))
        var listing = ""
        plain.emitListing(for: binary, emit: { listing += $0 })
        #expect(listing.contains("1000: 14000003  b 0x100c\n"))
        #expect(!listing.contains("_first+"))
    }

    @Test func sameSectionNearestSymbolAnnotates() throws {
        let binary = try #require(walkedBinary(cliFixturePath("hello-arm64")))
        var listing = ""
        plain.emitListing(for: binary, emit: { listing += $0 })
        #expect(listing.contains("b 0x100000354 ; _sum_to+0x14"))
    }

    @Test func targetBeforeEverySymbolHasNoAnnotation() throws {
        var a = MachOAssembler()
        a.machHeader64(ncmds: 2, sizeofcmds: 72 + 80 + 24)
        a.segmentCommand64(name: "__TEXT", vmaddr: 0x1000, nsects: 1, cmdsize: 72 + 80)
        a.section64(sectname: "__text", segname: "__TEXT", addr: 0x1000, size: 8, offset: 512, flags: someInstructions)
        a.symtabCommand(symoff: 520, nsyms: 1, stroff: 536, strsize: 8)
        a.pad(to: 512)
        a.u32(0xD503_201F)
        a.u32(0x17FF_FFFF)
        a.nlist64(strx: 1, type: 0x0F, value: 0x1004)
        a.fixedString("\0_late\0", length: 8)
        let binary = try #require(walkedBinary(bytes: a.bytes))
        var listing = ""
        plain.emitListing(for: binary, emit: { listing += $0 })
        #expect(listing.contains("1004: 17ffffff  b 0x1000\n"))
        #expect(!listing.contains("_late+"))
    }

    @Test func functionStartOutsideSectionDrawsNoLabel() throws {
        let bytes = minimalBinary(words: [0xD503_201F], extraSize: 16, extraCommands: { a in
            a.linkeditDataCommand(cmd: 0x26, dataoff: 264, datasize: 2)
        }, trailer: { a in
            a.pad(to: 264)
            a.bytes.append(contentsOf: [0x04, 0x00])
        })
        let binary = try #require(walkedBinary(bytes: bytes))
        #expect(binary.functionStarts == [0x1004])
        var listing = ""
        plain.emitListing(for: binary, emit: { listing += $0 })
        #expect(!listing.contains("sub_"))
        #expect(listing.contains("1000: d503201f  nop\n"))
    }

    @Test func branchTextWithoutLabelTokenPassesThrough() {
        let synthetic = Instruction(
            mnemonic: .ret,
            branchClass: .direct,
            category: .branchesExceptionSystem,
            operands: [.label(byteOffset: 16)],
        )
        #expect(synthetic.branchTarget == 16)
        #expect(synthetic.text == "?ret")
        #expect(InstructionText.absoluteBranchText(synthetic) == "?ret")
    }

    @Test func emitStreamEmitsOneChunkPerInstruction() {
        let empty = InstructionStream(
            baseAddress: 0,
            byteCount: 0,
            features: [],
            records: [],
            operands: [],
            diagnostics: [],
        )
        let oneWord = InstructionStream(bytes: [0x1F, 0x20, 0x03, 0xD5])
        var chunks: [String] = []
        let sink: (String) -> Void = { chunks.append($0) }

        plain.emitStream(empty, emit: sink)
        #expect(chunks.isEmpty)
        plain.emitStream(oneWord, emit: sink)
        #expect(chunks == ["0: d503201f  nop\n"])
    }

    @Test func addressColumnPadsToSectionWidth() throws {
        let binary = try #require(walkedBinary(cliFixturePath("dic-arm64.o")))
        var listing = ""
        plain.emitListing(for: binary, emit: { listing += $0 })
        #expect(listing.contains("\n00: 52800000  mov w0, #0\n"))
        #expect(listing.contains("\n04: d65f03c0  ret\n"))
    }

    func wrappingBinaryBytes() -> [UInt8] {
        minimalBinary(words: [0xD503_201F, 0xD503_201F, 0xD65F_03C0], textAddr: UInt64.max - 7)
    }

    @Test func wrappingSectionListsWithoutCrashing() throws {
        let bytes = minimalBinary(
            words: [0xD503_201F, 0xD503_201F, 0xD65F_03C0],
            textAddr: UInt64.max - 7,
            extraSize: 24,
            extraCommands: { a in
                a.symtabCommand(symoff: 268, nsyms: 3, stroff: 316, strsize: 17)
            },
            trailer: { a in
                a.pad(to: 268)
                a.nlist64(strx: 1, type: 0x0F, value: UInt64.max - 7)
                a.nlist64(strx: 4, type: 0x0F, value: UInt64.max)
                a.nlist64(strx: 9, type: 0x0F, value: 0)
                a.fixedString("\0_f\0_top\0_wrap\0", length: 17)
            },
        )
        let binary = try #require(walkedBinary(bytes: bytes))
        #expect(binary.symbols.count == 3)
        var listing = ""
        plain.emitListing(for: binary, emit: { listing += $0 })
        #expect(listing.contains("\n_f:\n"))
        #expect(listing.contains("\n_wrap:\n"))
        #expect(listing.contains("fffffffffffffff8: d503201f  nop\n"))
        #expect(listing.contains("0000000000000000: d65f03c0  ret\n"))
    }

    @Test func addressWrapIsSurfacedOnStderr() {
        for mode in [[], ["--json"], ["stats"]] {
            let run = withTemporaryFile(bytes: wrappingBinaryBytes()) { runCLI(mode + [$0]) }
            #expect(run.status == CLI.exitSuccess)
            #expect(run.stderr == "iris: warning: __TEXT,__text: addresses wrap past 2^64 at buffer offset 8\n")
        }
    }

    @Test func addressWrapWarningHonorsQuiet() {
        let run = withTemporaryFile(bytes: wrappingBinaryBytes()) { runCLI(["--quiet", $0]) }
        #expect(run.status == CLI.exitSuccess)
        #expect(run.stderr.isEmpty)
        #expect(run.stdout.contains("0: d65f03c0  ret\n"))
    }
}

/// Validates the `--semantics` column on a record with no semantics.
@Suite("Listing / semantics column with an empty annotation")
struct SemanticsEmptyAnnotationTests {
    private let renderer = ListingRenderer(palette: Palette(enabled: false), includeSemantics: true)

    @Test func anUnallocatedWordGetsNoAnnotationAndNoPadding() {
        let stream = InstructionStream(bytes: [0xFF, 0xFF, 0xFF, 0xFF] as [UInt8])
        let line = renderer.line(for: stream[0], addressWidth: 4, context: nil)
        #expect(line.hasSuffix("; undefined"), "got \(line.debugDescription)")
        #expect(!line.hasSuffix(" "), "an empty annotation must not pad")
    }

    @Test func aRecordWithSemanticsStillGetsItsColumn() {
        let stream = InstructionStream(bytes: [0x20, 0x04, 0x00, 0x91] as [UInt8])
        let line = renderer.line(for: stream[0], addressWidth: 4, context: nil)
        #expect(line.contains("; reads=x1 writes=x0"), "got \(line.debugDescription)")
    }
}
