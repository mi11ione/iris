// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
import Iris
import IrisCLICore
import Testing

/// Validates the walker's no-crash contract over the malformed fixture
/// set and synthetic hostile binaries: every malformation degrades to a
/// typed diagnostic and an honest partial result — never a crash, never
/// a guess.
@Suite("Walker on malformed binaries")
struct MalformedBinaryTests {
    @Test func truncatedHeaderIsNotMachO() throws {
        let detail = try #require(notMachOOutcome(MachOWalker.walk(path: cliFixturePath("truncated-header"), arch: nil)))
        #expect(detail == "mach_header_64 truncated (slice is 16 bytes, header needs 32)")
    }

    @Test func lyingSectionSizeIsClamped() throws {
        let binary = try #require(walkedBinary(cliFixturePath("lying-section")))
        #expect(binary.diagnostics.map(\.kind).contains(.sectionContentOutOfBounds))
        let text = try #require(binary.codeSections.first { $0.sectionName == "__text" })
        #expect(text.fileOffset + text.byteCount <= 16952)
        let stream = text.instructions(features: binary.features)
        #expect(!stream.isEmpty)
    }

    @Test func zeroSizeSectionIsSkipped() throws {
        let binary = try #require(walkedBinary(cliFixturePath("zero-size-section")))
        #expect(binary.diagnostics.map(\.kind).contains(.sectionEmpty))
        #expect(!binary.codeSections.contains { $0.sectionName == "__text" })
    }

    @Test func lyingNsectsWalksTheBudget() throws {
        let binary = try #require(walkedBinary(cliFixturePath("lying-nsects")))
        #expect(binary.diagnostics.map(\.kind).contains(.sectionTableTruncated))
        #expect(binary.codeSections.contains { $0.sectionName == "__text" })
    }

    @Test func badSymtabDropsSymbolsOnly() throws {
        let binary = try #require(walkedBinary(cliFixturePath("bad-symtab")))
        #expect(binary.diagnostics.map(\.kind).contains(.symbolTableOutOfBounds))
        #expect(binary.symbols.count == 0)
        #expect(!binary.codeSections.isEmpty)
        #expect(!binary.functionStarts.isEmpty)
    }

    @Test func badFunctionStartsDropsStartsOnly() throws {
        let binary = try #require(walkedBinary(cliFixturePath("bad-fnstarts")))
        #expect(binary.diagnostics.map(\.kind).contains(.functionStartsOutOfBounds))
        #expect(binary.functionStarts.isEmpty)
        #expect(binary.symbols.count > 0)
    }

    @Test func hostileDataInCodeEntryIsDropped() throws {
        let binary = try #require(walkedBinary(cliFixturePath("hostile-dic-entry")))
        #expect(binary.diagnostics.map(\.kind).contains(.dataInCodeEntryOutsideCode))
        let text = try #require(binary.codeSections.first { $0.sectionName == "__text" })
        // The surgered first entry is dropped; the second (data kind) survives.
        #expect(text.dataInCode.count == 1)
        #expect(text.dataInCode[0].kind == .data)
    }

    @Test func hostileDataInCodeRegionIsIgnored() throws {
        let binary = try #require(walkedBinary(cliFixturePath("hostile-dic-region")))
        #expect(binary.diagnostics.map(\.kind).contains(.dataInCodeRegionOutOfBounds))
        let text = try #require(binary.codeSections.first { $0.sectionName == "__text" })
        #expect(text.dataInCode.isEmpty)
    }

    @Test func fatWithBadSliceFallsBack() throws {
        let binary = try #require(walkedBinary(cliFixturePath("fat-bad-slice")))
        #expect(binary.diagnostics.map(\.kind).contains(.fatSliceOutOfBounds))
        #expect(binary.architecture == "arm64")
    }

    @Test func fatWithBadSliceRefusesItExplicitly() throws {
        let outcome = MachOWalker.walk(path: cliFixturePath("fat-bad-slice"), arch: .arm64e)
        let unavailable = try #require(archUnavailableOutcome(outcome))
        #expect(unavailable.requested == .arm64e)
        #expect(unavailable.available == ["arm64", "arm64e"])
    }

    @Test func emptyAndTinyFiles() throws {
        let empty = try #require(unreadableOutcome(walkBytes([])))
        #expect(empty.contains("cannot open or map"))
        let oneByte = try #require(notMachODetail(bytes: [0xCF]))
        #expect(oneByte.contains("shorter than 4 bytes"))
        let twoBytes = try #require(notMachODetail(bytes: [0xCF, 0xFA]))
        #expect(twoBytes.contains("shorter than 4 bytes"))
    }

    @Test func directoryIsUnreadable() throws {
        let detail = try #require(unreadableOutcome(MachOWalker.walk(path: cliFixturesRoot, arch: nil)))
        #expect(detail == "cannot open or map '\(cliFixturesRoot)'")
    }

    @Test func wrongMagicIsNotMachO() throws {
        let detail = try #require(notMachODetail(bytes: [0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0]))
        #expect(detail.contains("has no Mach-O or fat magic (first word 0xefbeadde)"))
    }

    @Test func fatHeaderWithoutCountIsNotMachO() throws {
        // Big-endian CAFEBABE then EOF before nfat_arch.
        let detail = try #require(notMachODetail(bytes: [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00]))
        #expect(detail == "fat header truncated (no nfat_arch)")
    }

    @Test func fatWithZeroArchitectures() {
        var a = MachOAssembler(bigEndian: true)
        a.u32(0xCAFE_BABE)
        a.u32(0)
        #expect(notMachODetail(bytes: a.bytes) == "fat header declares zero architectures")
    }

    @Test func fatArchTableTruncated() {
        var a = MachOAssembler(bigEndian: true)
        a.u32(0xCAFE_BABE)
        a.u32(2) // declares two fat_arch records, provides half of one
        a.u32(0x0100_000C)
        a.u32(0)
        #expect(notMachODetail(bytes: a.bytes) == "fat arch table truncated (entry 0 of 2 past end of file)")
    }

    @Test func fatArchTableEndsInsideCputype() {
        // The record's leading cputype/cpusubtype pair is itself cut off.
        var a = MachOAssembler(bigEndian: true)
        a.u32(0xCAFE_BABE)
        a.u32(1)
        a.u16(0x0100)
        #expect(notMachODetail(bytes: a.bytes) == "fat arch table truncated (entry 0 of 1 past end of file)")
    }

    @Test func fat64ArchTableEndsInsideOffset() {
        // fat_arch_64: the 64-bit offset/size pair is cut off after the
        // cputype pair survived.
        var a = MachOAssembler(bigEndian: true)
        a.u32(0xCAFE_BABF)
        a.u32(1)
        a.u32(0x0100_000C)
        a.u32(0)
        a.u32(0) // half of the 64-bit offset
        #expect(notMachODetail(bytes: a.bytes) == "fat arch table truncated (entry 0 of 1 past end of file)")
    }

    @Test func diagnosticLabelsAreStable() {
        let labels: [WalkerDiagnostic.Kind: String] = [
            .fatSliceOutOfBounds: "fat slice out of bounds",
            .loadCommandInvalid: "load command invalid",
            .loadCommandRegionTruncated: "load command region truncated",
            .duplicateLoadCommand: "duplicate load command",
            .sectionTableTruncated: "section table truncated",
            .sectionContentOutOfBounds: "section content out of bounds",
            .sectionEmpty: "section empty",
            .dataInCodeRegionOutOfBounds: "data-in-code region out of bounds",
            .dataInCodeRegionTruncated: "data-in-code region truncated",
            .dataInCodeEntryOutsideCode: "data-in-code entry outside code",
            .dataInCodeEntryClamped: "data-in-code entry clamped",
            .symbolTableOutOfBounds: "symbol table out of bounds",
            .symbolNameOutOfBounds: "symbol name out of bounds",
            .functionStartsOutOfBounds: "function starts out of bounds",
            .functionStartsMalformed: "function starts malformed",
            .functionStartsUnanchored: "function starts unanchored",
        ]
        for (kind, label) in labels {
            #expect(kind.label == label)
            #expect(WalkerDiagnostic(kind: kind, detail: "d").description == "warning: \(label): d")
        }
    }

    @Test func fatSliceShorterThanMagic() {
        // One in-bounds slice of 2 bytes: selected, then too short to read.
        var a = MachOAssembler(bigEndian: true)
        a.u32(0xCAFE_BABE)
        a.u32(1)
        a.u32(0x0100_000C) // cputype arm64
        a.u32(0) // subtype
        a.u32(28) // offset
        a.u32(2) // size
        a.u32(0) // align
        a.u8(0xAA)
        a.u8(0xBB)
        #expect(notMachODetail(bytes: a.bytes) == "selected arm64 slice is shorter than 4 bytes")
    }

    @Test func fatSliceWithForeignMagic() {
        var a = MachOAssembler(bigEndian: true)
        a.u32(0xCAFE_BABE)
        a.u32(1)
        a.u32(0x0100_000C)
        a.u32(0)
        a.u32(28)
        a.u32(8)
        a.u32(0)
        a.bytes.append(contentsOf: [0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0])
        #expect(notMachODetail(bytes: a.bytes) == "selected arm64 slice is not a 64-bit Mach-O (first word 0xefbeadde)")
    }

    @Test func loadCommandRegionPastSlice() throws {
        // sizeofcmds claims more bytes than the file holds; the walk
        // covers the in-bounds prefix and still finds the section.
        var bytes = minimalBinary(words: [0xD503_201F])
        // sizeofcmds at offset 20 (LE): inflate to 1 MiB.
        bytes.replaceSubrange(20 ..< 24, with: [0x00, 0x00, 0x10, 0x00])
        let binary = try #require(walkedBinary(bytes: bytes))
        #expect(binary.diagnostics.map(\.kind).contains(.loadCommandRegionTruncated))
        #expect(binary.codeSections.count == 1)
    }

    @Test func commandCountPastRegion() throws {
        // ncmds = 2 but the region only holds one command: the walk stops
        // with a diagnostic after the first.
        var bytes = minimalBinary(words: [0xD503_201F])
        bytes.replaceSubrange(16 ..< 20, with: [2, 0, 0, 0])
        let binary = try #require(walkedBinary(bytes: bytes))
        let diagnostic = try #require(binary.diagnostics.first { $0.kind == .loadCommandInvalid })
        #expect(diagnostic.detail == "command 1 of 2 starts past the load-command region; stopping")
        #expect(binary.codeSections.count == 1)
    }

    @Test func commandSizeTooSmall() throws {
        // cmdsize = 4 (< 8) is structurally invalid; the walk stops at it.
        var a = MachOAssembler()
        a.machHeader64(ncmds: 1, sizeofcmds: 8)
        a.u32(0x19)
        a.u32(4)
        let binary = try #require(walkedBinary(bytes: a.bytes))
        let diagnostic = try #require(binary.diagnostics.first { $0.kind == .loadCommandInvalid })
        #expect(diagnostic.detail == "command 0 (cmd 0x19) has cmdsize 4 outside [8, region end]; stopping")
        #expect(binary.codeSections.isEmpty)
    }

    @Test func segmentCommandSmallerThanItsHeader() throws {
        // An LC_SEGMENT_64 whose cmdsize (16) cannot hold the 72-byte
        // struct is skipped with a diagnostic; the walk continues.
        var a = MachOAssembler()
        a.machHeader64(ncmds: 1, sizeofcmds: 16)
        a.u32(0x19)
        a.u32(16)
        a.u64(0)
        let binary = try #require(walkedBinary(bytes: a.bytes))
        let diagnostic = try #require(binary.diagnostics.first { $0.kind == .loadCommandInvalid })
        #expect(diagnostic.detail == "LC_SEGMENT_64 at 32 has cmdsize 16, smaller than its 72-byte header; skipped")
    }

    @Test func symtabCommandTooSmall() throws {
        let bytes = minimalBinary(words: [0xD503_201F], extraSize: 16, extraCommands: { a in
            a.u32(0x2) // LC_SYMTAB with cmdsize 16 < 24
            a.u32(16)
            a.u64(0)
        })
        let binary = try #require(walkedBinary(bytes: bytes))
        let diagnostic = try #require(binary.diagnostics.first { $0.kind == .loadCommandInvalid })
        #expect(diagnostic.detail == "LC_SYMTAB at 184 has cmdsize 16, smaller than its 24-byte struct; skipped")
        #expect(binary.symbols.count == 0)
    }

    @Test func linkeditCommandTooSmall() throws {
        let bytes = minimalBinary(words: [0xD503_201F], extraSize: 8, extraCommands: { a in
            a.u32(0x26) // LC_FUNCTION_STARTS with cmdsize 8 < 16
            a.u32(8)
        })
        let binary = try #require(walkedBinary(bytes: bytes))
        let diagnostic = try #require(binary.diagnostics.first { $0.kind == .loadCommandInvalid })
        #expect(diagnostic.detail == "LC_FUNCTION_STARTS at 184 has cmdsize 8, smaller than its 16-byte struct; skipped")
    }

    @Test func duplicateCommandsKeepTheFirst() throws {
        // Two LC_DATA_IN_CODE commands: the second draws a diagnostic.
        let bytes = minimalBinary(words: [0xD503_201F], extraSize: 32, extraCount: 2, extraCommands: { a in
            a.linkeditDataCommand(cmd: 0x29, dataoff: 0, datasize: 0)
            a.linkeditDataCommand(cmd: 0x29, dataoff: 0, datasize: 0)
        })
        let binary = try #require(walkedBinary(bytes: bytes))
        let diagnostic = try #require(binary.diagnostics.first { $0.kind == .duplicateLoadCommand })
        #expect(diagnostic.detail == "more than one LC_DATA_IN_CODE; using the first")
    }

    @Test func sectionContentStartingPastSlice() throws {
        // section_64.offset points past EOF entirely: skipped, diagnosed.
        var a = MachOAssembler()
        a.machHeader64(ncmds: 1, sizeofcmds: 72 + 80)
        a.segmentCommand64(name: "__TEXT", vmaddr: 0x1000, nsects: 1, cmdsize: 72 + 80)
        a.section64(
            sectname: "__text",
            segname: "__TEXT",
            addr: 0x1000,
            size: 4,
            offset: 0xF000_0000,
            flags: someInstructions,
        )
        let binary = try #require(walkedBinary(bytes: a.bytes))
        #expect(binary.diagnostics.map(\.kind).contains(.sectionContentOutOfBounds))
        #expect(binary.codeSections.isEmpty)
    }

    @Test func sectionSizeOverflowingUInt64IsClamped() throws {
        // offset + size overflows UInt64: the addition is checked, the
        // section is clamped to the bytes that exist.
        var a = MachOAssembler()
        a.machHeader64(ncmds: 1, sizeofcmds: 72 + 80)
        a.segmentCommand64(name: "__TEXT", vmaddr: 0x1000, nsects: 1, cmdsize: 72 + 80)
        a.section64(
            sectname: "__text",
            segname: "__TEXT",
            addr: 0x1000,
            size: UInt64.max,
            offset: 184,
            flags: someInstructions,
        )
        a.pad(to: 184)
        a.u32(0xD503_201F)
        let binary = try #require(walkedBinary(bytes: a.bytes))
        #expect(binary.diagnostics.map(\.kind).contains(.sectionContentOutOfBounds))
        let text = try #require(binary.codeSections.first)
        #expect(text.byteCount == 4)
    }

    @Test func zerofillCodeSectionIsExcluded() throws {
        // S_ZEROFILL type with an instructions attribute has no file
        // content to decode; the walker excludes it without a diagnostic
        // (nothing was lost — there are no bytes).
        var a = MachOAssembler()
        a.machHeader64(ncmds: 1, sizeofcmds: 72 + 80)
        a.segmentCommand64(name: "__TEXT", vmaddr: 0x1000, nsects: 1, cmdsize: 72 + 80)
        a.section64(
            sectname: "__bss_code",
            segname: "__TEXT",
            addr: 0x1000,
            size: 64,
            offset: 0,
            flags: someInstructions | 0x1,
        )
        let binary = try #require(walkedBinary(bytes: a.bytes))
        #expect(binary.codeSections.isEmpty)
        #expect(binary.diagnostics.isEmpty)
    }

    @Test func nonInstructionSectionsAreExcluded() throws {
        var a = MachOAssembler()
        a.machHeader64(ncmds: 1, sizeofcmds: 72 + 80)
        a.segmentCommand64(name: "__DATA", vmaddr: 0x2000, nsects: 1, cmdsize: 72 + 80)
        a.section64(sectname: "__const", segname: "__DATA", addr: 0x2000, size: 16, offset: 184, flags: 0)
        let binary = try #require(walkedBinary(bytes: a.bytes))
        #expect(binary.codeSections.isEmpty)
        #expect(binary.diagnostics.isEmpty)
    }

    @Test func nonARM64ThinFileIsUnavailable() throws {
        var a = MachOAssembler()
        a.machHeader64(cputype: 0x0100_0007, ncmds: 0, sizeofcmds: 0)
        let unavailable = try #require(archUnavailableOutcome(walkBytes(a.bytes)))
        #expect(unavailable.requested == nil)
        #expect(unavailable.available == ["x86_64"])
    }

    @Test func explicitArchMismatchOnThinFile() throws {
        let outcome = walkBytes(minimalBinary(words: [0xD503_201F]), arch: .arm64e)
        let unavailable = try #require(archUnavailableOutcome(outcome))
        #expect(unavailable.requested == .arm64e)
        #expect(unavailable.available == ["arm64"])
    }

    @Test func walkerNeverCrashesOnFuzzedTruncations() throws {
        // Every prefix of a real small Mach-O walks to *some* typed
        // outcome — the totality net for the load-command machinery.
        let whole = try #require(FileManager.default.contents(atPath: cliFixturePath("dic-arm64.o")))
        var verdicts: Set<String> = []
        for length in 0 ... whole.count {
            switch walkBytes(Array(whole.prefix(length))) {
            case .binary: verdicts.insert("binary")
            case .unreadable: verdicts.insert("unreadable")
            case .notMachO: verdicts.insert("notMachO")
            case .archUnavailable: verdicts.insert("archUnavailable")
            }
        }
        #expect(verdicts.contains("unreadable")) // length 0
        #expect(verdicts.contains("notMachO")) // 1 ..< 32
        #expect(verdicts.contains("binary")) // the whole file
        #expect(!verdicts.contains("archUnavailable")) // cputype is always arm64
    }
}
