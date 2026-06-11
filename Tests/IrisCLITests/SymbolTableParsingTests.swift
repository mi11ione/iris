// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisCLICore
import Testing

/// Validates `LC_SYMTAB` decoding against synthetic symbol tables:
/// which `nlist_64` entries label a listing (section-defined and
/// absolute, stabs and undefineds excluded), name-edge handling, and
/// the external-before-local ordering rule.
@Suite("Symbol table parsing")
struct SymbolTableParsingTests {
    /// A one-section binary whose symtab is assembled by `build`:
    /// symbols at file offset 264, strings at 264 + 16·nsyms.
    func binaryWithSymbols(
        nsyms: UInt32,
        strings: [UInt8],
        strsizeOverride: UInt32? = nil,
        stroffOverride: UInt32? = nil,
        build: (inout MachOAssembler) -> Void,
    ) -> WalkedBinary? {
        let symoff: UInt32 = 264
        let stroff = stroffOverride ?? (symoff + 16 * nsyms)
        let bytes = minimalBinary(words: [0xD503_201F, 0xD65F_03C0], extraSize: 24, extraCommands: { a in
            a.symtabCommand(
                symoff: symoff,
                nsyms: nsyms,
                stroff: stroff,
                strsize: strsizeOverride ?? UInt32(strings.count),
            )
        }, trailer: { a in
            a.pad(to: Int(symoff))
            build(&a)
            a.bytes.append(contentsOf: strings)
        })
        return walkedBinary(bytes: bytes)
    }

    @Test func sectionAndAbsoluteSymbolsAreKept() throws {
        let strings = Array("\0_sect\0_abs\0".utf8)
        let binary = try #require(binaryWithSymbols(nsyms: 2, strings: strings) { a in
            a.nlist64(strx: 1, type: 0x0E, value: 0x1000) // N_SECT, local
            a.nlist64(strx: 7, type: 0x02, value: 0x2000) // N_ABS, local
        })
        #expect(binary.symbols.count == 2)
        #expect(binary.symbols.name(at: 0x1000) == "_sect")
        #expect(binary.symbols.name(at: 0x2000) == "_abs")
        #expect(binary.diagnostics.isEmpty)
    }

    @Test func stabsAndUndefinedsAreExcluded() throws {
        let strings = Array("\0_real\0_undef\0_stab\0".utf8)
        let binary = try #require(binaryWithSymbols(nsyms: 3, strings: strings) { a in
            a.nlist64(strx: 1, type: 0x0E, value: 0x1000) // kept
            a.nlist64(strx: 7, type: 0x01, value: 0) // N_UNDF: excluded
            a.nlist64(strx: 14, type: 0x64, value: 0x1234) // N_SO stab: excluded
        })
        #expect(binary.symbols.count == 1)
        #expect(binary.symbols.name(at: 0x1000) == "_real")
    }

    @Test func externalBeatsLocalAtSharedAddress() throws {
        // nlist order puts the local first; the walker feeds externals
        // ahead of locals so the shared address labels externally.
        let strings = Array("\0ltmp0\0_main\0".utf8)
        let binary = try #require(binaryWithSymbols(nsyms: 2, strings: strings) { a in
            a.nlist64(strx: 1, type: 0x0E, value: 0x1000) // local first in table
            a.nlist64(strx: 7, type: 0x0F, value: 0x1000) // external (N_EXT)
        })
        #expect(binary.symbols.count == 1)
        #expect(binary.symbols.name(at: 0x1000) == "_main")
    }

    @Test func zeroStrxAndEmptyNamesAreSkippedSilently() throws {
        let strings = Array("\0\0_named\0".utf8)
        let binary = try #require(binaryWithSymbols(nsyms: 3, strings: strings) { a in
            a.nlist64(strx: 0, type: 0x0E, value: 0x1000) // no name slot
            a.nlist64(strx: 1, type: 0x0E, value: 0x2000) // empty name
            a.nlist64(strx: 2, type: 0x0E, value: 0x3000) // "_named"
        })
        #expect(binary.symbols.count == 1)
        #expect(binary.symbols.name(at: 0x3000) == "_named")
        #expect(binary.diagnostics.isEmpty)
    }

    @Test func nameOffsetPastStringTableIsDiagnosed() throws {
        let strings = Array("\0_ok\0".utf8)
        let binary = try #require(binaryWithSymbols(nsyms: 2, strings: strings) { a in
            a.nlist64(strx: 1, type: 0x0E, value: 0x1000)
            a.nlist64(strx: 500, type: 0x0E, value: 0x2000) // strx >= strsize
        })
        let diagnostic = try #require(binary.diagnostics.first { $0.kind == .symbolNameOutOfBounds })
        #expect(diagnostic.detail == "symbol 1 n_strx 500 >= strsize 5; symbol dropped")
        #expect(binary.symbols.count == 1)
    }

    @Test func unterminatedNameIsDiagnosed() throws {
        let strings = Array("\0_chopped".utf8) // no trailing NUL
        let binary = try #require(binaryWithSymbols(nsyms: 1, strings: strings) { a in
            a.nlist64(strx: 1, type: 0x0E, value: 0x1000)
        })
        let diagnostic = try #require(binary.diagnostics.first { $0.kind == .symbolNameOutOfBounds })
        #expect(diagnostic.detail == "symbol 0 name at string-table offset 1 has no terminator; symbol dropped")
        #expect(binary.symbols.count == 0)
    }

    @Test func stringTableRegionPastSliceDropsSymbols() throws {
        let strings = Array("\0_x\0".utf8)
        let binary = try #require(binaryWithSymbols(nsyms: 1, strings: strings, strsizeOverride: 0xF000_0000) { a in
            a.nlist64(strx: 1, type: 0x0E, value: 0x1000)
        })
        let diagnostic = try #require(binary.diagnostics.first { $0.kind == .symbolTableOutOfBounds })
        #expect(diagnostic.detail.contains("string table"))
        #expect(binary.symbols.count == 0)
    }

    @Test func zeroSymbolCountIsEmptyWithoutDiagnostics() throws {
        let binary = try #require(binaryWithSymbols(nsyms: 0, strings: []) { _ in })
        #expect(binary.symbols.count == 0)
        #expect(binary.diagnostics.isEmpty)
    }
}
