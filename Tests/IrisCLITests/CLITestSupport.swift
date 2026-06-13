// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Shared support for the CLI test suites: fixture path resolution,
// an in-process CLI runner capturing both output streams, golden
// normalization, and a little-/big-endian Mach-O byte assembler for
// the synthetic malformed binaries no compiler will emit.

import Foundation
import IrisCLICore
import Testing

/// Absolute path of a checked-in CLI fixture binary under
/// `Tests/Fixtures/CLI/bin`, resolved relative to this source file so
/// `swift test` finds it regardless of the working directory.
func cliFixturePath(_ name: String) -> String {
    cliFixturesRoot + "/bin/" + name
}

/// Absolute path of a locked golden file under `Tests/Fixtures/CLI/golden`.
func cliGoldenPath(_ name: String) -> String {
    cliFixturesRoot + "/golden/" + name
}

/// Absolute path of `Tests/Fixtures/CLI`.
let cliFixturesRoot: String = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent() // IrisCLITests
    .deletingLastPathComponent() // Tests
    .appendingPathComponent("Fixtures/CLI").path

/// The locked golden bytes for `name`, as the UTF-8 string the CLI emitted.
func golden(_ name: String) -> String {
    let data = FileManager.default.contents(atPath: cliGoldenPath(name)) ?? Data()
    return String(decoding: data, as: UTF8.self)
}

/// One captured CLI invocation: exit status plus everything written to
/// each stream.
struct CLIRun {
    let status: Int32
    let stdout: String
    let stderr: String
}

/// Run `CLI.run` in-process with the given argv, capturing both sinks.
func runCLI(_ arguments: [String], tty: Bool = false) -> CLIRun {
    var out = ""
    var err = ""
    let status = CLI.run(
        arguments: arguments,
        standardOutputIsTTY: tty,
        writeOutput: { out += $0 },
        writeError: { err += $0 },
    )
    return CLIRun(status: status, stdout: out, stderr: err)
}

/// Rewrite this machine's absolute fixture paths to the repo-relative
/// form the goldens were locked with (the goldens are generated from
/// the repo root; only the path prefix differs across machines).
func normalizedToGolden(_ output: String) -> String {
    output.replacingOccurrences(of: cliFixturesRoot + "/bin/", with: "Tests/Fixtures/CLI/bin/")
}

/// Write `bytes` to a unique temporary file, hand the path to `body`,
/// and delete the file afterwards (an `mmap` made inside `body` stays
/// valid past the unlink; the kernel pins the inode).
func withTemporaryFile<R>(bytes: [UInt8], _ body: (String) -> R) -> R {
    let path = FileManager.default.temporaryDirectory
        .appendingPathComponent("iris-cli-test-\(UUID().uuidString)").path
    let created = FileManager.default.createFile(atPath: path, contents: Data(bytes))
    #expect(created, "temporary fixture file must be creatable")
    let result = body(path)
    try? FileManager.default.removeItem(atPath: path)
    return result
}

/// Write `bytes` to a temporary file and walk it.
func walkBytes(_ bytes: [UInt8], arch: ArchSelection? = nil) -> WalkOutcome {
    withTemporaryFile(bytes: bytes) { MachOWalker.walk(path: $0, arch: arch) }
}

/// Every diagnostic kind present in a walk that produced a binary;
/// empty for the failure outcomes.
func diagnosticKinds(of outcome: WalkOutcome) -> [WalkerDiagnostic.Kind] {
    switch outcome {
    case let .binary(binary): binary.diagnostics.map(\.kind)
    case .unreadable, .notMachO, .archUnavailable: []
    }
}

/// The `.binary` payload, or `nil` for any failure outcome (the
/// inspectors below pair with `try #require` at call sites).
func binaryOutcome(_ outcome: WalkOutcome) -> WalkedBinary? {
    guard case let .binary(binary) = outcome else { return nil }
    return binary
}

/// The `.notMachO` detail, or `nil` for any other outcome.
func notMachOOutcome(_ outcome: WalkOutcome) -> String? {
    guard case let .notMachO(detail) = outcome else { return nil }
    return detail
}

/// The `.unreadable` detail, or `nil` for any other outcome.
func unreadableOutcome(_ outcome: WalkOutcome) -> String? {
    guard case let .unreadable(detail) = outcome else { return nil }
    return detail
}

/// The `.archUnavailable` payload, or `nil` for any other outcome.
func archUnavailableOutcome(_ outcome: WalkOutcome) -> (requested: ArchSelection?, available: [String])? {
    guard case let .archUnavailable(requested, available) = outcome else { return nil }
    return (requested, available)
}

/// The walked binary of a fixture, or `nil` for any failure outcome.
func walkedBinary(_ path: String, arch: ArchSelection? = nil) -> WalkedBinary? {
    binaryOutcome(MachOWalker.walk(path: path, arch: arch))
}

/// Walk synthetic bytes into a binary, or `nil` for any failure outcome.
func walkedBinary(bytes: [UInt8], arch: ArchSelection? = nil) -> WalkedBinary? {
    binaryOutcome(walkBytes(bytes, arch: arch))
}

/// The not-Mach-O detail of walking synthetic bytes.
func notMachODetail(bytes: [UInt8], arch: ArchSelection? = nil) -> String? {
    notMachOOutcome(walkBytes(bytes, arch: arch))
}

/// Byte-buffer assembler for synthetic Mach-O structures, writing
/// multi-byte fields in the configured byte order so one builder covers
/// both the native little-endian path and the byte-swapped (`cigam`)
/// walker paths.
struct MachOAssembler {
    var bytes: [UInt8] = []
    let bigEndian: Bool

    init(bigEndian: Bool = false) {
        self.bigEndian = bigEndian
    }

    mutating func u8(_ value: UInt8) {
        bytes.append(value)
    }

    mutating func u16(_ value: UInt16) {
        let v = bigEndian ? value.bigEndian : value.littleEndian
        withUnsafeBytes(of: v) { bytes.append(contentsOf: $0) }
    }

    mutating func u32(_ value: UInt32) {
        let v = bigEndian ? value.bigEndian : value.littleEndian
        withUnsafeBytes(of: v) { bytes.append(contentsOf: $0) }
    }

    mutating func u64(_ value: UInt64) {
        let v = bigEndian ? value.bigEndian : value.littleEndian
        withUnsafeBytes(of: v) { bytes.append(contentsOf: $0) }
    }

    /// NUL-padded fixed-width name field (`segname` / `sectname`).
    mutating func fixedString(_ value: String, length: Int) {
        let utf8 = Array(value.utf8.prefix(length))
        bytes.append(contentsOf: utf8)
        bytes.append(contentsOf: [UInt8](repeating: 0, count: length - utf8.count))
    }

    /// Zero-fill up to absolute offset `offset` (no-op when already there).
    mutating func pad(to offset: Int) {
        while bytes.count < offset {
            bytes.append(0)
        }
    }

    /// `mach_header_64` (32 bytes).
    mutating func machHeader64(
        cputype: UInt32 = 0x0100_000C,
        cpusubtype: UInt32 = 0,
        filetype: UInt32 = 0x2,
        ncmds: UInt32,
        sizeofcmds: UInt32,
    ) {
        u32(0xFEED_FACF)
        u32(cputype)
        u32(cpusubtype)
        u32(filetype)
        u32(ncmds)
        u32(sizeofcmds)
        u32(0) // flags
        u32(0) // reserved
    }

    /// `segment_command_64` header (72 bytes; sections follow separately).
    mutating func segmentCommand64(
        name: String,
        vmaddr: UInt64,
        fileoff: UInt64 = 0,
        filesize: UInt64 = 0,
        nsects: UInt32,
        cmdsize: UInt32,
    ) {
        u32(0x19)
        u32(cmdsize)
        fixedString(name, length: 16)
        u64(vmaddr)
        u64(0) // vmsize
        u64(fileoff)
        u64(filesize)
        u32(7) // maxprot
        u32(5) // initprot
        u32(nsects)
        u32(0) // flags
    }

    /// `section_64` (80 bytes). `reserved1`/`reserved2` carry the
    /// indirect-symbol base and entry stride for an `S_SYMBOL_STUBS`
    /// section; they are zero for ordinary sections.
    mutating func section64(
        sectname: String,
        segname: String,
        addr: UInt64,
        size: UInt64,
        offset: UInt32,
        flags: UInt32,
        reserved1: UInt32 = 0,
        reserved2: UInt32 = 0,
    ) {
        fixedString(sectname, length: 16)
        fixedString(segname, length: 16)
        u64(addr)
        u64(size)
        u32(offset)
        u32(2) // align
        u32(0) // reloff
        u32(0) // nreloc
        u32(flags)
        u32(reserved1)
        u32(reserved2)
        u32(0) // reserved3
    }

    /// `dysymtab_command` (80 bytes). Only `indirectsymoff` (+56) and
    /// `nindirectsyms` (+60) drive stub symbolication; the rest are zero.
    mutating func dysymtabCommand(indirectsymoff: UInt32, nindirectsyms: UInt32) {
        u32(0xB) // LC_DYSYMTAB
        u32(80)
        for _ in 0 ..< 12 {
            u32(0)
        } // ilocalsym … nextrel (12 u32 fields)
        u32(indirectsymoff)
        u32(nindirectsyms)
        for _ in 0 ..< 4 {
            u32(0)
        } // extreloff … nlocrel (4 u32 fields)
    }

    /// `symtab_command` (24 bytes).
    mutating func symtabCommand(symoff: UInt32, nsyms: UInt32, stroff: UInt32, strsize: UInt32) {
        u32(0x2)
        u32(24)
        u32(symoff)
        u32(nsyms)
        u32(stroff)
        u32(strsize)
    }

    /// `linkedit_data_command` (16 bytes) for `LC_FUNCTION_STARTS` (0x26)
    /// or `LC_DATA_IN_CODE` (0x29).
    mutating func linkeditDataCommand(cmd: UInt32, dataoff: UInt32, datasize: UInt32) {
        u32(cmd)
        u32(16)
        u32(dataoff)
        u32(datasize)
    }

    /// `nlist_64` (16 bytes).
    mutating func nlist64(strx: UInt32, type: UInt8, sect: UInt8 = 1, desc: UInt16 = 0, value: UInt64) {
        u32(strx)
        u8(type)
        u8(sect)
        u16(desc)
        u64(value)
    }

    /// `data_in_code_entry` (8 bytes).
    mutating func dataInCodeEntry(offset: UInt32, length: UInt16, kind: UInt16) {
        u32(offset)
        u16(length)
        u16(kind)
    }
}

/// `S_ATTR_SOME_INSTRUCTIONS`, the attribute bit the walker keys on.
let someInstructions: UInt32 = 0x0000_0400
/// `S_ATTR_PURE_INSTRUCTIONS`.
let pureInstructions: UInt32 = 0x8000_0000
/// `S_CSTRING_LITERALS`, the section-type low byte for a `__cstring`.
let cStringLiterals: UInt32 = 0x2

/// A minimal arm64 Mach-O whose `__TEXT` segment carries one `__text`
/// code section (a single `ret`) and one `__cstring` data section holding
/// `bytes` at VM address `dataAddress`. Used to drive the referenced-data
/// resolver through a real walk (the `DataSection` initializer is
/// internal, so a fixture walk is the way to obtain one). The walked
/// binary's `dataSections` holds the cstring section over `bytes`.
func stringSectionBinary(address dataAddress: UInt64, bytes: [UInt8]) -> WalkedBinary {
    dataSectionBinary(
        segname: "__TEXT", sectname: "__cstring",
        address: dataAddress, bytes: bytes, sectionFlags: cStringLiterals,
    )
}

/// A minimal arm64 Mach-O carrying one `__text` code section (a single
/// `ret`) and one data section (`segname,sectname`) of `bytes.count` bytes
/// at `address` with the given `sectionFlags` (the section-type low byte
/// selects cstring vs plain data). Drives the referenced-data resolver
/// through a real walk, since the `DataSection` initializer is internal.
func dataSectionBinary(
    segname: String,
    sectname: String,
    address: UInt64,
    bytes: [UInt8],
    sectionFlags: UInt32,
) -> WalkedBinary {
    let textAddr: UInt64 = 0x1000
    // Content sits past the two segment commands (header 32 + 2·152 = 336),
    // so a generous 512-byte code offset keeps the ret word and the
    // appended data bytes clear of the load-command region.
    let codeOffset = 512
    let dataOffset = codeOffset + 4 // after the one ret word
    var a = MachOAssembler()
    // Two segments: __TEXT holds the code, the data segment holds the
    // section (a data section can name any segment, e.g. __DATA,__const).
    let textCmdsize: UInt32 = 72 + 80
    let dataCmdsize: UInt32 = 72 + 80
    a.machHeader64(ncmds: 2, sizeofcmds: textCmdsize + dataCmdsize)
    a.segmentCommand64(name: "__TEXT", vmaddr: textAddr, nsects: 1, cmdsize: textCmdsize)
    a.section64(
        sectname: "__text", segname: "__TEXT",
        addr: textAddr, size: 4, offset: UInt32(codeOffset),
        flags: pureInstructions | someInstructions,
    )
    a.segmentCommand64(name: segname, vmaddr: address, nsects: 1, cmdsize: dataCmdsize)
    a.section64(
        sectname: sectname, segname: segname,
        addr: address, size: UInt64(bytes.count), offset: UInt32(dataOffset),
        flags: sectionFlags,
    )
    a.pad(to: codeOffset)
    withUnsafeBytes(of: UInt32(0xD65F_03C0).littleEndian) { a.bytes.append(contentsOf: $0) } // ret
    a.bytes.append(contentsOf: bytes)
    return walkedBinary(bytes: a.bytes)!
}

/// A minimal arm64 Mach-O whose `__text` holds one `adr x0, #256`
/// (forming the absolute address `0x1100`) and whose `__DATA,__const`
/// section at `0x1100` carries an external symbol `_datum` there. Drives
/// the referenced-data annotation's data-symbol tier end to end: the
/// listing annotates `; _datum`, the JSON carries `referencedSymbol`.
/// `sectionSize` lets a caller inflate the `__const` size past the file
/// to exercise the walker's data-section clamp.
func dataSymbolReferenceBinary(sectionSize: UInt64 = 8) -> [UInt8] {
    var a = MachOAssembler()
    // One __TEXT segment with __text + __const, plus an LC_SYMTAB.
    let segCmdsize: UInt32 = 72 + 160
    let sizeofcmds: UInt32 = segCmdsize + 24
    let codeOffset = 512
    let dataOffset = codeOffset + 4
    a.machHeader64(ncmds: 2, sizeofcmds: sizeofcmds)
    a.segmentCommand64(name: "__TEXT", vmaddr: 0x1000, nsects: 2, cmdsize: segCmdsize)
    a.section64(
        sectname: "__text", segname: "__TEXT",
        addr: 0x1000, size: 4, offset: UInt32(codeOffset),
        flags: pureInstructions | someInstructions,
    )
    a.section64(
        sectname: "__const", segname: "__DATA",
        addr: 0x1100, size: sectionSize, offset: UInt32(dataOffset),
        flags: 0,
    )
    let symoff = UInt32(dataOffset + 8)
    let stroff = symoff + 16
    a.symtabCommand(symoff: symoff, nsyms: 1, stroff: stroff, strsize: 8)
    a.pad(to: codeOffset)
    a.u32(0x1000_0800) // adr x0, #256 at 0x1000 -> target 0x1100
    a.bytes.append(contentsOf: [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00]) // __const bytes (8)
    a.nlist64(strx: 1, type: 0x0F, value: 0x1100) // _datum, external, at 0x1100
    a.fixedString("\0_datum\0", length: 8)
    return a.bytes
}

/// A minimal valid one-section arm64 Mach-O: `__TEXT,__text` holding
/// `words` (little-endian instruction words) at file offset 256 /
/// VM address `textAddr`, optionally followed by extra load commands
/// built by `extraCommands` (sized `extraSize`) and trailing payload
/// bytes appended after the code. The shared shape for the synthetic
/// walker tests; every field is independently overridable at the
/// assembler level for the hostile variants.
func minimalBinary(
    words: [UInt32],
    textAddr: UInt64 = 0x1000,
    filetype: UInt32 = 0x2,
    bigEndian: Bool = false,
    extraSize: UInt32 = 0,
    extraCount: UInt32 = 0,
    extraCommands: (inout MachOAssembler) -> Void = { _ in },
    trailer: (inout MachOAssembler) -> Void = { _ in },
) -> [UInt8] {
    var a = MachOAssembler(bigEndian: bigEndian)
    let sizeofcmds: UInt32 = 72 + 80 + extraSize
    let ncmds: UInt32 = 1 + (extraCount > 0 ? extraCount : (extraSize > 0 ? 1 : 0))
    a.machHeader64(filetype: filetype, ncmds: ncmds, sizeofcmds: sizeofcmds)
    a.segmentCommand64(name: "__TEXT", vmaddr: textAddr, nsects: 1, cmdsize: 72 + 80)
    a.section64(
        sectname: "__text",
        segname: "__TEXT",
        addr: textAddr,
        size: UInt64(words.count * 4),
        offset: 256,
        flags: pureInstructions | someInstructions,
    )
    extraCommands(&a)
    a.pad(to: 256)
    for word in words {
        // Instruction words are little-endian in any Mach-O; the
        // assembler's byte order applies to header fields only.
        withUnsafeBytes(of: word.littleEndian) { a.bytes.append(contentsOf: $0) }
    }
    trailer(&a)
    return a.bytes
}
