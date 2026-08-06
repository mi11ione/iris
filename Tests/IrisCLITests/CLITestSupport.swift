// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
import IrisCLICore
import Testing

func cliFixturePath(_ name: String) -> String {
    cliFixturesRoot + "/bin/" + name
}

func cliGoldenPath(_ name: String) -> String {
    cliFixturesRoot + "/golden/" + name
}

let cliFixturesRoot: String = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .appendingPathComponent("Fixtures/CLI").path

func golden(_ name: String) -> String {
    let data = FileManager.default.contents(atPath: cliGoldenPath(name)) ?? Data()
    return String(decoding: data, as: UTF8.self)
}

struct CLIRun {
    let status: Int32
    let stdout: String
    let stderr: String
}

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

func normalizedToGolden(_ output: String) -> String {
    output.replacingOccurrences(of: cliFixturesRoot + "/bin/", with: "Tests/Fixtures/CLI/bin/")
}

func withTemporaryFile<R>(bytes: [UInt8], _ body: (String) -> R) -> R {
    let path = FileManager.default.temporaryDirectory
        .appendingPathComponent("iris-cli-test-\(UUID().uuidString)").path
    let created = FileManager.default.createFile(atPath: path, contents: Data(bytes))
    #expect(created, "temporary fixture file must be creatable")
    let result = body(path)
    try? FileManager.default.removeItem(atPath: path)
    return result
}

func walkBytes(_ bytes: [UInt8], arch: ArchSelection? = nil) -> WalkOutcome {
    withTemporaryFile(bytes: bytes) { MachOWalker.walk(path: $0, arch: arch) }
}

func diagnosticKinds(of outcome: WalkOutcome) -> [WalkerDiagnostic.Kind] {
    switch outcome {
    case let .binary(binary): binary.diagnostics.map(\.kind)
    case .unreadable, .notMachO, .archUnavailable: []
    }
}

func binaryOutcome(_ outcome: WalkOutcome) -> WalkedBinary? {
    guard case let .binary(binary) = outcome else { return nil }
    return binary
}

func notMachOOutcome(_ outcome: WalkOutcome) -> String? {
    guard case let .notMachO(detail) = outcome else { return nil }
    return detail
}

func unreadableOutcome(_ outcome: WalkOutcome) -> String? {
    guard case let .unreadable(detail) = outcome else { return nil }
    return detail
}

func archUnavailableOutcome(_ outcome: WalkOutcome) -> (requested: ArchSelection?, available: [String])? {
    guard case let .archUnavailable(requested, available) = outcome else { return nil }
    return (requested, available)
}

func verdictName(_ outcome: WalkOutcome) -> String {
    switch outcome {
    case .binary: "binary"
    case .unreadable: "unreadable"
    case .notMachO: "notMachO"
    case .archUnavailable: "archUnavailable"
    }
}

func walkedBinary(_ path: String, arch: ArchSelection? = nil) -> WalkedBinary? {
    binaryOutcome(MachOWalker.walk(path: path, arch: arch))
}

func walkedBinary(bytes: [UInt8], arch: ArchSelection? = nil) -> WalkedBinary? {
    binaryOutcome(walkBytes(bytes, arch: arch))
}

func notMachODetail(bytes: [UInt8], arch: ArchSelection? = nil) -> String? {
    notMachOOutcome(walkBytes(bytes, arch: arch))
}

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

    mutating func fixedString(_ value: String, length: Int) {
        let utf8 = Array(value.utf8.prefix(length))
        bytes.append(contentsOf: utf8)
        bytes.append(contentsOf: [UInt8](repeating: 0, count: length - utf8.count))
    }

    mutating func pad(to offset: Int) {
        while bytes.count < offset {
            bytes.append(0)
        }
    }

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
        u32(0)
        u32(0)
    }

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
        u64(0)
        u64(fileoff)
        u64(filesize)
        u32(7)
        u32(5)
        u32(nsects)
        u32(0)
    }

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
        u32(2)
        u32(0)
        u32(0)
        u32(flags)
        u32(reserved1)
        u32(reserved2)
        u32(0)
    }

    mutating func dysymtabCommand(indirectsymoff: UInt32, nindirectsyms: UInt32) {
        u32(0xB)
        u32(80)
        for _ in 0 ..< 12 {
            u32(0)
        }
        u32(indirectsymoff)
        u32(nindirectsyms)
        for _ in 0 ..< 4 {
            u32(0)
        }
    }

    mutating func symtabCommand(symoff: UInt32, nsyms: UInt32, stroff: UInt32, strsize: UInt32) {
        u32(0x2)
        u32(24)
        u32(symoff)
        u32(nsyms)
        u32(stroff)
        u32(strsize)
    }

    mutating func linkeditDataCommand(cmd: UInt32, dataoff: UInt32, datasize: UInt32) {
        u32(cmd)
        u32(16)
        u32(dataoff)
        u32(datasize)
    }

    mutating func nlist64(strx: UInt32, type: UInt8, sect: UInt8 = 1, desc: UInt16 = 0, value: UInt64) {
        u32(strx)
        u8(type)
        u8(sect)
        u16(desc)
        u64(value)
    }

    mutating func dataInCodeEntry(offset: UInt32, length: UInt16, kind: UInt16) {
        u32(offset)
        u16(length)
        u16(kind)
    }
}

let someInstructions: UInt32 = 0x0000_0400
let pureInstructions: UInt32 = 0x8000_0000
let cStringLiterals: UInt32 = 0x2

func stringSectionBinary(address dataAddress: UInt64, bytes: [UInt8]) -> WalkedBinary {
    dataSectionBinary(
        segname: "__TEXT", sectname: "__cstring",
        address: dataAddress, bytes: bytes, sectionFlags: cStringLiterals,
    )
}

func dataSectionBinary(
    segname: String,
    sectname: String,
    address: UInt64,
    bytes: [UInt8],
    sectionFlags: UInt32,
) -> WalkedBinary {
    let textAddr: UInt64 = 0x1000
    let codeOffset = 512
    let dataOffset = codeOffset + 4
    var a = MachOAssembler()
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
    withUnsafeBytes(of: UInt32(0xD65F_03C0).littleEndian) { a.bytes.append(contentsOf: $0) }
    a.bytes.append(contentsOf: bytes)
    return walkedBinary(bytes: a.bytes)!
}

func dataSymbolReferenceBinary(sectionSize: UInt64 = 8) -> [UInt8] {
    var a = MachOAssembler()
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
    a.u32(0x1000_0800)
    a.bytes.append(contentsOf: [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00])
    a.nlist64(strx: 1, type: 0x0F, value: 0x1100)
    a.fixedString("\0_datum\0", length: 8)
    return a.bytes
}

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
        withUnsafeBytes(of: word.littleEndian) { a.bytes.append(contentsOf: $0) }
    }
    trailer(&a)
    return a.bytes
}
