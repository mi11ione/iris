// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisCLICore
import Testing

/// Validates the byte-swapped (`cigam`) walk paths: a big-endian-header
/// Mach-O — a shape no ARM64 toolchain emits but the format permits —
/// walks identically to its little-endian twin, every multi-byte header
/// field passing through the swap layer. Instruction words stay
/// little-endian per the architecture regardless of header order.
@Suite("Byte-swapped Mach-O walk")
struct ByteSwappedWalkTests {
    /// One binary, both header byte orders: segment + section + symtab
    /// + function starts + data-in-code.
    func fullBinary(bigEndian: Bool) -> [UInt8] {
        var a = MachOAssembler(bigEndian: bigEndian)
        let sizeofcmds: UInt32 = 72 + 80 + 24 + 16 + 16
        a.machHeader64(ncmds: 4, sizeofcmds: sizeofcmds)
        a.segmentCommand64(name: "__TEXT", vmaddr: 0x1000, nsects: 1, cmdsize: 72 + 80)
        a.section64(
            sectname: "__text",
            segname: "__TEXT",
            addr: 0x1000,
            size: 12,
            offset: 512,
            flags: pureInstructions | someInstructions,
        )
        a.symtabCommand(symoff: 524, nsyms: 1, stroff: 540, strsize: 7)
        a.linkeditDataCommand(cmd: 0x26, dataoff: 547, datasize: 2)
        a.linkeditDataCommand(cmd: 0x29, dataoff: 549, datasize: 8)
        a.pad(to: 512)
        for word in [0xD503_201F, 0xDEAD_BEEF, 0xD65F_03C0] as [UInt32] {
            withUnsafeBytes(of: word.littleEndian) { a.bytes.append(contentsOf: $0) }
        }
        a.nlist64(strx: 1, type: 0x0F, value: 0x1000)
        a.fixedString("\0_main\0", length: 7)
        a.bytes.append(contentsOf: [0x00, 0x00]) // function starts: terminator
        a.dataInCodeEntry(offset: 516, length: 4, kind: 1)
        return a.bytes
    }

    @Test func bigEndianHeadersWalkLikeLittleEndian() throws {
        let little = try #require(walkedBinary(bytes: fullBinary(bigEndian: false)))
        let big = try #require(walkedBinary(bytes: fullBinary(bigEndian: true)))

        #expect(little.architecture == "arm64")
        #expect(big.architecture == little.architecture)
        #expect(big.codeSections.map(\.displayName) == little.codeSections.map(\.displayName))
        #expect(big.codeSections.map(\.address) == little.codeSections.map(\.address))
        #expect(big.codeSections.map(\.byteCount) == little.codeSections.map(\.byteCount))
        #expect(big.symbols.name(at: 0x1000) == "_main")
        #expect(little.symbols.name(at: 0x1000) == "_main")
        #expect(big.diagnostics == little.diagnostics)

        let bigText = try #require(big.codeSections.first)
        let littleText = try #require(little.codeSections.first)
        #expect(bigText.dataInCode == [DataInCodeSpan(offset: 4, length: 4, kind: .data)])
        #expect(littleText.dataInCode == bigText.dataInCode)
    }

    @Test func instructionWordsStayLittleEndian() throws {
        let binary = try #require(walkedBinary(bytes: fullBinary(bigEndian: true)))
        let text = try #require(binary.codeSections.first)
        let stream = text.instructions(features: binary.features)
        #expect(stream.map(\.encoding) == [0xD503_201F, 0xDEAD_BEEF, 0xD65F_03C0])
        #expect(stream.first?.text == "nop")
        #expect(stream.last?.text == "ret")
        #expect(stream[1].category == .dataInCodeMarker)
    }

    @Test func byteSwappedFatHeadersSelectSlices() throws {
        // Real fat headers are big-endian; the fixture run already covers
        // them. Pin the swap explicitly with a hand-built container too.
        var a = MachOAssembler(bigEndian: true)
        let slice = fullBinary(bigEndian: false)
        a.u32(0xCAFE_BABE)
        a.u32(1)
        a.u32(0x0100_000C)
        a.u32(0)
        a.u32(28)
        a.u32(UInt32(slice.count))
        a.u32(0)
        a.bytes.append(contentsOf: slice)
        let binary = try #require(walkedBinary(bytes: a.bytes))
        #expect(binary.architecture == "arm64")
        #expect(binary.symbols.name(at: 0x1000) == "_main")
    }
}
