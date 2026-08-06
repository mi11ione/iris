// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
import Iris
import IrisCLICore
import Testing

/// Drives `S_SYMBOL_STUBS` resolution over synthetic binaries.
@Suite("Stub symbolication")
struct StubSymbolicationTests {
    static let symbolStubsType: UInt32 = 0x8
    static let indirectLocal: UInt32 = 0x8000_0000

    struct Sym {
        var strx: UInt32
        var value: UInt64 = 0
        var type: UInt8 = 0x1
    }

    func stubBinary(
        stubSize: UInt64 = 8,
        stride: UInt32 = 8,
        firstIndirect: UInt32 = 0,
        indirectSlots: [UInt32] = [0],
        symbols: [Sym] = [Sym(strx: 1)],
        stringTable: [UInt8] = Array("\0_strcoll\0".utf8),
        declaredIndirectCount: Int? = nil,
        symoffOverride: UInt32? = nil,
    ) -> [UInt8] {
        var a = MachOAssembler()
        let sizeofcmds: UInt32 = 232 + 24 + 80
        a.machHeader64(ncmds: 3, sizeofcmds: sizeofcmds)
        a.segmentCommand64(name: "__TEXT", vmaddr: 0x1000, nsects: 2, cmdsize: 232)
        a.section64(
            sectname: "__text",
            segname: "__TEXT",
            addr: 0x1000,
            size: 4,
            offset: 512,
            flags: pureInstructions | someInstructions,
        )
        let indirectOffset = 520
        let symtabOffset = indirectOffset + indirectSlots.count * 4
        let stringOffset = symtabOffset + symbols.count * 16
        a.section64(
            sectname: "__stubs",
            segname: "__TEXT",
            addr: 0x2000,
            size: stubSize,
            offset: 516,
            flags: Self.symbolStubsType | someInstructions,
            reserved1: firstIndirect,
            reserved2: stride,
        )
        a.symtabCommand(
            symoff: symoffOverride ?? UInt32(symtabOffset),
            nsyms: UInt32(symbols.count),
            stroff: UInt32(stringOffset),
            strsize: UInt32(stringTable.count),
        )
        a.dysymtabCommand(
            indirectsymoff: UInt32(indirectOffset),
            nindirectsyms: UInt32(declaredIndirectCount ?? indirectSlots.count),
        )
        a.pad(to: 512)
        a.u32(0xD503_201F)
        a.u32(0)
        for slot in indirectSlots {
            a.u32(slot)
        }
        for sym in symbols {
            a.nlist64(strx: sym.strx, type: sym.type, value: sym.value)
        }
        a.bytes.append(contentsOf: stringTable)
        return a.bytes
    }

    @Test func resolvesStubEntryToItsImportedSymbol() throws {
        let binary = try #require(walkedBinary(bytes: stubBinary()))
        #expect(binary.stubTargets[0x2000] == "_strcoll")
    }

    @Test func zeroStrideResolvesNothing() throws {
        let binary = try #require(walkedBinary(bytes: stubBinary(stride: 0)))
        #expect(binary.stubTargets.isEmpty)
    }

    @Test func zeroSizeStubSectionResolvesNothing() throws {
        let binary = try #require(walkedBinary(bytes: stubBinary(stubSize: 0)))
        #expect(binary.stubTargets.isEmpty)
    }

    @Test func entriesPastTheIndirectTableStop() throws {
        let binary = try #require(walkedBinary(bytes: stubBinary(
            stubSize: 16,
            indirectSlots: [0],
            declaredIndirectCount: 1,
        )))
        #expect(binary.stubTargets[0x2000] == "_strcoll")
        #expect(binary.stubTargets[0x2008] == nil)
    }

    @Test func localSlotNamesNoSymbol() throws {
        let binary = try #require(walkedBinary(bytes: stubBinary(indirectSlots: [Self.indirectLocal])))
        #expect(binary.stubTargets.isEmpty)
    }

    @Test func outOfRangeSymbolIndexIsDropped() throws {
        let binary = try #require(walkedBinary(bytes: stubBinary(indirectSlots: [9])))
        #expect(binary.stubTargets.isEmpty)
    }

    @Test func zeroStringIndexIsDropped() throws {
        let binary = try #require(walkedBinary(bytes: stubBinary(symbols: [Sym(strx: 0)])))
        #expect(binary.stubTargets.isEmpty)
    }

    @Test func stringIndexPastTableIsDropped() throws {
        let binary = try #require(walkedBinary(bytes: stubBinary(symbols: [Sym(strx: 999)])))
        #expect(binary.stubTargets.isEmpty)
    }

    @Test func emptyNameIsDropped() throws {
        let binary = try #require(walkedBinary(bytes: stubBinary(
            symbols: [Sym(strx: 1)],
            stringTable: Array("\0\0".utf8),
        )))
        #expect(binary.stubTargets.isEmpty)
    }

    @Test func unterminatedNameIsDropped() throws {
        let binary = try #require(walkedBinary(bytes: stubBinary(
            symbols: [Sym(strx: 1)],
            stringTable: Array("\0abc".utf8),
        )))
        #expect(binary.stubTargets.isEmpty)
    }

    @Test func outOfBoundsSymtabResolvesNoStubsSilently() throws {
        let binary = try #require(walkedBinary(bytes: stubBinary(symoffOverride: 0xF000_0000)))
        #expect(binary.stubTargets.isEmpty)
        #expect(binary.diagnostics.map(\.kind).contains(.symbolTableOutOfBounds))
        #expect(binary.diagnostics.allSatisfy { $0.kind != .indirectSymbolTableOutOfBounds })
    }
}
