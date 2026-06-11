// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
import Iris
import IrisCLICore
import Testing

/// Drives the walker's `S_SYMBOL_STUBS` resolution over synthetic
/// binaries no compiler emits: the happy path where a stub entry names
/// its imported symbol, and every degraded slot (zero stride, entries
/// past the indirect table, LOCAL/ABS slots, out-of-range symbol
/// indices, and unnamed / unterminated string-table entries) that must
/// drop the one entry and keep walking rather than fabricate a name or
/// crash.
@Suite("Stub symbolication")
struct StubSymbolicationTests {
    /// `S_SYMBOL_STUBS` section type (low byte of `section_64.flags`).
    static let symbolStubsType: UInt32 = 0x8
    /// `INDIRECT_SYMBOL_LOCAL` — a slot naming no imported symbol.
    static let indirectLocal: UInt32 = 0x8000_0000

    /// One `nlist_64` to lay into the synthetic symbol table.
    struct Sym {
        var strx: UInt32
        var value: UInt64 = 0
        var type: UInt8 = 0x1 // N_EXT
    }

    /// Assemble a one-`__text`-one-`__stubs` arm64 Mach-O with an
    /// `LC_SYMTAB` + `LC_DYSYMTAB`, fully parameterized so each test can
    /// perturb a single field. The stub section sits at VM `0x2000`;
    /// entry N resolves to indirect-table slot `firstIndirect + N`.
    func stubBinary(
        stubSize: UInt64 = 8,
        stride: UInt32 = 8,
        firstIndirect: UInt32 = 0,
        indirectSlots: [UInt32] = [0],
        symbols: [Sym] = [Sym(strx: 1)],
        stringTable: [UInt8] = Array("\0_strcoll\0".utf8),
        // Lets a test shrink the declared indirect count below the bytes
        // actually present (to exercise the "entry past the table" break).
        declaredIndirectCount: Int? = nil,
        // Overrides the symtab's symoff so it can be pointed out of bounds
        // (the indirect table stays in-bounds, so stub parsing reaches the
        // symtab-bounds guard rather than the indirect-table one).
        symoffOverride: UInt32? = nil,
    ) -> [UInt8] {
        var a = MachOAssembler()
        let sizeofcmds: UInt32 = 232 + 24 + 80 // segment(2 sects) + symtab + dysymtab
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
        // Payload layout, all after the 368-byte load-command region:
        //   512  code (one nop)
        //   520  indirect symbol table (4 bytes/slot)
        //        nlist_64 array (16 bytes/entry)
        //        string table
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
        a.u32(0xD503_201F) // nop, the __text content
        a.u32(0) // __stubs content padding (offset 516, unread)
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
        // reserved2 = 0: no entry can be enumerated.
        let binary = try #require(walkedBinary(bytes: stubBinary(stride: 0)))
        #expect(binary.stubTargets.isEmpty)
    }

    @Test func zeroSizeStubSectionResolvesNothing() throws {
        let binary = try #require(walkedBinary(bytes: stubBinary(stubSize: 0)))
        #expect(binary.stubTargets.isEmpty)
    }

    @Test func entriesPastTheIndirectTableStop() throws {
        // The section declares two entries (size 16 / stride 8) but the
        // indirect table only has one slot, so the second entry breaks.
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
        // Slot points at symbol index 9, but only one symbol exists.
        let binary = try #require(walkedBinary(bytes: stubBinary(indirectSlots: [9])))
        #expect(binary.stubTargets.isEmpty)
    }

    @Test func zeroStringIndexIsDropped() throws {
        // n_strx == 0 is "no name"; the entry resolves to nothing.
        let binary = try #require(walkedBinary(bytes: stubBinary(symbols: [Sym(strx: 0)])))
        #expect(binary.stubTargets.isEmpty)
    }

    @Test func stringIndexPastTableIsDropped() throws {
        let binary = try #require(walkedBinary(bytes: stubBinary(symbols: [Sym(strx: 999)])))
        #expect(binary.stubTargets.isEmpty)
    }

    @Test func emptyNameIsDropped() throws {
        // strx is non-zero but points at a NUL, so the C string is empty
        // and names nothing (distinct from the strx == 0 path).
        let binary = try #require(walkedBinary(bytes: stubBinary(
            symbols: [Sym(strx: 1)],
            stringTable: Array("\0\0".utf8),
        )))
        #expect(binary.stubTargets.isEmpty)
    }

    @Test func unterminatedNameIsDropped() throws {
        // strx points into a string table whose remaining bytes hold no
        // NUL terminator, so readCString finds no string.
        let binary = try #require(walkedBinary(bytes: stubBinary(
            symbols: [Sym(strx: 1)],
            stringTable: Array("\0abc".utf8), // no trailing NUL after "abc"
        )))
        #expect(binary.stubTargets.isEmpty)
    }

    @Test func outOfBoundsSymtabResolvesNoStubsSilently() throws {
        // The indirect table is in-bounds but the symtab's symoff runs
        // past the slice: parseSymbols already diagnoses that, so stub
        // resolution returns empty without a second diagnostic.
        let binary = try #require(walkedBinary(bytes: stubBinary(symoffOverride: 0xF000_0000)))
        #expect(binary.stubTargets.isEmpty)
        #expect(binary.diagnostics.map(\.kind).contains(.symbolTableOutOfBounds))
        #expect(binary.diagnostics.allSatisfy { $0.kind != .indirectSymbolTableOutOfBounds })
    }
}
