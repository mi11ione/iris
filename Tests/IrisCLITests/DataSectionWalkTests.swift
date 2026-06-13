// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisCLICore
import Testing

/// Validates the walker's data-section collection (the non-code,
/// file-backed sections feeding the referenced-data annotation) and the
/// `DataSection` zero-copy reads: section attribution, cstring detection,
/// string reads, and the bounds guards that keep a clamped or hostile
/// section total.
@Suite("Data-section walk")
struct DataSectionWalkTests {
    @Test func cstringSectionIsCollectedAndReadable() throws {
        let binary = try #require(walkedBinary(cliFixturePath("strings-arm64")))
        let cstring = try #require(binary.dataSections.first { $0.sectionName == "__cstring" })
        #expect(cstring.displayName == "__TEXT,__cstring")
        #expect(cstring.isCStringLiteral)
        // The literal pool holds the two source strings; the first one
        // reads back from its own address.
        let world = cstring.cString(at: cstring.address &+ 12)
        #expect(world == "world")
        let hello = cstring.cString(at: cstring.address)
        #expect(hello == "hello, %s!\n")
    }

    @Test func dataSectionsExcludeCodeSections() throws {
        let binary = try #require(walkedBinary(cliFixturePath("strings-arm64")))
        // A section is in exactly one of the two lists: __text is code,
        // __cstring is data, never both.
        let codeNames = Set(binary.codeSections.map(\.displayName))
        let dataNames = Set(binary.dataSections.map(\.displayName))
        #expect(codeNames.contains("__TEXT,__text"))
        #expect(!dataNames.contains("__TEXT,__text"))
        #expect(codeNames.isDisjoint(with: dataNames))
    }

    @Test func containsAddressIsHalfOpenAndWrapSafe() {
        let section = syntheticDataSectionValue(address: 0x2000, byteCount: 0x100)
        #expect(section.containsAddress(0x2000))
        #expect(section.containsAddress(0x20FF))
        #expect(!section.containsAddress(0x2100)) // exclusive end
        #expect(!section.containsAddress(0x1FFF))
    }

    @Test func cStringReadOutsideTheSectionIsNil() {
        let section = syntheticCStringSectionValue(address: 0x3000, bytes: Array("ok\u{0}".utf8))
        #expect(section.cString(at: 0x3000) == "ok")
        // Past the section's range: no read.
        #expect(section.cString(at: 0x4000) == nil)
        #expect(section.cString(at: 0x2FFF) == nil)
    }

    @Test func cStringWithoutTerminatorIsNil() {
        // Bytes with no NUL in the section: readCString finds no terminator.
        let section = syntheticCStringSectionValue(address: 0x3000, bytes: [0x41, 0x42, 0x43])
        #expect(section.cString(at: 0x3000) == nil)
    }

    @Test func nonCStringDataSectionReadsNoString() throws {
        // A __const section is collected but not flagged cstring, so the
        // resolver reads no string from it (only section + symbol tiers).
        let binary = dataSectionBinary(
            segname: "__DATA", sectname: "__const",
            address: 0x5000, bytes: [0xDE, 0xAD, 0xBE, 0xEF], sectionFlags: 0,
        )
        let section = try #require(binary.dataSections.first { $0.sectionName == "__const" })
        #expect(!section.isCStringLiteral)
        #expect(binary.referencedDataResolver.resolve(target: 0x5000)?.string == nil)
        #expect(binary.referencedDataResolver.resolve(target: 0x5000)?.section == "__DATA,__const")
    }

    @Test func zerofillSectionIsNotCollectedAsData() {
        // A zerofill section (type 0x1) has no file content, so it is not a
        // data section the annotation can read.
        let bss: UInt32 = 0x1 // S_ZEROFILL
        let binary = dataSectionBinary(
            segname: "__DATA", sectname: "__bss",
            address: 0x6000, bytes: [], sectionFlags: bss,
        )
        #expect(!binary.dataSections.contains { $0.sectionName == "__bss" })
    }

    @Test func zeroSizeDataSectionIsSkipped() {
        // A non-zerofill data section declaring zero bytes has nothing to
        // read, so it is dropped (the size>0 guard), not collected empty.
        let binary = dataSectionBinary(
            segname: "__DATA", sectname: "__const",
            address: 0x7000, bytes: [], sectionFlags: 0,
        )
        #expect(!binary.dataSections.contains { $0.sectionName == "__const" })
    }

    @Test func aBinaryWithNoDataSectionsResolvesNothing() throws {
        // hello-arm64 is pure code (no cstring/const referenced); its
        // resolver still answers, just never resolves a target.
        let binary = try #require(walkedBinary(cliFixturePath("hello-arm64")))
        let resolver = binary.referencedDataResolver
        #expect(resolver.resolve(target: binary.functionStarts.first ?? 0) == nil)
    }

    // MARK: helpers

    func syntheticDataSectionValue(address: UInt64, byteCount: Int) -> DataSection {
        let binary = dataSectionBinary(
            segname: "__DATA", sectname: "__const",
            address: address, bytes: [UInt8](repeating: 0, count: byteCount), sectionFlags: 0,
        )
        return binary.dataSections.first { $0.address == address }!
    }

    func syntheticCStringSectionValue(address: UInt64, bytes: [UInt8]) -> DataSection {
        stringSectionBinary(address: address, bytes: bytes).dataSections.first { $0.address == address }!
    }
}
