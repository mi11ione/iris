// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisCLICore
import Testing

/// Validates the walker against the well-formed fixture binaries:
/// section discovery, symbol indexing, function starts, architecture
/// and feature detection — the documented structure of each fixture.
@Suite("Mach-O walker on well-formed binaries")
struct MachOWalkerTests {
    @Test func thinARM64Walk() throws {
        let binary = try #require(walkedBinary(cliFixturePath("hello-arm64")))
        #expect(binary.architecture == "arm64")
        #expect(binary.features == [])
        #expect(binary.diagnostics.isEmpty)

        let names = binary.codeSections.map(\.displayName)
        #expect(names.contains("__TEXT,__text"))
        let text = try #require(binary.codeSections.first { $0.sectionName == "__text" })
        #expect(text.byteCount % 4 == 0)
        #expect(text.dataInCode.isEmpty)

        for symbol in ["_add42", "_sum_to", "_helper", "_main"] {
            #expect(binary.symbols.symbols(in: text.address ..< text.address + text.byteCount)
                .contains { $0.name == symbol })
        }
        #expect(binary.functionStarts.count == 4)
        for start in binary.functionStarts {
            #expect(binary.symbols.name(at: start) != nil)
        }
    }

    @Test func arm64eSliceImpliesPACFeatures() throws {
        let binary = try #require(walkedBinary(cliFixturePath("hello-arm64e")))
        #expect(binary.architecture == "arm64e")
        #expect(binary.features == .arm64e)

        let text = try #require(binary.codeSections.first { $0.sectionName == "__text" })
        let stream = text.instructions(features: binary.features)
        #expect(stream.contains { $0.usesPointerAuthentication })
    }

    @Test func strippedBinaryKeepsFunctionStarts() throws {
        let binary = try #require(walkedBinary(cliFixturePath("hello-stripped")))
        #expect(binary.functionStarts.count == 4)
        let text = try #require(binary.codeSections.first { $0.sectionName == "__text" })
        let inText = binary.symbols.symbols(in: text.address ..< text.address + text.byteCount)
        #expect(inText.isEmpty)
    }

    @Test func objectFileWalk() throws {
        let binary = try #require(walkedBinary(cliFixturePath("dic-arm64.o")))
        #expect(binary.architecture == "arm64")
        #expect(binary.functionStarts.isEmpty)
        let text = try #require(binary.codeSections.first { $0.sectionName == "__text" })
        #expect(binary.symbols.name(at: text.address) == "_main")
    }

    @Test func sectionDecodeIsZeroCopyConsistent() throws {
        let binary = try #require(walkedBinary(cliFixturePath("hello-arm64")))
        let text = try #require(binary.codeSections.first { $0.sectionName == "__text" })
        let stream = text.instructions(features: binary.features)
        #expect(stream.baseAddress == text.address)
        #expect(stream.byteCount == text.byteCount)
        #expect(UInt64(stream.records.count) == text.byteCount / 4)
        let main = try #require(binary.symbols.symbols(in: text.address ..< text.address + text.byteCount)
            .first { $0.name == "_main" })
        #expect(stream.contains { $0.address == main.address })
    }

    @Test func walkedBinaryValueRoundTrips() {
        let binary = WalkedBinary(
            path: "p",
            architecture: "arm64",
            features: .arm64e,
            codeSections: [],
            symbols: .empty,
            functionStarts: [1, 2],
            diagnostics: [WalkerDiagnostic(kind: .sectionEmpty, detail: "d")],
        )
        #expect(binary.path == "p")
        #expect(binary.architecture == "arm64")
        #expect(binary.features == .arm64e)
        #expect(binary.codeSections.isEmpty)
        #expect(binary.functionStarts == [1, 2])
        #expect(binary.diagnostics == [WalkerDiagnostic(kind: .sectionEmpty, detail: "d")])
    }

    @Test func externalSymbolWinsSharedAddress() throws {
        // In MH_OBJECT output the assembler's local `ltmp0` shares the
        // section-start address with `_main`; the walker feeds externals
        // first so the listing label is the external name.
        let binary = try #require(walkedBinary(cliFixturePath("dic-arm64.o")))
        let text = try #require(binary.codeSections.first { $0.sectionName == "__text" })
        #expect(binary.symbols.name(at: text.address) == "_main")
    }

    @Test func outcomeProjectionsKeepOnlyTheirOwnCase() {
        // One outcome of each kind, all synthetic. Each projection returns a
        // payload for its own case and nil for every other, and the diagnostic
        // projection reads the kinds from a binary outcome and nothing from a
        // failure outcome.
        var inflated = minimalBinary(words: [0xD503_201F])
        inflated.replaceSubrange(20 ..< 24, with: [0x00, 0x00, 0x10, 0x00]) // sizeofcmds = 1 MiB
        let binary = walkBytes(inflated)
        let notMachO = walkBytes([0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0])
        let unreadable = walkBytes([])
        let unavailable = walkBytes(minimalBinary(words: [0xD503_201F]), arch: .arm64e)

        // Each accessor projects its own case.
        #expect(binaryOutcome(binary) != nil)
        #expect(notMachOOutcome(notMachO) != nil)
        #expect(unreadableOutcome(unreadable) != nil)
        #expect(archUnavailableOutcome(unavailable) != nil)

        // And returns nil for a different case (the else arm of each guard).
        #expect(binaryOutcome(notMachO) == nil)
        #expect(notMachOOutcome(binary) == nil)
        #expect(unreadableOutcome(binary) == nil)
        #expect(archUnavailableOutcome(binary) == nil)

        // The diagnostic projection reads a binary's kinds and is empty for
        // every failure outcome.
        let kinds = diagnosticKinds(of: binary)
        #expect(kinds.contains(.loadCommandRegionTruncated))
        #expect(diagnosticKinds(of: notMachO).isEmpty)
        #expect(diagnosticKinds(of: unreadable).isEmpty)
        #expect(diagnosticKinds(of: unavailable).isEmpty)
    }
}
