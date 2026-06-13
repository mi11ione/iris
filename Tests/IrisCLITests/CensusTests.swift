// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
import Iris
import IrisCLICore
import Testing

/// Validates the `stats` verb census: accumulation rules (sentinels in the
/// totals, not the mnemonic table), extension-site counters, the table
/// rendering against its golden, and the `stats --json` object. The census
/// reads a Mach-O file, so the table/JSON-shape unit checks build a
/// ``Census`` over a synthesized stream directly (the same accumulation the
/// verb drives) and assert on its rendering.
@Suite("Instruction census")
struct CensusTests {
    /// A census accumulated over one little-endian word stream.
    func census(words: [UInt32], features: Features = []) -> Census {
        var bytes: [UInt8] = []
        for word in words {
            withUnsafeBytes(of: word.littleEndian) { bytes.append(contentsOf: $0) }
        }
        var census = Census()
        census.add(InstructionStream(bytes: bytes, features: features))
        return census
    }

    // MARK: CLI integration over a file

    @Test func tableMatchesGolden() {
        let run = runCLI(["stats", cliFixturePath("hello-arm64e")])
        #expect(run.status == CLI.exitSuccess)
        #expect(run.stdout == golden("hello-arm64e.stats.txt"))
    }

    @Test func jsonObjectMatchesGolden() {
        let run = runCLI(["stats", "--json", cliFixturePath("dic-linked")])
        #expect(run.status == CLI.exitSuccess)
        #expect(run.stdout == golden("dic-linked.stats.json"))
    }

    @Test func jsonObjectParsesWithSchemaFields() throws {
        let run = runCLI(["stats", "--json", cliFixturePath("dic-linked")])
        let fields = try #require(
            (try? JSONSerialization.jsonObject(with: Data(run.stdout.utf8))) as? [String: Any],
        )
        #expect(fields["schemaVersion"] as? Int == JSONText.schemaVersion)
        #expect(fields["kind"] as? String == "census")
        #expect(fields["totalWords"] as? Int == 20)
        #expect(fields["dataWords"] as? Int == 2)
        #expect(fields["undefinedWords"] as? Int == 0)
        let mnemonics = try #require(fields["mnemonics"] as? [String: Int])
        #expect(mnemonics["ret"] == 5)
        let extensions = try #require(fields["extensions"] as? [String: Int])
        #expect(extensions["pointerAuthentication"] == 0)
    }

    @Test func arm64eBinaryCountsPACSites() throws {
        let binary = try #require(walkedBinary(cliFixturePath("hello-arm64e")))
        var census = Census()
        for section in binary.codeSections {
            census.add(section.instructions(features: binary.features))
        }
        #expect(census.pointerAuthenticationSites == 4)
        #expect(census.totalWords == 56)
        #expect(census.mnemonicCounts["pacibsp"] == 2)
        #expect(census.mnemonicCounts["retab"] == 2)
    }

    // MARK: Accumulation rules

    @Test func sentinelsCountInTotalsNotMnemonics() {
        var census = Census()
        let stream = InstructionStream(
            bytes: [0x1F, 0x20, 0x03, 0xD5, 0x00, 0x00, 0x00, 0x04, 0xAA],
            dataInCode: [DataInCodeSpan(offset: 4, length: 4, kind: .data)],
        )
        census.add(stream)
        #expect(census.totalWords == 3)
        #expect(census.dataWords == 1)
        #expect(census.truncatedTails == 1)
        #expect(census.undefinedWords == 0)
        #expect(census.mnemonicCounts == ["nop": 1])
        #expect(census.categoryCounts["dataInCodeMarker"] == 1)
        #expect(census.categoryCounts["truncatedTail"] == 1)
    }

    @Test func undefinedWordsCount() {
        var census = Census()
        census.add(InstructionStream(bytes: [0x00, 0x00, 0x00, 0x04]))
        #expect(census.undefinedWords == 1)
        #expect(census.totalWords == 1)
        #expect(census.mnemonicCounts.isEmpty)
    }

    @Test func extensionSiteCounters() {
        // pacia x0, x1 / irg x0, x1 / aese v0.16b, v1.16b /
        // casal x0, x1, [x2] / AMX ldy x0
        let census = census(words: [0xDAC1_0020, 0x9ADF_1020, 0x4E28_4820, 0xC8E0_FC41, 0x0020_1020], features: .arm64e)
        #expect(census.pointerAuthenticationSites == 1)
        #expect(census.memoryTaggingSites == 1)
        #expect(census.cryptoSites == 1)
        #expect(census.amxSites == 1)
        #expect(census.totalWords == 5)
        #expect(census.mnemonicCounts["ldy"] == 1)
    }

    // MARK: Table rendering (the rendering the `stats` verb prints)

    @Test func amxSiteReachesTheTable() {
        let lines = census(words: [0x0020_1020]).tableLines()
        // The extension-sites row and the per-category row both carry it.
        #expect(lines.contains("  amx              1"))
        #expect(lines.contains("  amx                       1"))
    }

    @Test func tableRendersTruncatedTailRow() {
        var census = Census()
        census.add(InstructionStream(bytes: [0x1F, 0x20, 0x03, 0xD5, 0xAA])) // nop + 1-byte tail
        let lines = census.tableLines()
        #expect(lines.contains("truncated tails    1"))
        #expect(lines.contains("total words        2"))
    }

    @Test func tableOmitsTailRowWhenNone() {
        let lines = census(words: [0xD503_201F]).tableLines()
        #expect(!lines.contains { $0.hasPrefix("truncated tails") })
    }

    @Test func tableOrdersByCountThenName() throws {
        // Two rets, one nop, one mov: ret first, then mov/nop by name.
        let lines = census(words: [0xD65F_03C0, 0xD503_201F, 0xAA01_03E0, 0xD65F_03C0]).tableLines()
        let header = try #require(lines.firstIndex(of: "mnemonics:"))
        let mnemonicRows = lines.suffix(from: header + 1).map { $0.trimmingCharacters(in: .whitespaces) }
        #expect(mnemonicRows == ["ret                       2", "mov                       1", "nop                       1"])
    }

    @Test func censusHonorsFeatures() {
        // ldraa is gated on the arm64e feature set: honest UNDEFINED
        // without it, a counted PAC site with it.
        let without = census(words: [0xF820_0420])
        #expect(without.tableLines().contains("undefined          1"))
        let with = census(words: [0xF820_0420], features: .arm64e)
        #expect(with.tableLines().contains("undefined          0"))
        #expect(with.tableLines().contains("  pointer-auth     1"))
    }

    // MARK: The verb is file-only

    @Test func statsRejectsARawWord() {
        // The census reads a Mach-O file; a raw word routes to decode.
        let run = runCLI(["stats", "0x00201020"])
        #expect(run.status == CLI.exitUsage)
        #expect(run.stderr.contains("iris stats: error: '0x00201020' is a raw word; use 'iris decode 0x00201020'"))
    }
}
