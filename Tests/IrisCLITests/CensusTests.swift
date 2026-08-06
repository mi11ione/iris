// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
import Iris
import IrisCLICore
import Testing

/// Validates the `stats` census.
@Suite("Instruction census")
struct CensusTests {
    func census(words: [UInt32], features: Features = []) -> Census {
        var bytes: [UInt8] = []
        for word in words {
            withUnsafeBytes(of: word.littleEndian) { bytes.append(contentsOf: $0) }
        }
        var census = Census()
        census.add(InstructionStream(bytes: bytes, features: features))
        return census
    }

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

    @Test func slimCensusDropsConstantsKeepsEveryCount() throws {
        let full = runCLI(["stats", "--json", cliFixturePath("dic-linked")])
        let slim = runCLI(["stats", "--json", "--slim", cliFixturePath("dic-linked")])
        #expect(slim.status == CLI.exitSuccess)
        let fields = try #require(
            (try? JSONSerialization.jsonObject(with: Data(slim.stdout.utf8))) as? [String: Any],
        )
        #expect(fields["schemaVersion"] == nil)
        #expect(fields["kind"] == nil)
        #expect(fields["totalWords"] as? Int == 20)
        #expect(fields["dataWords"] as? Int == 2)
        let extensions = try #require(fields["extensions"] as? [String: Int])
        #expect(extensions["pointerAuthentication"] == 0)
        #expect(slim.stdout.utf8.count < full.stdout.utf8.count)
        #expect(full.stdout == golden("dic-linked.stats.json"))
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
        census.add(InstructionStream(bytes: [0x00, 0x00, 0x00, 0x02]))
        #expect(census.undefinedWords == 1)
        #expect(census.totalWords == 1)
        #expect(census.mnemonicCounts.isEmpty)
    }

    @Test func undefinedWordsInAnAllocatedTierStillCountAsUndefined() {
        let census = census(words: [0x80DE_B1FE, 0xEFBE_4786])
        #expect(census.totalWords == 2)
        #expect(census.undefinedWords == 2)
        #expect(census.mnemonicCounts.isEmpty)
        #expect(census.categoryCounts["sme"] == 1)
        #expect(census.categoryCounts["undefined"] == 1)
    }

    @Test func extensionSiteCounters() {
        let census = census(words: [0xDAC1_0020, 0x9ADF_1020, 0x4E28_4820, 0xC8E0_FC41, 0x0020_1020], features: .arm64e)
        #expect(census.pointerAuthenticationSites == 1)
        #expect(census.memoryTaggingSites == 1)
        #expect(census.cryptoSites == 1)
        #expect(census.amxSites == 1)
        #expect(census.totalWords == 5)
        #expect(census.mnemonicCounts["ldy"] == 1)
    }

    @Test func amxSiteReachesTheTable() {
        let lines = census(words: [0x0020_1020]).tableLines()
        #expect(lines.contains("  amx              1"))
        #expect(lines.contains("  amx                       1"))
    }

    @Test func tableRendersTruncatedTailRow() {
        var census = Census()
        census.add(InstructionStream(bytes: [0x1F, 0x20, 0x03, 0xD5, 0xAA]))
        let lines = census.tableLines()
        #expect(lines.contains("truncated tails    1"))
        #expect(lines.contains("total words        2"))
    }

    @Test func tableOmitsTailRowWhenNone() {
        let lines = census(words: [0xD503_201F]).tableLines()
        #expect(!lines.contains { $0.hasPrefix("truncated tails") })
    }

    @Test func tableOrdersByCountThenName() throws {
        let lines = census(words: [0xD65F_03C0, 0xD503_201F, 0xAA01_03E0, 0xD65F_03C0]).tableLines()
        let header = try #require(lines.firstIndex(of: "mnemonics:"))
        let mnemonicRows = lines.suffix(from: header + 1).map { $0.trimmingCharacters(in: .whitespaces) }
        #expect(mnemonicRows == ["ret                       2", "mov                       1", "nop                       1"])
    }

    @Test func censusHonorsFeatures() {
        let without = census(words: [0xF820_0420])
        #expect(without.tableLines().contains("undefined          1"))
        let with = census(words: [0xF820_0420], features: .arm64e)
        #expect(with.tableLines().contains("undefined          0"))
        #expect(with.tableLines().contains("  pointer-auth     1"))
    }

    @Test func statsRejectsARawWord() {
        let run = runCLI(["stats", "0x00201020"])
        #expect(run.status == CLI.exitUsage)
        #expect(run.stderr.contains("iris stats: error: '0x00201020' is a raw word; use 'iris decode 0x00201020'"))
    }
}
