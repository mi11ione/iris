// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
import Iris
import IrisCLICore
import Testing

/// Validates the `--stats` census: accumulation rules (sentinels in the
/// totals, not the mnemonic table), extension-site counters, the table
/// rendering against its golden, and the `--stats --json` object.
@Suite("Instruction census")
struct CensusTests {
    @Test func tableMatchesGolden() {
        let run = runCLI(["--stats", cliFixturePath("hello-arm64e")])
        #expect(run.status == CLI.exitSuccess)
        #expect(run.stdout == golden("hello-arm64e.stats.txt"))
    }

    @Test func jsonObjectMatchesGolden() {
        let run = runCLI(["--stats", "--json", cliFixturePath("dic-linked")])
        #expect(run.status == CLI.exitSuccess)
        #expect(run.stdout == golden("dic-linked.stats.json"))
    }

    @Test func jsonObjectParsesWithSchemaFields() throws {
        let run = runCLI(["--stats", "--json", cliFixturePath("dic-linked")])
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
        var census = Census()
        // pacia x0, x1 / irg x0, x1 / aese v0.16b, v1.16b /
        // casal x0, x1, [x2] / AMX ldy x0
        for word in [0xDAC1_0020, 0x9ADF_1020, 0x4E28_4820, 0xC8E0_FC41, 0x0020_1020] as [UInt32] {
            var bytes: [UInt8] = []
            withUnsafeBytes(of: word.littleEndian) { bytes.append(contentsOf: $0) }
            census.add(InstructionStream(bytes: bytes, features: .arm64e))
        }
        #expect(census.pointerAuthenticationSites == 1)
        #expect(census.memoryTaggingSites == 1)
        #expect(census.cryptoSites == 1)
        #expect(census.amxSites == 1)
        #expect(census.totalWords == 5)
        #expect(census.mnemonicCounts["ldy"] == 1)
    }

    @Test func amxSitesReachTheTable() {
        let run = runCLI(["--stats", "0x00201020"])
        #expect(run.stdout.contains("amx              1\n"))
        #expect(run.stdout.contains("  amx                       1\n"))
    }

    @Test func tableRendersTruncatedTailRow() {
        let run = runCLI(["--stats", "--bytes", "1f 20 03 d5 aa"])
        #expect(run.stdout.contains("truncated tails    1\n"))
        #expect(run.stdout.contains("total words        2\n"))
    }

    @Test func tableOmitsTailRowWhenNone() {
        let run = runCLI(["--stats", "--bytes", "1f 20 03 d5"])
        #expect(!run.stdout.contains("truncated tails"))
    }

    @Test func tableOrdersByCountThenName() {
        // Two rets, one nop, one mov: ret first, then mov/nop by name.
        let run = runCLI(["--stats", "--bytes", "c0 03 5f d6 1f 20 03 d5 e0 03 01 aa c0 03 5f d6"])
        let lines = run.stdout.split(separator: "\n").map(String.init)
        let start = lines.firstIndex(of: "mnemonics:").map { $0 + 1 }
        #expect(start != nil)
        let mnemonicRows = lines.suffix(from: start ?? lines.count).map { $0.trimmingCharacters(in: .whitespaces) }
        #expect(mnemonicRows == ["ret                       2", "mov                       1", "nop                       1"])
    }

    @Test func directStatsHonorFeatures() {
        // ldraa is gated on the arm64e feature set: honest UNDEFINED
        // without it, a counted PAC site with it.
        let without = runCLI(["--stats", "0xf8200420"])
        #expect(without.stdout.contains("undefined          1\n"))
        let with = runCLI(["--stats", "--features", "arm64e", "0xf8200420"])
        #expect(with.stdout.contains("undefined          0\n"))
        #expect(with.stdout.contains("pointer-auth     1\n"))
    }
}
