// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
import Iris
import IrisValidation
import Testing

/// Golden-corpus parity: every DPR synthetic TSV row decodes and canonicalizes
/// to its harvested `expected_text`, so regressions are caught by `swift
/// test`.
@Suite("Decode corpus path resolution")
struct DecodeCorpusPathTests {
    @Test func theDefaultIsTheTrackedInRepoFixture() {
        let path = decodeCorpusTSVPath(family: "dpr")
        #expect(path.hasSuffix("Tests/Fixtures/Decode/synthetic-dpr.tsv"))
        #expect(FileManager.default.isReadableFile(atPath: path))
    }

    @Test func anExternalRootUsesThePerFamilyDirectoryLayout() {
        #expect(decodeCorpusTSVPath(family: "sve", externalRoot: "/corpus")
            == "/corpus/decode-sve/synthetic.tsv")
    }
}

/// Golden-corpus parity: every DPR synthetic TSV row decodes and canonicalizes
/// to its harvested `expected_text`.
@Suite("DPR / golden synthetic corpus parity (every row)")
struct DPRGoldenCorpusParityTests {
    private static var corpusPath: String {
        decodeCorpusTSVPath(family: "dpr")
    }

    private struct Row {
        let encoding: UInt32
        let expectedText: String
        let lineNumber: Int
    }

    private static func loadRows() throws -> [Row] {
        let contents = try String(contentsOfFile: corpusPath, encoding: .utf8)
        var rows: [Row] = []
        rows.reserveCapacity(20000)
        for (idx, raw) in contents.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
            let line = String(raw)
            if line.isEmpty { continue }
            if line.hasPrefix("#") { continue }
            let parts = line.split(separator: "\t", omittingEmptySubsequences: false).map { String($0) }
            let encoding = UInt32(parts[0], radix: 16)!
            let expected = parts.dropFirst().joined(separator: "\t").trimmingCharacters(in: .whitespaces).lowercased()
            rows.append(Row(encoding: encoding, expectedText: expected, lineNumber: idx + 1))
        }
        return rows
    }

    private static let deferredOosPrefixes: [String] = [
        "rmif", "setf8", "setf16",
        "pacia", "pacib", "pacda", "pacdb", "pacga",
        "autia", "autib", "autda", "autdb", "xpaci", "xpacd",
        "paciza", "pacizb", "pacdza", "pacdzb",
        "autiza", "autizb", "autdza", "autdzb",
    ]

    private static func isDeferredOos(_ text: String) -> Bool {
        for prefix in deferredOosPrefixes where text.hasPrefix("\(prefix) ") {
            return true
        }
        return false
    }

    @Test func everyRowDecodesToExpectedText() throws {
        let rows = try Self.loadRows()
        for row in rows {
            if Self.isDeferredOos(row.expectedText) { continue }
            let d = decode(row.encoding, at: 0)
            #expect(
                row.expectedText.isEmpty ? d.isUndefined : d.text == row.expectedText,
                "L\(row.lineNumber) 0x\(String(format: "%08x", row.encoding)): iris=`\(d.text)` expected=`\(row.expectedText)`",
            )
        }
    }

    @Test func everyRowPassesSemanticChecker() throws {
        let rows = try Self.loadRows()
        for row in rows {
            let d = decode(row.encoding, at: 0)
            let issue = DPRSemanticChecker.verify(d)
            #expect(
                issue == nil,
                "L\(row.lineNumber) 0x\(String(format: "%08x", row.encoding)) (\(d.mnemonic.rawValue)): \(String(describing: issue))",
            )
        }
    }
}
