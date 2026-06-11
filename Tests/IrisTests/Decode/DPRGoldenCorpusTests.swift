// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
@_spi(Validation) import Iris
import Testing

/// Golden-corpus parity check at the unit-test level. Reads the DPR
/// synthetic corpus TSV (llvm-mc-harvested ground truth) and verifies
/// that for every row, decode → canonicalize → compare against the
/// harvested `expected_text` matches exactly — so regressions are
/// caught by `swift test` alone.
@Suite("DPR / golden synthetic corpus parity (every row)")
struct DPRGoldenCorpusParityTests {
    /// In-repo fixture by default; an external corpus tree when
    /// `IRIS_DECODE_CORPUS` is set — see `decodeCorpusTSVPath(family:)`.
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

    /// Mnemonic prefixes catalogued as deferred out-of-scope for the
    /// DPR family decoder (FEAT_FlagM2 RMIF/SETF and the DPR-encoded
    /// PAC tier). These rows have non-empty oracle text but the decoder
    /// correctly emits .undefined; the filter keeps the parity test
    /// gated on REAL divergences only.
    private static let deferredOosPrefixes: [String] = [
        "rmif", "setf8", "setf16",
        "pacia", "pacib", "pacda", "pacdb", "pacga",
        "autia", "autib", "autda", "autdb", "xpaci", "xpacd",
        "paciza", "pacizb", "pacdza", "pacdzb",
        "autiza", "autizb", "autdza", "autdzb",
    ]

    private static func isDeferredOos(_ text: String) -> Bool {
        // Every deferred mnemonic in the catalogue takes register operands
        // (no bare-mnemonic forms), so `prefix + " "` is the only shape the
        // corpus produces.
        for prefix in deferredOosPrefixes where text.hasPrefix("\(prefix) ") {
            return true
        }
        return false
    }

    @Test func everyRowDecodesToExpectedText() throws {
        let rows = try Self.loadRows()
        for row in rows {
            // Skip pre-catalogued deferred-out-of-scope rows.
            if Self.isDeferredOos(row.expectedText) { continue }
            let d = decode(row.encoding, at: 0)
            // The oracle's "" convention marks undefined encodings; Iris
            // text is total (`.long 0x…`), so the comparison maps "" to
            // the undefined witness.
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
