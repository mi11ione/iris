// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
import Iris
import IrisValidation
import Testing

private func dispatchDecode(_ encoding: UInt32) -> Instruction {
    decode(encoding, at: 0, features: .arm64e)
}

/// Golden-corpus parity for the SIMD & Floating-Point family: every harvested
/// row reproduces its `expected_text`, every reserved row stays UNDEFINED, and
/// every record passes `SIMDFPSemanticChecker.verify`.
@Suite("SIMD/FP golden synthetic corpus parity (every row)")
struct SIMDFPGoldenCorpusParityTests {
    private struct Row {
        let encoding: UInt32
        let expectedText: String
        let lineNumber: Int
    }

    private static func loadRows() throws -> [Row] {
        let path = decodeCorpusTSVPath(family: "simd-fp")
        let contents = try String(contentsOfFile: path, encoding: .utf8)
        var rows: [Row] = []
        rows.reserveCapacity(45000)
        for (idx, raw) in contents.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
            let line = String(raw)
            if line.isEmpty { continue }
            if line.hasPrefix("#") { continue }
            let parts = line.split(separator: "\t", omittingEmptySubsequences: false).map { String($0) }
            let encoding = UInt32(parts[0], radix: 16)!
            let expected = parts.dropFirst().joined(separator: "\t")
                .trimmingCharacters(in: .whitespaces).lowercased()
            rows.append(Row(encoding: encoding, expectedText: expected, lineNumber: idx + 1))
        }
        return rows
    }

    @Test func corpusIsNonEmpty() throws {
        let rows = try Self.loadRows()
        #expect(rows.count > 40000, "synthetic corpus shrank unexpectedly: \(rows.count) rows")
    }

    @Test func everyRowDecodesToItsExpectedText() throws {
        let rows = try Self.loadRows()
        for row in rows {
            let d = dispatchDecode(row.encoding)
            #expect(
                row.expectedText.isEmpty ? d.isUndefined : d.text == row.expectedText,
                "L\(row.lineNumber) 0x\(String(row.encoding, radix: 16)): iris=`\(d.text)` expected=`\(row.expectedText)`",
            )
        }
    }

    @Test func reservedRowsDecodeToUndefined() throws {
        let rows = try Self.loadRows()
        var reservedSeen = 0
        for row in rows where row.expectedText.isEmpty {
            let d = dispatchDecode(row.encoding)
            #expect(
                d.mnemonic == .undefined && d.category == .undefined,
                "L\(row.lineNumber) 0x\(String(row.encoding, radix: 16)) should be UNDEFINED",
            )
            reservedSeen += 1
        }
        #expect(reservedSeen > 20000, "expected reserved-encoding negatives in the corpus")
    }

    @Test func everyRowPassesTheSemanticChecker() throws {
        let rows = try Self.loadRows()
        for row in rows {
            let d = dispatchDecode(row.encoding)
            if d.category != .simdAndFP { continue }
            let issue = SIMDFPSemanticChecker.verify(d)
            #expect(
                issue == nil,
                "L\(row.lineNumber) 0x\(String(row.encoding, radix: 16)): \(String(describing: issue))",
            )
        }
    }

    @Test func everyDecodedRecordPreservesItsEncodingAndStaysNonBranching() throws {
        let rows = try Self.loadRows()
        for row in rows {
            let d = dispatchDecode(row.encoding)
            #expect(d.encoding == row.encoding, "L\(row.lineNumber): encoding preserved")
            #expect(d.branchClass == .none, "L\(row.lineNumber): branchClass")
        }
    }

    @Test func corpusSpansEveryFloatingPointAtomicMnemonic() throws {
        let rows = try Self.loadRows()
        var seen: Set<UInt16> = []
        for row in rows {
            let d = dispatchDecode(row.encoding)
            if d.mnemonic != .undefined { seen.insert(d.mnemonic.rawValue) }
        }
        let atomics: [Mnemonic] = [
            .ldbfadd, .ldbfadda, .ldbfaddl, .ldbfaddal,
            .ldbfmax, .ldbfmaxa, .ldbfmaxl, .ldbfmaxal,
            .ldbfmin, .ldbfmina, .ldbfminl, .ldbfminal,
            .ldbfmaxnm, .ldbfmaxnma, .ldbfmaxnml, .ldbfmaxnmal,
            .ldbfminnm, .ldbfminnma, .ldbfminnml, .ldbfminnmal,
            .ldfadd, .ldfadda, .ldfaddl, .ldfaddal,
            .ldfmax, .ldfmaxa, .ldfmaxl, .ldfmaxal,
            .ldfmin, .ldfmina, .ldfminl, .ldfminal,
            .ldfmaxnm, .ldfmaxnma, .ldfmaxnml, .ldfmaxnmal,
            .ldfminnm, .ldfminnma, .ldfminnml, .ldfminnmal,
            .stbfadd, .stbfaddl, .stbfmax, .stbfmaxl, .stbfmin, .stbfminl,
            .stbfmaxnm, .stbfmaxnml, .stbfminnm, .stbfminnml,
            .stfadd, .stfaddl, .stfmax, .stfmaxl, .stfmin, .stfminl,
            .stfmaxnm, .stfmaxnml, .stfminnm, .stfminnml,
        ]
        for m in atomics {
            #expect(seen.contains(m.rawValue), "corpus misses \(m.name)")
        }
        for m: Mnemonic in [.fmlal, .fmlal2, .fmlsl, .fmlsl2, .fmmla, .fdot] {
            #expect(seen.contains(m.rawValue), "corpus misses \(m.name)")
        }
    }
}
