// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
import Iris
import IrisValidation
import Testing

private func dispatchDecode(_ encoding: UInt32) -> Instruction {
    decode(encoding, at: 0, features: .arm64e)
}

/// Golden-corpus parity: every in-scope L/S row reproduces its harvested
/// `expected_text`, every record passes `LSSemanticChecker.verify`, and the.
@Suite("L/S golden synthetic corpus parity (every row)")
struct LSGoldenCorpusParityTests {
    private static var corpusPath: String {
        decodeCorpusTSVPath(family: "ls")
    }

    private struct Row {
        let encoding: UInt32
        let expectedText: String
        let lineNumber: Int
    }

    private static func loadRows() throws -> [Row] {
        let contents = try String(contentsOfFile: corpusPath, encoding: .utf8)
        var rows: [Row] = []
        rows.reserveCapacity(8000)
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

    private static let deferredOosMnemonics: Set<String> = [
        "ld1", "ld2", "ld3", "ld4", "st1", "st2", "st3", "st4",
        "ld1r", "ld2r", "ld3r", "ld4r",
        "stg", "st2g", "stzg", "stz2g", "ldg", "ldgm", "stgm", "stzgm",
        "rprfm",
        "ld64b", "st64b", "st64bv", "st64bv0",
        "cpyp", "cpym", "cpye", "cpypwn", "cpymwn", "cpyewn",
        "cpyprn", "cpymrn", "cpyern", "cpypn", "cpymn", "cpyen",
        "cpyprt", "cpymrt", "cpyert", "cpypt", "cpymt", "cpyet",
        "setp", "setm", "sete", "setpn", "setmn", "seten",
        "setgp", "setgm", "setge", "setgpn", "setgmn", "setgen",
        "swpp", "swppa", "swppl", "swppal",
        "ldclrp", "ldclrpa", "ldclrpl", "ldclrpal",
        "ldsetp", "ldsetpa", "ldsetpl", "ldsetpal",
    ]

    private static func isDeferredOos(_ text: String) -> Bool {
        let fields = text.split(separator: " ", maxSplits: 1)
        let mnemonic = fields.first.map(String.init) ?? ""
        let firstOperand = fields.dropFirst().first?
            .split(separator: ",", maxSplits: 1)
            .first
            .map(String.init) ?? ""
        let simdRegisterOperand = firstOperand.range(
            of: #"^[bhsdq][0-9]+"#,
            options: .regularExpression,
        ) != nil
        return deferredOosMnemonics.contains(mnemonic) || simdRegisterOperand
    }

    @Test func corpusIsNonEmpty() throws {
        let rows = try Self.loadRows()
        #expect(rows.count > 6000, "synthetic corpus shrank unexpectedly: \(rows.count) rows")
    }

    @Test func everyInScopeRowDecodesToExpectedText() throws {
        let rows = try Self.loadRows()
        var checked = 0
        for row in rows {
            if Self.isDeferredOos(row.expectedText) { continue }
            let d = dispatchDecode(row.encoding)
            #expect(
                row.expectedText.isEmpty ? d.isUndefined : d.text == row.expectedText,
                "L\(row.lineNumber) 0x\(String(format: "%08x", row.encoding)): iris=`\(d.text)` expected=`\(row.expectedText)`",
            )
            checked += 1
        }
        #expect(checked > 5000, "too few in-scope rows checked: \(checked)")
    }

    @Test func everyRowPassesSemanticChecker() throws {
        let rows = try Self.loadRows()
        for row in rows {
            let d = dispatchDecode(row.encoding)
            if d.category == .simdAndFP { continue }
            let issue = LSSemanticChecker.verify(d)
            #expect(
                issue == nil,
                "L\(row.lineNumber) 0x\(String(format: "%08x", row.encoding)) (\(d.mnemonic.rawValue)): \(String(describing: issue))",
            )
        }
    }

    @Test func everyDecodedRecordCarriesLoadsAndStoresInvariants() throws {
        let rows = try Self.loadRows()
        for row in rows {
            let d = dispatchDecode(row.encoding)
            if d.mnemonic == .undefined { continue }
            if d.category == .simdAndFP { continue }
            if d.category == .memoryTagging { continue }
            #expect(d.category == .loadsAndStores, "L\(row.lineNumber): category")
            #expect(d.branchClass == .none, "L\(row.lineNumber): branchClass")
            #expect(d.flagEffect == .none, "L\(row.lineNumber): flagEffect")
            #expect(d.encoding == row.encoding, "L\(row.lineNumber): encoding preserved")
        }
    }

    @Test func reservedRowsDecodeToUndefinedInBothColumns() throws {
        let rows = try Self.loadRows()
        var reservedSeen = 0
        for row in rows where row.expectedText.isEmpty {
            let d = dispatchDecode(row.encoding)
            #expect(
                d.mnemonic == .undefined && d.category == .undefined,
                "L\(row.lineNumber) 0x\(String(format: "%08x", row.encoding)) should be UNDEFINED, got \(d.mnemonic.rawValue)",
            )
            reservedSeen += 1
        }
        #expect(reservedSeen > 0, "expected reserved-encoding negatives in the corpus")
    }

    @Test func syntheticCorpusSpansEveryDecoderReachableMnemonic() throws {
        let rows = try Self.loadRows()
        var seen: Set<UInt16> = []
        for row in rows {
            let d = dispatchDecode(row.encoding)
            if d.mnemonic != .undefined { seen.insert(d.mnemonic.rawValue) }
        }
        for (mnemonic, _, name) in LSMnemonicConstantsTests.allLSMnemonics {
            #expect(
                seen.contains(mnemonic.rawValue),
                "no synthetic-corpus encoding decodes to \(name) — the fixture misses this mnemonic",
            )
        }
    }

    @Test func syntheticCorpusSpansEveryPrefetchOperation() throws {
        let rows = try Self.loadRows()
        var prefetchValues: Set<UInt8> = []
        for row in rows {
            let d = dispatchDecode(row.encoding)
            guard d.mnemonic == .prfm || d.mnemonic == .prfum else { continue }
            for operand in d.operands {
                if case let .prefetchOperation(p) = operand {
                    prefetchValues.insert(p.rawValue)
                }
            }
        }
        for raw in UInt8(0) ... UInt8(31) {
            #expect(
                prefetchValues.contains(raw),
                "no PRFM/PRFUM corpus row carries prefetch operand #\(raw)",
            )
        }
    }

    @Test func deferredOosClassifierAcceptsAndRejectsByCatalogue() {
        let outOfScope = [
            "ldr q0, [x1]",
            "str d3, [sp, #8]",
            "ld1 { v0.16b }, [x1]",
            "stg x0, [x1, #0]",
            "ld64b x0, [x1]",
            "rprfm pldl1keep, x2, [x1]",
            "swpp x0, x1, [x2]",
        ]
        for text in outOfScope {
            #expect(Self.isDeferredOos(text), "expected deferred-OOS: `\(text)`")
        }
        let inScope = [
            "ldr x0, [x1]",
            "ldraa x0, [x0]",
            "ldp x0, x1, [x2]",
            "prfm pldl1keep, [x0]",
            "stgp x0, x1, [x2]",
            "casp x0, x1, x2, x3, [x4]",
            "ldaddal x0, x1, [x2]",
        ]
        for text in inScope {
            #expect(!Self.isDeferredOos(text), "expected in-scope: `\(text)`")
        }
    }
}
