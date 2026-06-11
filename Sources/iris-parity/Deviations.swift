// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Known-deviations catalogue: KNOWN-DEVIATIONS.md at the repository
// root is both human documentation and the machine-readable
// classification table the parity subcommands consult. A divergence matching a catalogue entry
// is reported under the entry's id and does not gate; everything else
// gates. Two statuses exist — `expected` (a by-design oracle gap, e.g.
// AMX) and `open-defect` (a recorded library bug awaiting a fix leg);
// both are non-gating but defects are reported loudly so they cannot
// fade into the background.

import Foundation
@_spi(Validation) import Iris

/// Which parity instrument an entry classifies for: text-parity
/// divergences (`tsv`/`live`) or semantic-checker issues (`semantic`).
/// A text deviation and a semantic deviation are different claims, so
/// an entry never crosses instruments — `check=semantic` opts in, the
/// default is text.
enum DeviationCheck: String, Sendable {
    case text
    case semantic
}

struct DeviationEntry: Sendable {
    let id: String
    let status: String
    let check: DeviationCheck
    let constraints: [(key: String, value: String)]

    /// Match one divergence. Constraint keys:
    /// `iris.category=<name>` · `iris.mnemonic=<name>` ·
    /// `oracle=invalid` · `oracle.prefix=<token>` ·
    /// `encoding.mask=0xM:0xV` (encoding & M == V) ·
    /// `field=<name>` (the semantic checker's issue field; text
    /// divergences carry no field, so the clause never matches them).
    /// All must hold. (`check=` is instrument routing, consumed at
    /// load, not a per-divergence constraint.)
    func matches(instruction: Instruction, oracleText: String, field: String? = nil) -> Bool {
        for constraint in constraints {
            switch constraint.key {
            case "iris.category":
                if constraint.value != "\(instruction.category)" { return false }
            case "iris.mnemonic":
                if instruction.mnemonic.name != constraint.value { return false }
            case "oracle":
                if constraint.value == "invalid", !oracleText.isEmpty { return false }
            case "oracle.prefix":
                if !oracleText.hasPrefix(constraint.value) { return false }
            case "encoding.mask":
                let parts = constraint.value.split(separator: ":")
                guard parts.count == 2,
                      let mask = UInt32(parts[0].dropFirst(2), radix: 16),
                      let value = UInt32(parts[1].dropFirst(2), radix: 16),
                      instruction.encoding & mask == value
                else { return false }
            case "field":
                if field != constraint.value { return false }
            default:
                return false
            }
        }
        return !constraints.isEmpty
    }
}

struct DeviationCatalogue: Sendable {
    let entries: [DeviationEntry]
    let path: String

    /// Load `KNOWN-DEVIATIONS.md`, parsing rows of the entry table:
    /// `| id | status | matcher | ... |` where matcher is a
    /// backtick-quoted `;`-separated `key=value` list. A missing file
    /// yields an empty catalogue (every divergence gates).
    static func load() -> DeviationCatalogue {
        let path = repositoryRoot().appendingPathComponent("KNOWN-DEVIATIONS.md").path
        guard let contents = try? String(contentsOfFile: path, encoding: .utf8) else {
            return DeviationCatalogue(entries: [], path: path)
        }
        var entries: [DeviationEntry] = []
        for raw in contents.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard line.hasPrefix("|") else { continue }
            let cells = line.split(separator: "|").map { $0.trimmingCharacters(in: .whitespaces) }
            guard cells.count >= 3 else { continue }
            let id = cells[0].trimmingCharacters(in: CharacterSet(charactersIn: "`"))
            let status = cells[1]
            guard status == "expected" || status == "open-defect" else { continue }
            let matcherCell = cells[2].trimmingCharacters(in: CharacterSet(charactersIn: "`"))
            var check = DeviationCheck.text
            var constraints: [(String, String)] = []
            for clause in matcherCell.split(separator: ";") {
                let pair = clause.split(separator: "=", maxSplits: 1).map {
                    $0.trimmingCharacters(in: .whitespaces)
                }
                if pair.count == 2 {
                    if pair[0] == "check" {
                        check = DeviationCheck(rawValue: pair[1]) ?? .text
                    } else {
                        constraints.append((pair[0], pair[1]))
                    }
                } else if pair.count == 1, pair[0] == "oracle" {
                    constraints.append(("oracle", "invalid"))
                }
            }
            if !constraints.isEmpty {
                entries.append(DeviationEntry(id: id, status: status, check: check, constraints: constraints))
            }
        }
        return DeviationCatalogue(entries: entries, path: path)
    }

    /// The first matching entry for a divergence, or nil (gating).
    /// `check` routes by instrument: `tsv`/`live` classify text
    /// divergences, `semantic` classifies checker issues (with no
    /// oracle text — semantic entries must not carry oracle clauses —
    /// and the issue's `field`, so a `field=` entry catalogues exactly
    /// the recorded defect, not every future issue on the mnemonic).
    func classify(
        instruction: Instruction, oracleText: String, check: DeviationCheck = .text,
        field: String? = nil,
    ) -> DeviationEntry? {
        entries.first { $0.check == check && $0.matches(instruction: instruction, oracleText: oracleText, field: field) }
    }
}
