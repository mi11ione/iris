// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// The `stats` verb's instruction census: per-mnemonic and per-category
/// counts, extension-site counts (PAC / MTE / AMX / crypto), and word
/// totals, accumulated streamingly and rendered as a table or one JSON
/// object.
@frozen
public struct Census: Sendable {
    /// Count per mnemonic name (sentinel records excluded, they are
    /// counted in the totals, not the mnemonic census).
    public private(set) var mnemonicCounts: [String: Int] = [:]
    /// Count per category name, sentinels included.
    public private(set) var categoryCounts: [String: Int] = [:]
    /// Instructions whose mnemonic involves pointer authentication.
    public private(set) var pointerAuthenticationSites = 0
    /// Instructions in the MTE category.
    public private(set) var memoryTaggingSites = 0
    /// Instructions in the AMX category.
    public private(set) var amxSites = 0
    /// Instructions in the crypto category.
    public private(set) var cryptoSites = 0
    /// All records seen (words + a truncated tail if present).
    public private(set) var totalWords = 0
    /// UNDEFINED records.
    public private(set) var undefinedWords = 0
    /// Data-in-code marker records.
    public private(set) var dataWords = 0
    /// Truncated-tail records (0 or 1 per stream).
    public private(set) var truncatedTails = 0

    public init() {}

    /// Accumulate one instruction.
    public mutating func add(_ instruction: Instruction) {
        totalWords += 1
        categoryCounts[JSONText.categoryName(instruction.category), default: 0] += 1
        switch instruction.category {
        case .undefined:
            undefinedWords += 1
        case .dataInCodeMarker:
            dataWords += 1
        case .truncatedTail:
            truncatedTails += 1
        default:
            mnemonicCounts[instruction.mnemonic.name, default: 0] += 1
            if instruction.usesPointerAuthentication { pointerAuthenticationSites += 1 }
            if instruction.category == .memoryTagging { memoryTaggingSites += 1 }
            if instruction.category == .amx { amxSites += 1 }
            if instruction.category == .crypto { cryptoSites += 1 }
        }
    }

    /// Accumulate a whole stream.
    public mutating func add(_ stream: InstructionStream) {
        for instruction in stream {
            add(instruction)
        }
    }

    /// The table rendering: totals, extension sites, per-category and
    /// per-mnemonic counts (descending count, then name).
    public func tableLines() -> [String] {
        var lines: [String] = []
        lines.append("total words        \(totalWords)")
        lines.append("undefined          \(undefinedWords)")
        lines.append("data-in-code       \(dataWords)")
        if truncatedTails > 0 {
            lines.append("truncated tails    \(truncatedTails)")
        }
        lines.append("")
        lines.append("extension sites:")
        lines.append("  pointer-auth     \(pointerAuthenticationSites)")
        lines.append("  memory-tagging   \(memoryTaggingSites)")
        lines.append("  amx              \(amxSites)")
        lines.append("  crypto           \(cryptoSites)")
        lines.append("")
        lines.append("categories:")
        for (name, count) in sortedByCount(categoryCounts) {
            lines.append("  " + pad(name, to: 26) + "\(count)")
        }
        lines.append("")
        lines.append("mnemonics:")
        for (name, count) in sortedByCount(mnemonicCounts) {
            lines.append("  " + pad(name, to: 26) + "\(count)")
        }
        return lines
    }

    /// The `stats --json` rendering: one JSON object (`kind` is `census`),
    /// map keys sorted by name for byte-stable output.
    public func jsonObject() -> String {
        var fields: [String] = []
        fields.append("\"schemaVersion\":\(JSONText.schemaVersion)")
        fields.append("\"kind\":\"census\"")
        fields.append("\"totalWords\":\(totalWords)")
        fields.append("\"undefinedWords\":\(undefinedWords)")
        fields.append("\"dataWords\":\(dataWords)")
        fields.append("\"truncatedTails\":\(truncatedTails)")
        fields.append(
            "\"extensions\":{\"pointerAuthentication\":\(pointerAuthenticationSites),"
                + "\"memoryTagging\":\(memoryTaggingSites),"
                + "\"amx\":\(amxSites),"
                + "\"crypto\":\(cryptoSites)}",
        )
        fields.append("\"categories\":" + sortedObject(categoryCounts))
        fields.append("\"mnemonics\":" + sortedObject(mnemonicCounts))
        return "{" + fields.joined(separator: ",") + "}"
    }

    /// The `stats --json --slim` rendering: the census object with the two
    /// constant fields (`schemaVersion`, `kind`) dropped, matching the
    /// instruction-stream slim. Every count stays (a zero count is signal:
    /// it is exactly what a CI gate like `pointerAuthentication > 0`
    /// reads), so the census slims only by those two keys.
    public func slimJsonObject() -> String {
        var fields: [String] = []
        fields.append("\"totalWords\":\(totalWords)")
        fields.append("\"undefinedWords\":\(undefinedWords)")
        fields.append("\"dataWords\":\(dataWords)")
        fields.append("\"truncatedTails\":\(truncatedTails)")
        fields.append(
            "\"extensions\":{\"pointerAuthentication\":\(pointerAuthenticationSites),"
                + "\"memoryTagging\":\(memoryTaggingSites),"
                + "\"amx\":\(amxSites),"
                + "\"crypto\":\(cryptoSites)}",
        )
        fields.append("\"categories\":" + sortedObject(categoryCounts))
        fields.append("\"mnemonics\":" + sortedObject(mnemonicCounts))
        return "{" + fields.joined(separator: ",") + "}"
    }

    /// `(name, count)` pairs ordered by descending count, ties by name.
    func sortedByCount(_ counts: [String: Int]) -> [(String, Int)] {
        counts.sorted { lhs, rhs in
            if lhs.value != rhs.value { return lhs.value > rhs.value }
            return lhs.key < rhs.key
        }
    }

    /// JSON object literal with name-sorted keys.
    func sortedObject(_ counts: [String: Int]) -> String {
        let body = counts.sorted { $0.key < $1.key }
            .map { "\(JSONText.string($0.key)):\($0.value)" }
            .joined(separator: ",")
        return "{" + body + "}"
    }

    /// Right-pad `name` with spaces to `width` (one space minimum).
    func pad(_ name: String, to width: Int) -> String {
        name + String(repeating: " ", count: max(width - name.count, 1))
    }
}
