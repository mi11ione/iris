// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
import Iris
import IrisValidation

/// One word-generation template.
struct GenerationTier: Sendable {
    let fixed: UInt32
    let freeMask: UInt32
    var mattr: String?

    func word(_ generator: inout SplitMix64) -> UInt32 {
        fixed | (generator.nextWord() & freeMask)
    }
}

struct ParityFamily: Sendable {
    let name: String
    /// op0 (bits[28:25]) partitions the family owns; empty for
    /// mask-discriminated families (crypto-apple).
    let op0Partitions: [UInt8]
    /// Maximal llvm-mc -mattr (see ``maximalMattr``).
    let mattr: String
    /// Decode features. Only the LDRAA/LDRAB tier is feature-gated, but each
    /// family mirrors the parent validator's CPU-subtype choice.
    let features: Features
    /// In-repo synthetic fixture name under Tests/Fixtures/Decode, or nil when
    /// the family has no tracked synthetic corpus.
    let syntheticFixture: String?
    /// Word-generation tiers for the live/semantic sweeps.
    let generationTiers: [GenerationTier]

    /// The maximal oracle mattr, shared by every family.
    ///
    /// `+all` turns on every llvm-mc *feature* but leaves the
    /// architecture-*version* predicates clear, and some alias printing is
    /// gated on those: at bare `+all` llvm-mc renders `0x331c13e0` as
    /// `bfi w0, wzr, #4, #5`, and only with `+v9.6a` does it render the
    /// ARM-ARM-preferred `bfc w0, #4, #5` that iris emits. `+all,+v9.7a`
    /// decodes identically to `+all,+v9.6a` over 400,000 random words, so
    /// `+all,+v9.6a` is the strongest oracle this llvm-mc offers and every
    /// family is held to it. A per-family mattr can only hide instructions
    /// the family's own partitions contain, which is how whole missing
    /// instruction families used to read as agreement.
    static let maximalMattr = "+all,+v9.6a"

    /// All registered families, keyed by `--family` name.
    static let all: [ParityFamily] = [
        ParityFamily(
            name: "dpi",
            op0Partitions: [0x8, 0x9],
            mattr: maximalMattr,
            features: [],
            syntheticFixture: "synthetic-dpi.tsv",
            generationTiers: op0Tiers([0x8, 0x9]),
        ),
        ParityFamily(
            name: "bes",
            op0Partitions: [0xA, 0xB],
            mattr: maximalMattr,
            features: .arm64e,
            syntheticFixture: "synthetic-bes.tsv",
            generationTiers: op0Tiers([0xA, 0xB]),
        ),
        ParityFamily(
            name: "ls",
            op0Partitions: [0x4, 0x6, 0xC, 0xE],
            mattr: maximalMattr,
            features: .arm64e,
            syntheticFixture: "synthetic-ls.tsv",
            generationTiers: op0Tiers([0x4, 0x6, 0xC, 0xE]),
        ),
        ParityFamily(
            name: "dpr",
            op0Partitions: [0x5, 0xD],
            mattr: maximalMattr,
            features: [],
            syntheticFixture: "synthetic-dpr.tsv",
            generationTiers: op0Tiers([0x5, 0xD]),
        ),
        ParityFamily(
            name: "simd-fp",
            op0Partitions: [0x7, 0xF],
            mattr: maximalMattr,
            features: [],
            syntheticFixture: "synthetic-simd-fp.tsv",
            generationTiers: op0Tiers([0x7, 0xF]),
        ),
        ParityFamily(
            name: "crypto-apple",
            op0Partitions: [],
            mattr: maximalMattr,
            features: .arm64e,
            syntheticFixture: "synthetic-crypto-apple.tsv",
            generationTiers: [
                GenerationTier(fixed: 0x4E28_0800, freeMask: 0x0000_F3FF),
                GenerationTier(fixed: 0x5E00_0000, freeMask: 0x001F_73FF),
                GenerationTier(fixed: 0x5E28_0800, freeMask: 0x0000_F3FF),
                GenerationTier(fixed: 0xCE00_0000, freeMask: 0x00FF_FFFF),
                GenerationTier(fixed: 0xDAC1_0000, freeMask: 0x0000_FFFF),
                GenerationTier(fixed: 0x9AC0_3000, freeMask: 0x001F_03FF),
                GenerationTier(fixed: 0x9180_0000, freeMask: 0x607F_FFFF),
                GenerationTier(fixed: 0x9AC0_0000, freeMask: 0x201F_FFFF),
                GenerationTier(fixed: 0xD920_0000, freeMask: 0x00DF_FFFF),
                GenerationTier(fixed: 0x0020_1000, freeMask: 0x0000_03FF),
            ],
        ),
        ParityFamily(
            name: "reserved",
            op0Partitions: [0x0, 0x1, 0x3],
            mattr: maximalMattr,
            features: .arm64e,
            syntheticFixture: "synthetic-reserved.tsv",
            generationTiers: op0Tiers([0x0, 0x1, 0x3]) + [
                GenerationTier(fixed: 0x0000_0000, freeMask: 0x0000_FFFF),
                GenerationTier(fixed: 0x0020_1000, freeMask: 0x0000_03FF),
            ],
        ),
        ParityFamily(
            name: "sve",
            op0Partitions: [],
            mattr: maximalMattr,
            features: [],
            syntheticFixture: "synthetic-sve.tsv",
            generationTiers: op0Tiers([0x2]),
        ),
        ParityFamily(
            name: "sme",
            op0Partitions: [],
            mattr: maximalMattr,
            features: [],
            syntheticFixture: "synthetic-sme.tsv",
            generationTiers: [GenerationTier(fixed: 0x8000_0000, freeMask: 0x61FF_FFFF)],
        ),
    ]

    static func named(_ name: String) -> ParityFamily? {
        all.first { $0.name == name }
    }

    /// Build uniform-random tiers over op0 slabs.
    private static func op0Tiers(_ op0s: [UInt8]) -> [GenerationTier] {
        op0s.map { op0 in
            GenerationTier(fixed: UInt32(op0) << 25, freeMask: ~(UInt32(0xF) << 25))
        }
    }

    /// Generate `count` seeded words, cycling the family's tiers.
    func generateWords(count: Int, seed: UInt64) -> [UInt32] {
        var generator = SplitMix64(seed: seed)
        var words: [UInt32] = []
        words.reserveCapacity(count)
        for index in 0 ..< count {
            words.append(generationTiers[index % generationTiers.count].word(&generator))
        }
        return words
    }

    /// Generate `count` seeded words grouped by the live-oracle mattr each
    /// tier requires (tier override, else the family mattr).
    func generateWordGroups(count: Int, seed: UInt64) -> [(mattr: String, words: [UInt32])] {
        var generator = SplitMix64(seed: seed)
        var order: [String] = []
        var groups: [String: [UInt32]] = [:]
        for index in 0 ..< count {
            let tier = generationTiers[index % generationTiers.count]
            let mattr = tier.mattr ?? mattr
            if groups[mattr] == nil { order.append(mattr) }
            groups[mattr, default: []].append(tier.word(&generator))
        }
        return order.map { ($0, groups[$0] ?? []) }
    }

    /// Resolve TSV inputs for this family.
    func resolveTSVPaths() -> [String] {
        let fm = FileManager.default
        if let external = ProcessInfo.processInfo.environment["IRIS_DECODE_CORPUS"] {
            let base = URL(fileURLWithPath: external).appendingPathComponent("decode-\(name)")
            return ["synthetic.tsv", "real_text.tsv"]
                .map { base.appendingPathComponent($0).path }
                .filter { fm.fileExists(atPath: $0) }
        }
        guard let fixture = syntheticFixture else { return [] }
        let path = repositoryRoot()
            .appendingPathComponent("Tests/Fixtures/Decode")
            .appendingPathComponent(fixture).path
        return fm.fileExists(atPath: path) ? [path] : []
    }

    /// Infer the family owning `path` from its corpus-layout directory
    /// (`decode-<family>/`) or in-repo fixture name
    /// (`synthetic-<family>.tsv`).
    static func inferred(fromPath path: String) -> ParityFamily? {
        for family in all {
            if path.contains("decode-\(family.name)/") { return family }
            if let fixture = family.syntheticFixture, path.hasSuffix(fixture) { return family }
        }
        return nil
    }
}

/// Route a decoded record to its family's `IrisValidation` semantic checker by
/// category attribution (each record self-identifies; PAC / MTE / crypto / AMX
/// records carry their own categories regardless of which op0 slab routed
/// them).
func semanticIssue(for instruction: Instruction) -> (field: String, actual: String, expected: String)? {
    switch instruction.category {
    case .dataProcessingImmediate:
        DPISemanticChecker.verify(instruction).map { ($0.field, $0.actual, $0.expected) }
    case .branchesExceptionSystem:
        BESSemanticChecker.verify(instruction).map { ($0.field, $0.actual, $0.expected) }
    case .dataProcessingRegister:
        DPRSemanticChecker.verify(instruction).map { ($0.field, $0.actual, $0.expected) }
    case .loadsAndStores:
        LSSemanticChecker.verify(instruction).map { ($0.field, $0.actual, $0.expected) }
    case .simdAndFP:
        SIMDFPSemanticChecker.verify(instruction).map { ($0.field, $0.actual, $0.expected) }
    case .pointerAuthentication, .crypto, .amx, .memoryTagging:
        CryptoAppleExtensionsSemanticChecker.verify(instruction).map { ($0.field, $0.actual, $0.expected) }
    case .sve, .sme:
        scalableSemanticIssue(for: instruction)
    case .undefined, .dataInCodeMarker, .truncatedTail:
        nil
    }
}
