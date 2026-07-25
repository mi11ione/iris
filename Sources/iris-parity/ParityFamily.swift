// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// The per-family parity registry: encoding partitions, the MAXIMAL
// llvm-mc -mattr per family, decode features, fixture resolution, word
// generation, and semantic-checker routing.
//
// The mattr table is the oracle contract. Each entry is the maximal
// feature set the family decoder was proven against (zero-divergence
// exhaustive op0-partition sweeps in the parent project, llvm-mc
// 22.1.4) — NOT the harvest-era TSV mattr, which for some corpora is
// narrower (the real_text TSV headers record what their expected-text
// column was captured with; `tsv --reanchor` resolves the gap live).
// DPI runs at the maximal mattr: the family decoder covers the CSSC
// immediate forms (SMAX/SMIN/UMAX/UMIN #imm, via MinMaxImmDecode) and the
// MTE ADDG/SUBG words in its op1=0b011 row, so the oracle can carry the
// full feature set with no blind spot. The scalable tiers carry no decode
// feature at all (op0=2 SVE and the op0=0 bit31=1 SME region always
// decode), so every family whose partitions reach them — the dedicated
// `sve`/`sme` families and the `reserved` slab that shares op0=0 — runs
// its oracle at the maximal scalable mattr.

import Foundation
import Iris
import IrisValidation

/// One word-generation template: `fixed` bits plus a random fill of
/// `freeMask` bits. Tiers whose discriminant is not a pure op0 slab
/// (crypto / PAC / MTE / AMX) enumerate their row shapes this way.
///
/// `mattr` overrides the family mattr for the live oracle on this
/// tier's words. The crypto/PAC/MTE tiers live INSIDE other families'
/// op0 partitions, and a random fill of a tier's free bits legitimately
/// strays onto neighboring rows of the host partition (a word next to
/// MTE SUBP is CRC32/CSSC territory) — so the live oracle must carry
/// the host partition's maximal feature set: maximal mattr per
/// encoding PARTITION, the oracle contract.
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
    /// Maximal llvm-mc -mattr (see the table note above).
    let mattr: String
    /// Decode features. Only the LDRAA/LDRAB tier is feature-gated, but
    /// each family mirrors the parent validator's CPU-subtype choice.
    let features: Features
    /// In-repo synthetic fixture name under Tests/Fixtures/Decode, or
    /// nil when the family has no tracked synthetic corpus.
    let syntheticFixture: String?
    /// Word-generation tiers for the live/semantic sweeps.
    let generationTiers: [GenerationTier]

    /// Per-family maximal mattr strings (the oracle contract — see the
    /// header note). Named so the crypto-apple tiers can reference their
    /// HOST partition's mattr without duplication.
    static let dpiMattr = scalableMattr
    static let besMattr = "+v9.6a,+sme,+sme2,+nmi,+gcs,+chk,+clrbhb,+hbc,+the,+d128,+ite,+tlbiw,"
        + "+predres,+specres2,+ssbs,+mte,+xs,+spe,+wfxt,+pauth,+flagm,+cssc,+sve"
    static let lsMattr = besMattr + ",+lse,+lor,+rcpc,+rcpc-immo,+rcpc3,+mops,+ls64,+lse128"
    static let dprMattr = besMattr
    static let simdFPMattr = "+v9.6a,+fullfp16,+bf16,+i8mm,+fp8,+fp8fma,+fp8dot2,+fp8dot4,+faminmax,"
        + "+lut,+sve,+sve2,+aes,+sha2,+sha3,+sm4,+ssbs,+mte,+xs,+spe,+pauth"
    static let cryptoAppleMattr = "+aes,+sha2,+sha3,+sm4,+pauth,+mte"
    static let reservedMattr = "+v9.6a,+nmi,+gcs,+chk,+clrbhb,+hbc,+the,+d128,+ite,+tlbiw,+predres,"
        + "+specres2,+ssbs,+mte,+xs,+spe,+wfxt,+pauth,+flagm,+cssc,+lse,+lor,"
        + "+rcpc,+rcpc-immo,+rcpc3,+mops,+ls64,+lse128,+fullfp16,+bf16,+i8mm,"
        + "+aes,+sha2,+sha3,+sm4"
    /// The maximal Apple-ISA decode mattr INCLUDING SVE/SME — Aperture's
    /// single-source-of-truth oracle contract (`appleMaximalDecodeMattr`),
    /// copied verbatim (every SVE/SME/f8 feature llvm-mc 22.1.4 accepts), so
    /// the oracle can never scope below a decoded scalable feature.
    static let scalableMattr = "+v9.6a,+nmi,+gcs,+chk,+clrbhb,+hbc,+the,+d128,+ite,+tlbiw,+predres,+specres2,"
        + "+ssbs,+mte,+xs,+spe,+wfxt,+pauth,+flagm,+cssc,+lse,+lor,+rcpc,+rcpc-immo,"
        + "+rcpc3,+mops,+ls64,+lse128,+fullfp16,+bf16,+i8mm,+aes,+sha2,+sha3,+sm4,"
        + "+sve,+sve2,+sme,+sme2,+sme-i16i64,+sme-f64f64,"
        + "+faminmax,+lut,+fp8,+fp8fma,+fp8dot2,+fp8dot4,+f8f16mm,+f8f32mm,+cpa,"
        + "+sve2p1,+sve2p2,+sve2p3,+sve-aes,+sve-aes2,+sve2-aes,+sve-bitperm,"
        + "+sve2-bitperm,+sve-sha3,+sve2-sha3,+sve-sm4,+sve2-sm4,+sve-b16b16,"
        + "+sve-b16mm,+sve-bfscale,+sve-f16f32mm,+sme2p1,+sme2p2,+sme2p3,"
        + "+sme-b16b16,+sme-f16f16,+sme-f8f16,+sme-f8f32,+sme-fa64,+sme-lutv2,"
        + "+sme-mop4,+sme-tmop,+ssve-aes,+ssve-bitperm,+ssve-fexpa,"
        + "+ssve-fp8dot2,+ssve-fp8dot4,+ssve-fp8fma,"
        + "+f16mm,+f32mm,+f64mm"

    /// All registered families, keyed by `--family` name.
    static let all: [ParityFamily] = [
        ParityFamily(
            name: "dpi",
            op0Partitions: [0x8, 0x9],
            mattr: dpiMattr,
            features: [],
            syntheticFixture: "synthetic-dpi.tsv",
            generationTiers: op0Tiers([0x8, 0x9]),
        ),
        ParityFamily(
            name: "bes",
            op0Partitions: [0xA, 0xB],
            mattr: besMattr,
            features: .arm64e,
            syntheticFixture: "synthetic-bes.tsv",
            generationTiers: op0Tiers([0xA, 0xB]),
        ),
        ParityFamily(
            name: "ls",
            op0Partitions: [0x4, 0x6, 0xC, 0xE],
            mattr: lsMattr,
            features: .arm64e,
            syntheticFixture: "synthetic-ls.tsv",
            generationTiers: op0Tiers([0x4, 0x6, 0xC, 0xE]),
        ),
        ParityFamily(
            name: "dpr",
            op0Partitions: [0x5, 0xD],
            mattr: dprMattr,
            features: [],
            syntheticFixture: "synthetic-dpr.tsv",
            generationTiers: op0Tiers([0x5, 0xD]),
        ),
        ParityFamily(
            name: "simd-fp",
            op0Partitions: [0x7, 0xF],
            mattr: simdFPMattr,
            features: [],
            syntheticFixture: nil,
            generationTiers: op0Tiers([0x7, 0xF]),
        ),
        ParityFamily(
            name: "crypto-apple",
            op0Partitions: [],
            // The family mattr is the synthetic corpus's harvest/reanchor
            // contract; each LIVE tier overrides it with its host
            // partition's maximal mattr (see `GenerationTier.mattr`).
            mattr: cryptoAppleMattr,
            features: .arm64e,
            syntheticFixture: "synthetic-crypto-apple.tsv",
            // Tier templates derived from the IrisValidation partition pre-filter
            // masks (CryptoAppleExtensionsCommon). Each free mask is the
            // complement of the predicate's fixed-bit mask, so the sweep
            // hits in-row valid words AND the row's reserved arms.
            generationTiers: [
                GenerationTier(fixed: 0x4E28_0800, freeMask: 0x0000_F3FF, mattr: simdFPMattr), // AES
                GenerationTier(fixed: 0x5E00_0000, freeMask: 0x001F_73FF, mattr: simdFPMattr), // SHA1/256 3-reg
                GenerationTier(fixed: 0x5E28_0800, freeMask: 0x0000_F3FF, mattr: simdFPMattr), // SHA1/256 2-reg
                GenerationTier(fixed: 0xCE00_0000, freeMask: 0x00FF_FFFF, mattr: simdFPMattr), // SHA3/512/SM3/SM4
                GenerationTier(fixed: 0xDAC1_0000, freeMask: 0x0000_FFFF, mattr: dprMattr), // PAC one-source
                GenerationTier(fixed: 0x9AC0_3000, freeMask: 0x001F_03FF, mattr: dprMattr), // PACGA
                GenerationTier(fixed: 0x9180_0000, freeMask: 0x607F_FFFF, mattr: dpiMattr), // MTE ADDG/SUBG
                GenerationTier(fixed: 0x9AC0_0000, freeMask: 0x201F_FFFF, mattr: dprMattr), // MTE DPR
                GenerationTier(fixed: 0xD920_0000, freeMask: 0x00DF_FFFF, mattr: lsMattr), // MTE L/S
                GenerationTier(fixed: 0x0020_1000, freeMask: 0x0000_03FF, mattr: reservedMattr), // AMX
            ],
        ),
        ParityFamily(
            name: "reserved",
            op0Partitions: [0x0, 0x1, 0x3],
            // op0=1,3 are architecturally unallocated and decode UNDEFINED on
            // both sides. op0=0 is shared: its bit31=1 half is the SME region,
            // which iris decodes unconditionally, so the oracle must carry the
            // scalable mattr here too or every SME word this slab reaches would
            // read as a divergence. The `sve`/`sme` families own those tiers
            // deliberately; this one only has to agree where they overlap.
            mattr: scalableMattr,
            features: .arm64e,
            syntheticFixture: nil,
            // op0 slabs plus focused UDF (bits[31:16] == 0) and AMX
            // tiers — both far too sparse for uniform sampling to reach.
            generationTiers: op0Tiers([0x0, 0x1, 0x3]) + [
                GenerationTier(fixed: 0x0000_0000, freeMask: 0x0000_FFFF), // UDF
                GenerationTier(fixed: 0x0020_1000, freeMask: 0x0000_03FF), // AMX
            ],
        ),
        ParityFamily(
            name: "sve",
            op0Partitions: [],
            mattr: scalableMattr,
            features: [],
            syntheticFixture: "synthetic-sve.tsv",
            // The whole op0=0b0010 SVE / SVE2 tier (bit31=1 is the memory
            // region). No decode feature gates it; the oracle carries the
            // maximal scalable mattr.
            generationTiers: op0Tiers([0x2]),
        ),
        ParityFamily(
            name: "sme",
            op0Partitions: [],
            mattr: scalableMattr,
            features: [],
            syntheticFixture: "synthetic-sme.tsv",
            // SME lives at op0=0 with bit31=1 (disjoint from AMX's magic mask
            // and UDF's bits[31:16]==0). Target it directly — an op0=0 slab
            // sweep would spend nearly every word on holes.
            generationTiers: [GenerationTier(fixed: 0x8000_0000, freeMask: 0x61FF_FFFF)],
        ),
    ]

    static func named(_ name: String) -> ParityFamily? {
        all.first { $0.name == name }
    }

    /// Build uniform-random tiers over op0 slabs: bits[28:25] forced,
    /// the remaining 28 bits free.
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

    /// Generate `count` seeded words grouped by the live-oracle mattr
    /// each tier requires (tier override, else the family mattr). Same
    /// generator discipline as `generateWords`, so a given (count,
    /// seed) produces the same word multiset. Group order is
    /// first-appearance — deterministic.
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

    /// Resolve TSV inputs for this family. In-repo fixture by default;
    /// an external corpus tree (`decode-<family>/{synthetic.tsv,
    /// real_text.tsv}`, the parent project's `Corpus/` layout) when
    /// `IRIS_DECODE_CORPUS` is set. `real_amx.tsv` is deliberately not
    /// consumed: its expected column is a `.long` sentinel (no llvm-mc
    /// AMX support), validated structurally in the parent project.
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

/// Route a decoded record to its family's `IrisValidation` semantic
/// checker by category attribution (each record self-identifies; PAC /
/// MTE / crypto / AMX records carry their own categories regardless of
/// which op0 slab routed them). Returns nil for clean or undefined
/// records.
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
