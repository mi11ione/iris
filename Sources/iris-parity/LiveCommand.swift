// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// `iris-parity live` — seeded random sweep per encoding partition,
// diffed against a LIVE llvm-mc at the family's maximal mattr.
//
// Comparison convention (the documented undefined mapping): llvm-mc's
// "invalid instruction encoding" reject ↔ Iris UNDEFINED. The compared
// Iris side is `isUndefined ? "" : text`; the oracle side is "" for a
// reject and the normalized disassembly line otherwise. Divergences are
// classified against KNOWN-DEVIATIONS.md; unclassified rows gate.

import Foundation
@_spi(Validation) import Iris

func runLiveCommand(_ args: [String]) -> Int32 {
    var familyName: String?
    var count = 65536
    var seed: UInt64 = 0xC_0FFE_E001_5BAD
    var llvmMCOverride: String?
    var chunkSize = 65536
    var index = 0
    while index < args.count {
        switch args[index] {
        case "--family":
            index += 1
            familyName = args.indices.contains(index) ? args[index] : nil
        case "--count":
            index += 1
            count = parseDecimalOption("--count", in: args, at: index, for: "live")
        case "--seed":
            index += 1
            seed = parseSeedOption("--seed", in: args, at: index, for: "live")
        case "--llvm-mc":
            index += 1
            llvmMCOverride = args.indices.contains(index) ? args[index] : nil
        case "--chunk":
            index += 1
            chunkSize = parseDecimalOption("--chunk", in: args, at: index, for: "live", minimum: 1)
        default:
            eprint("live: unknown option \(args[index])")
            return 2
        }
        index += 1
    }
    guard let familyName else {
        eprint("live: pass --family <name|all>")
        return 2
    }
    let families = familyName == "all"
        ? ParityFamily.all
        : ParityFamily.named(familyName).map { [$0] } ?? []
    guard !families.isEmpty else {
        eprint("live: unknown family `\(familyName)` (families: \(ParityFamily.all.map(\.name).joined(separator: ", ")), or `all`)")
        return 2
    }
    guard let llvmMC = llvmMCOverride ?? LLVMMC.locate() else {
        eprint("live: llvm-mc not found (set IRIS_LLVM_MC, install via brew/apt, or pass --llvm-mc)")
        return 2
    }
    print("[live] oracle: \(llvmMC) (\(LLVMMC.version(llvmMC)))")

    let catalogue = DeviationCatalogue.load()
    var exitCode: Int32 = 0
    for family in families {
        guard let gating = sweepFamily(
            family, llvmMC: llvmMC, count: count, seed: seed,
            chunkSize: chunkSize, catalogue: catalogue,
        ) else {
            return 2
        }
        if gating > 0 { exitCode = 1 }
    }
    return exitCode
}

/// Sweep one family: generate the seeded words grouped by the live
/// mattr each generation tier requires (crypto/PAC/MTE/AMX tiers carry
/// their HOST partition's maximal mattr — see `GenerationTier.mattr`),
/// then diff each group against llvm-mc at that group's mattr. Returns
/// the gating divergence count, or nil on oracle failure (feature-blind
/// oracle, launch failure, or timeout — setup errors, never scored).
private func sweepFamily(
    _ family: ParityFamily, llvmMC: String, count: Int, seed: UInt64,
    chunkSize: Int, catalogue: DeviationCatalogue,
) -> Int? {
    let started = Date()
    let groups = family.generateWordGroups(count: count, seed: seed)

    // Fail loud on a feature-blind oracle: llvm-mc only WARNS on an
    // unknown -mattr feature and proceeds without it, silently
    // shrinking the oracle's decode surface (the harvest-era lesson).
    for group in groups {
        let missing = LLVMMC.unrecognizedFeatures(llvmMC, mattr: group.mattr)
        guard missing.isEmpty else {
            eprint("live: \(family.name): this llvm-mc does not recognize \(missing.joined(separator: ", ")) — the oracle cannot represent the family's feature set; install a newer LLVM")
            return nil
        }
    }

    var agreeing = 0
    var oracleDecodes = 0
    var catalogued: [String: Int] = [:]
    var gatingSamples: [String] = []
    var gating = 0

    print("[live] \(family.name): words=\(grouped(groups.reduce(0) { $0 + $1.words.count })) seed=\(seed) mattr-groups=\(groups.count)")
    for group in groups {
        print("[live] \(family.name):   mattr=\(group.mattr) words=\(grouped(group.words.count))")
        var start = 0
        while start < group.words.count {
            let chunk = Array(group.words[start ..< min(start + chunkSize, group.words.count)])
            guard let oracle = LLVMMC.disassemble(chunk, llvmMC: llvmMC, mattr: group.mattr) else {
                eprint("live: \(family.name): aborted — llvm-mc oracle failure (see error above); nothing was scored as a divergence")
                return nil
            }
            for (word, oracleText) in zip(chunk, oracle) {
                let instruction = decode(word, at: 0, features: family.features)
                let irisText = instruction.isUndefined ? "" : instruction.text
                if !oracleText.isEmpty { oracleDecodes += 1 }
                if irisText == oracleText {
                    agreeing += 1
                    continue
                }
                if let entry = catalogue.classify(instruction: instruction, oracleText: oracleText) {
                    catalogued[entry.id, default: 0] += 1
                    continue
                }
                gating += 1
                if gatingSamples.count < 10 {
                    gatingSamples.append("  DIV \(hex32(word)): iris=`\(irisText.isEmpty ? "<undefined>" : irisText)` llvm-mc=`\(oracleText.isEmpty ? "<invalid>" : oracleText)`")
                }
            }
            start += chunkSize
        }
    }

    let catalogueNote = catalogued.isEmpty
        ? ""
        : " catalogued={" + catalogued.sorted { $0.key < $1.key }
        .map { "\($0.key):\(grouped($0.value))" }.joined(separator: ", ") + "}"
    print("[live] \(family.name): agree=\(grouped(agreeing)) oracle-decodes=\(grouped(oracleDecodes))\(catalogueNote) TRUE-DIVERGENCES=\(grouped(gating)) [\(secondsText(Date().timeIntervalSince(started)))]")
    for sample in gatingSamples {
        print(sample)
    }
    if gating > 10 {
        print("  ... and \(grouped(gating - 10)) more")
    }
    return gating
}
