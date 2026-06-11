// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// `iris-parity semantic` — run the `@_spi(Validation)` semantic
// checkers (the per-family expected-attribute tables) over a word set:
// every row of the family's synthetic TSV corpus plus a seeded random
// sweep of the family's partitions. Checkers verify the classification
// fields disassembly text cannot show — register read/write sets,
// branch class, memory access/ordering, flag effects — so this layer
// catches semantic regressions that perfect text parity would miss.
// Issues matching a `check=semantic` known-deviations entry are
// reported under their catalogue id and do not gate; everything else
// gates.

import Foundation
@_spi(Validation) import Iris

func runSemanticCommand(_ args: [String]) -> Int32 {
    var familyName: String?
    var count = 65536
    var seed: UInt64 = 0x5EED_5EED_5EED_5EED
    var index = 0
    while index < args.count {
        switch args[index] {
        case "--family":
            index += 1
            familyName = args.indices.contains(index) ? args[index] : nil
        case "--count":
            index += 1
            count = parseDecimalOption("--count", in: args, at: index, for: "semantic")
        case "--seed":
            index += 1
            seed = parseSeedOption("--seed", in: args, at: index, for: "semantic")
        default:
            eprint("semantic: unknown option \(args[index])")
            return 2
        }
        index += 1
    }
    guard let familyName else {
        eprint("semantic: pass --family <name|all>")
        return 2
    }
    let families = familyName == "all"
        ? ParityFamily.all
        : ParityFamily.named(familyName).map { [$0] } ?? []
    guard !families.isEmpty else {
        eprint("semantic: unknown family `\(familyName)` (families: \(ParityFamily.all.map(\.name).joined(separator: ", ")), or `all`)")
        return 2
    }

    let catalogue = DeviationCatalogue.load()
    var exitCode: Int32 = 0
    for family in families {
        let issues = checkFamily(family, count: count, seed: seed, catalogue: catalogue)
        if issues > 0 { exitCode = 1 }
    }
    return exitCode
}

private func checkFamily(
    _ family: ParityFamily, count: Int, seed: UInt64, catalogue: DeviationCatalogue,
) -> Int {
    let started = Date()
    var words = family.generateWords(count: count, seed: seed)
    var corpusWords = 0
    if family.syntheticFixture != nil {
        for path in family.resolveTSVPaths() where !(path as NSString).lastPathComponent.hasPrefix("real") {
            if let reader = TSVLineReader(path: path) {
                while let line = reader.nextLine() {
                    if line.isEmpty || line.hasPrefix("#") { continue }
                    if let first = line.split(separator: "\t").first,
                       let encoding = UInt32(first, radix: 16)
                    {
                        words.append(encoding)
                        corpusWords += 1
                    }
                }
            }
        }
    }

    var checked = 0
    var skippedUndefined = 0
    var issues = 0
    var catalogued: [String: Int] = [:]
    var samples: [String] = []
    for word in words {
        let instruction = decode(word, at: 0, features: family.features)
        if instruction.isUndefined {
            skippedUndefined += 1
            continue
        }
        checked += 1
        if let issue = semanticIssue(for: instruction) {
            if let entry = catalogue.classify(instruction: instruction, oracleText: "", check: .semantic, field: issue.field) {
                catalogued[entry.id, default: 0] += 1
                continue
            }
            issues += 1
            if samples.count < 10 {
                samples.append("  ISSUE \(hex32(word)) (\(instruction.mnemonic.name)): \(issue.field) actual=`\(issue.actual)` expected=`\(issue.expected)`")
            }
        }
    }

    let catalogueNote = catalogued.isEmpty
        ? ""
        : " catalogued={" + catalogued.sorted { $0.key < $1.key }
        .map { "\($0.key):\(grouped($0.value))" }.joined(separator: ", ") + "}"
    print("[semantic] \(family.name): words=\(grouped(words.count)) (random=\(grouped(words.count - corpusWords)) corpus=\(grouped(corpusWords))) checked=\(grouped(checked)) undefined-skipped=\(grouped(skippedUndefined))\(catalogueNote) ISSUES=\(grouped(issues)) [\(secondsText(Date().timeIntervalSince(started)))]")
    for sample in samples {
        print(sample)
    }
    if issues > 10 {
        print("  ... and \(grouped(issues - 10)) more")
    }
    return issues
}
