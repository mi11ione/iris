// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// `iris-parity tsv` — diff Iris decode+text against TSV corpora.
//
// Row convention (the golden-suite convention): an empty expected cell
// means the harvest-time oracle rejected the word, so Iris must report
// UNDEFINED; a non-empty cell must equal Iris's canonical text.
//
// Honesty about harvest-era cells: a TSV's expected column is only as
// feature-complete as the -mattr it was harvested with (recorded in the
// file's header comment). A cell can be ORACLE-BLIND — empty because
// the harvest mattr lacked the feature, not because the word is
// invalid. `--reanchor` re-drives every divergent row through llvm-mc
// at the family's MAXIMAL mattr and reclassifies rows where Iris
// matches the live oracle as oracle-blind (reported separately, never
// as Iris failures). Without `--reanchor`, divergences on a TSV whose
// header mattr differs from the family maximum are reported with that
// caveat and still gate — silence is never assumed in Iris's favor.

import Foundation
@_spi(Validation) import Iris

struct TSVRowRecord: Sendable {
    let encoding: UInt32
    let expected: String
    let line: Int
}

struct TSVDivergence: Sendable {
    let encoding: UInt32
    let expected: String
    let irisText: String
    let line: Int
}

private struct TSVBatchResult: Sendable {
    var rows = 0
    var ok = 0
    var catalogued: [String: Int] = [:]
    var defectCatalogued = 0
    var divergent: [TSVDivergence] = []
}

private struct TSVFileOutcome {
    var rows = 0
    var trueDivergences = 0
    var obliviousCells = 0
}

@available(macOS 10.15, *)
func runTSVCommand(_ args: [String]) async -> Int32 {
    var familyName: String?
    var explicitPath: String?
    var reanchor = false
    var llvmMCOverride: String?
    var limit: Int?
    var index = 0
    while index < args.count {
        switch args[index] {
        case "--family":
            index += 1
            familyName = args.indices.contains(index) ? args[index] : nil
        case "--reanchor":
            reanchor = true
        case "--llvm-mc":
            index += 1
            llvmMCOverride = args.indices.contains(index) ? args[index] : nil
        case "--limit":
            index += 1
            limit = parseDecimalOption("--limit", in: args, at: index, for: "tsv")
        default:
            if args[index].hasPrefix("--") {
                eprint("tsv: unknown option \(args[index])")
                return 2
            }
            explicitPath = args[index]
        }
        index += 1
    }

    var jobs: [(family: ParityFamily, path: String)] = []
    if let explicitPath {
        guard let family = familyName.flatMap(ParityFamily.named)
            ?? ParityFamily.inferred(fromPath: explicitPath)
        else {
            eprint("tsv: cannot infer the family for \(explicitPath); pass --family")
            return 2
        }
        jobs = [(family, explicitPath)]
    } else if let familyName {
        let families = familyName == "all"
            ? ParityFamily.all.filter { !$0.resolveTSVPaths().isEmpty }
            : ParityFamily.named(familyName).map { [$0] } ?? []
        guard !families.isEmpty else {
            eprint("tsv: unknown family `\(familyName)` (families: \(ParityFamily.all.map(\.name).joined(separator: ", ")), or `all`)")
            return 2
        }
        for family in families {
            let paths = family.resolveTSVPaths()
            if paths.isEmpty {
                eprint("tsv: no corpus for family `\(family.name)` (no in-repo fixture and IRIS_DECODE_CORPUS unset or empty)")
                return 2
            }
            jobs.append(contentsOf: paths.map { (family, $0) })
        }
    } else {
        eprint("tsv: pass a TSV path or --family <name|all>")
        return 2
    }

    var llvmMC: String?
    if reanchor {
        llvmMC = llvmMCOverride ?? LLVMMC.locate()
        guard let mc = llvmMC else {
            eprint("tsv: --reanchor needs llvm-mc (set IRIS_LLVM_MC, install via brew/apt, or pass --llvm-mc)")
            return 2
        }
        print("[tsv] reanchor oracle: \(mc) (\(LLVMMC.version(mc)))")
    }

    let catalogue = DeviationCatalogue.load()
    var exitCode: Int32 = 0
    for job in jobs {
        guard let outcome = await diffTSVFile(
            family: job.family, path: job.path, limit: limit,
            reanchorWith: llvmMC, catalogue: catalogue,
        ) else {
            return 2
        }
        if outcome.trueDivergences > 0 { exitCode = 1 }
    }
    return exitCode
}

@available(macOS 10.15, *)
private func diffTSVFile(
    family: ParityFamily, path: String, limit: Int?,
    reanchorWith llvmMC: String?, catalogue: DeviationCatalogue,
) async -> TSVFileOutcome? {
    guard let reader = TSVLineReader(path: path) else {
        eprint("tsv: cannot open \(path)")
        return nil
    }
    let isRealLayout = (path as NSString).lastPathComponent.hasPrefix("real")
    let started = Date()
    let batchSize = 65536
    let maxInFlight = max(2, ProcessInfo.processInfo.activeProcessorCount)
    let divergenceDetailCap = 1_000_000

    var total = TSVBatchResult()
    var headerMattr: String?
    // Counters are complete regardless of the detail cap: every batch's
    // divergent rows are counted (and, with --reanchor, re-driven
    // through llvm-mc) as they drain; only `details` — the rows
    // retained for printing — is capped.
    var divergentTotal = 0
    var blindTotal = 0
    var trueTotal = 0
    var details: [TSVDivergence] = []
    var truncatedDetails = false
    var oracleFailed = false

    await withTaskGroup(of: TSVBatchResult.self) { group in
        var inFlight = 0
        var batch: [TSVRowRecord] = []
        batch.reserveCapacity(batchSize)
        var exhausted = false
        var rowsRead = 0

        func drainOne() async {
            guard inFlight > 0, let result = await group.next() else { return }
            inFlight -= 1
            total.rows += result.rows
            total.ok += result.ok
            total.defectCatalogued += result.defectCatalogued
            for (id, count) in result.catalogued {
                total.catalogued[id, default: 0] += count
            }
            divergentTotal += result.divergent.count
            var hard = result.divergent
            if let llvmMC, !hard.isEmpty, !oracleFailed {
                guard let reanchored = reanchorDivergences(hard, family: family, llvmMC: llvmMC) else {
                    oracleFailed = true
                    return
                }
                blindTotal += reanchored.blind
                hard = reanchored.hard
            }
            trueTotal += hard.count
            let room = divergenceDetailCap - details.count
            if room > 0 {
                details.append(contentsOf: hard.prefix(room))
            }
            if hard.count > room { truncatedDetails = true }
        }

        while !exhausted || inFlight > 0 || !batch.isEmpty {
            while batch.count < batchSize, !exhausted, !oracleFailed {
                guard let line = reader.nextLine() else {
                    exhausted = true
                    break
                }
                if line.hasPrefix("#") {
                    if headerMattr == nil, let range = line.range(of: "-mattr=") {
                        headerMattr = String(line[range.upperBound...].prefix { $0 != ")" })
                    }
                    continue
                }
                if line.isEmpty { continue }
                if let cap = limit, rowsRead >= cap {
                    exhausted = true
                    break
                }
                if let row = parseTSVLine(line, lineNumber: reader.lineNumber, realLayout: isRealLayout) {
                    batch.append(row)
                    rowsRead += 1
                }
            }
            if oracleFailed {
                // Abandon the file: drain what is in flight, read no more.
                exhausted = true
                batch.removeAll(keepingCapacity: false)
            }
            if !batch.isEmpty, inFlight < maxInFlight {
                let work = batch
                batch.removeAll(keepingCapacity: true)
                inFlight += 1
                let features = family.features
                let cat = catalogue
                group.addTask { diffBatch(work, features: features, catalogue: cat) }
            }
            if inFlight >= maxInFlight || (exhausted && batch.isEmpty) {
                await drainOne()
            }
        }
    }

    if oracleFailed {
        eprint("tsv: \(family.name): aborted — llvm-mc oracle failure during --reanchor (see error above); nothing was scored")
        return nil
    }

    let mattrNote = headerMattr.map { $0 == family.mattr ? "harvest mattr = family maximal" : "harvest mattr `\($0)` ≠ family maximal" } ?? "no harvest-mattr header"
    print("[tsv] \(family.name): \(path)")
    print("[tsv] \(family.name): \(mattrNote)")

    var outcome = TSVFileOutcome()
    outcome.rows = total.rows
    outcome.obliviousCells = blindTotal
    outcome.trueDivergences = trueTotal

    if llvmMC != nil, divergentTotal > 0 {
        print("[tsv] \(family.name): reanchored \(grouped(divergentTotal)) divergent rows at maximal mattr -> oracle-blind=\(grouped(blindTotal)) still-divergent=\(grouped(trueTotal))")
    }

    let catalogueNote = total.catalogued.isEmpty
        ? ""
        : " catalogued={" + total.catalogued.sorted { $0.key < $1.key }
        .map { "\($0.key):\(grouped($0.value))" }.joined(separator: ", ") + "}"
    print("[tsv] \(family.name): rows=\(grouped(total.rows)) ok=\(grouped(total.ok))\(catalogueNote) oracle-blind=\(grouped(outcome.obliviousCells)) TRUE-DIVERGENCES=\(grouped(outcome.trueDivergences)) [\(secondsText(Date().timeIntervalSince(started)))]")
    if truncatedDetails {
        print("[tsv] \(family.name): note — all counts above are complete; the cap applies only to printed detail rows (first \(grouped(divergenceDetailCap)) retained)")
    }
    for sample in details.prefix(10) {
        print("  DIV L\(sample.line) \(hex32(sample.encoding)): iris=`\(sample.irisText)` expected=`\(sample.expected)`")
    }
    if outcome.trueDivergences > 10 {
        print("  ... and \(grouped(outcome.trueDivergences - 10)) more")
    }
    if outcome.trueDivergences > 0, llvmMC == nil, headerMattr != family.mattr {
        print("[tsv] \(family.name): caveat — this TSV's harvest mattr differs from the family maximum; rerun with --reanchor to separate oracle-blind cells from real divergences")
    }
    return outcome
}

/// Re-drive divergent rows through llvm-mc at the family's maximal
/// mattr. A row where Iris matches the live oracle is an oracle-blind
/// harvest cell (the TSV's expected column could not see the feature),
/// counted and dropped; the rest remain true divergences. Returns nil
/// on oracle failure (launch failure or timeout) — the caller must
/// abort the file, never score it.
private func reanchorDivergences(
    _ divergences: [TSVDivergence], family: ParityFamily, llvmMC: String,
) -> (blind: Int, hard: [TSVDivergence])? {
    var blind = 0
    var hard: [TSVDivergence] = []
    let chunkSize = 65536
    var start = 0
    while start < divergences.count {
        let chunk = Array(divergences[start ..< min(start + chunkSize, divergences.count)])
        guard let fresh = LLVMMC.disassemble(chunk.map(\.encoding), llvmMC: llvmMC, mattr: family.mattr) else {
            return nil
        }
        for (row, oracle) in zip(chunk, fresh) {
            let instruction = decode(row.encoding, at: 0, features: family.features)
            let matchesLive = oracle.isEmpty ? instruction.isUndefined : instruction.text == oracle
            if matchesLive {
                blind += 1
            } else {
                hard.append(row)
            }
        }
        start += chunkSize
    }
    return (blind, hard)
}

private func diffBatch(
    _ rows: [TSVRowRecord], features: Features, catalogue: DeviationCatalogue,
) -> TSVBatchResult {
    var result = TSVBatchResult()
    result.rows = rows.count
    for row in rows {
        let instruction = decode(row.encoding, at: 0, features: features)
        let ok = row.expected.isEmpty ? instruction.isUndefined : instruction.text == row.expected
        if ok {
            result.ok += 1
            continue
        }
        if let entry = catalogue.classify(instruction: instruction, oracleText: row.expected) {
            result.catalogued[entry.id, default: 0] += 1
            if entry.status == "open-defect" { result.defectCatalogued += 1 }
            continue
        }
        result.divergent.append(TSVDivergence(
            encoding: row.encoding,
            expected: row.expected,
            irisText: instruction.isUndefined ? "<undefined>" : instruction.text,
            line: row.line,
        ))
    }
    return result
}

/// Parse one TSV line. Synthetic layout: `encoding_hex \t expected`.
/// Real layout: `binary_path \t file_offset_hex \t encoding_hex \t expected`.
private func parseTSVLine(_ line: String, lineNumber: Int, realLayout: Bool) -> TSVRowRecord? {
    let parts = line.split(separator: "\t", omittingEmptySubsequences: false)
    let encodingColumn = realLayout ? 2 : 0
    guard parts.count > encodingColumn,
          let encoding = UInt32(parts[encodingColumn], radix: 16)
    else { return nil }
    let expectedParts = parts.dropFirst(encodingColumn + 1)
    let expected = expectedParts.isEmpty
        ? ""
        : normalizeDisassembly(expectedParts.joined(separator: " "))
    return TSVRowRecord(encoding: encoding, expected: expected, line: lineNumber)
}
