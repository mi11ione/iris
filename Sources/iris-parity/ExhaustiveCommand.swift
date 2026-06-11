// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// `iris-parity exhaustive` — the layer-3 trust sweep. Decodes the
// full 2^32 word space (or one op0 partition) asserting TOTALITY (every
// word yields a well-formed record, no crash) and DETERMINISM (two
// independent passes produce identical digests).
//
// Digest: FNV-1a 64 over the per-word tuple (mnemonic raw, category
// raw, branchClass raw, operand count, text hash) — text included for
// EVERY word, no subsampling — accumulated per fixed-size chunk, then
// folded over the ordered chunk digests. Order is fixed, so any decode
// or rendering difference between passes (or between runs on the same
// library version) changes the digest.
//
// Decode runs at `.arm64e` features — the superset surface (the only
// feature-gated tier is LDRAA/LDRAB, which plain features would leave
// UNDEFINED).

import Foundation
@_spi(Validation) import Iris

private struct ChunkOutcome: Sendable {
    let index: Int
    let digest: UInt64
    let defined: Int
    let undefined: Int
    let violations: Int
    let violationSamples: [String]
}

private struct PassResult {
    let digest: UInt64
    let chunkDigests: [UInt64]
    let defined: Int
    let undefined: Int
    let violations: Int
    let violationSamples: [String]
    let seconds: Double
}

@available(macOS 10.15, *)
func runExhaustiveCommand(_ args: [String]) async -> Int32 {
    var partition: UInt8?
    var allPartitions = false
    var jobs = ProcessInfo.processInfo.activeProcessorCount
    var index = 0
    while index < args.count {
        switch args[index] {
        case "--partition":
            index += 1
            guard args.indices.contains(index) else {
                eprint("exhaustive: --partition needs a value")
                return 2
            }
            if args[index] == "all" {
                allPartitions = true
            } else {
                let raw = args[index]
                let parsed = raw.hasPrefix("0x")
                    ? UInt8(raw.dropFirst(2), radix: 16)
                    : UInt8(raw)
                guard let value = parsed, value < 16 else {
                    eprint("exhaustive: bad op0 partition `\(raw)` (0-15 or 0x0-0xf)")
                    return 2
                }
                partition = value
            }
        case "all":
            allPartitions = true
        case "--jobs":
            index += 1
            jobs = parseDecimalOption("--jobs", in: args, at: index, for: "exhaustive", minimum: 1)
        default:
            eprint("exhaustive: unknown option \(args[index])")
            return 2
        }
        index += 1
    }
    if !allPartitions, partition == nil {
        allPartitions = true
    }
    jobs = max(1, jobs)

    #if DEBUG
        eprint("exhaustive: WARNING — debug build; run via `swift run -c release iris-parity` (a full sweep is ~10x slower unoptimized)")
    #endif

    let totalWords: UInt64 = allPartitions ? 1 << 32 : 1 << 28
    let scope = allPartitions ? "all (full 2^32 space)" : "op0=\(partition.map { String($0, radix: 16) } ?? "?")"
    print("[exhaustive] scope=\(scope) words=\(grouped(Int(totalWords))) jobs=\(jobs) features=arm64e")

    let passA = await sweepPass(label: "pass A", partition: allPartitions ? nil : partition, jobs: jobs)
    let passB = await sweepPass(label: "pass B", partition: allPartitions ? nil : partition, jobs: jobs)

    let deterministic = passA.digest == passB.digest
    var firstDifferingChunk: Int?
    if !deterministic {
        firstDifferingChunk = zip(passA.chunkDigests, passB.chunkDigests).enumerated()
            .first { $0.element.0 != $0.element.1 }?.offset
    }
    let violations = passA.violations + passB.violations

    print("[exhaustive] totality: defined=\(grouped(passA.defined)) undefined=\(grouped(passA.undefined)) violations=\(grouped(violations))")
    for sample in (passA.violationSamples + passB.violationSamples).prefix(10) {
        print("  VIOLATION \(sample)")
    }
    print("[exhaustive] determinism: passA=\(hex64(passA.digest)) passB=\(hex64(passB.digest)) \(deterministic ? "IDENTICAL" : "MISMATCH at chunk \(firstDifferingChunk.map(String.init) ?? "?")")")
    print("[exhaustive] timing: passA=\(secondsText(passA.seconds)) passB=\(secondsText(passB.seconds)) total=\(secondsText(passA.seconds + passB.seconds))")
    print("[exhaustive] digest=\(hex64(passA.digest)) \(deterministic && violations == 0 ? "OK" : "FAIL")")
    return deterministic && violations == 0 ? 0 : 1
}

@available(macOS 10.15, *)
private func sweepPass(label: String, partition: UInt8?, jobs: Int) async -> PassResult {
    let started = Date()
    let chunkWords: UInt64 = 1 << 22
    let totalWords: UInt64 = partition == nil ? 1 << 32 : 1 << 28
    let chunkCount = Int(totalWords / chunkWords)

    var chunkDigests = [UInt64](repeating: 0, count: chunkCount)
    var defined = 0
    var undefined = 0
    var violations = 0
    var violationSamples: [String] = []
    var completed = 0
    var lastProgress = Date()

    await withTaskGroup(of: ChunkOutcome.self) { group in
        var inFlight = 0
        var nextChunk = 0
        while nextChunk < chunkCount || inFlight > 0 {
            while inFlight < jobs, nextChunk < chunkCount {
                let chunkIndex = nextChunk
                nextChunk += 1
                inFlight += 1
                group.addTask {
                    sweepChunk(index: chunkIndex, words: chunkWords, partition: partition)
                }
            }
            if inFlight > 0, let outcome = await group.next() {
                inFlight -= 1
                chunkDigests[outcome.index] = outcome.digest
                defined += outcome.defined
                undefined += outcome.undefined
                violations += outcome.violations
                if violationSamples.count < 10 {
                    violationSamples.append(contentsOf: outcome.violationSamples.prefix(10 - violationSamples.count))
                }
                completed += 1
                let now = Date()
                if now.timeIntervalSince(lastProgress) >= 30 {
                    lastProgress = now
                    let pct = Double(completed) / Double(chunkCount) * 100
                    print("[exhaustive] \(label): \(completed)/\(chunkCount) chunks (\(String(format: "%.1f", pct))%)")
                }
            }
        }
    }

    var folded = FNV1a()
    for digest in chunkDigests {
        folded.combine(digest)
    }
    return PassResult(
        digest: folded.digest,
        chunkDigests: chunkDigests,
        defined: defined,
        undefined: undefined,
        violations: violations,
        violationSamples: violationSamples,
        seconds: Date().timeIntervalSince(started),
    )
}

/// Decode one contiguous chunk. For a single-partition sweep the 28
/// free bits map to a word as (high3 << 29) | (op0 << 25) | low25 —
/// the partition's full encoding space in a fixed enumeration order.
private func sweepChunk(index: Int, words: UInt64, partition: UInt8?) -> ChunkOutcome {
    var hasher = FNV1a()
    var defined = 0
    var undefined = 0
    var violations = 0
    var samples: [String] = []
    let base = UInt64(index) * words
    var cursor = base
    let end = base + words
    while cursor < end {
        let word: UInt32 = if let partition {
            partitionWord(partition: partition, free28: UInt32(truncatingIfNeeded: cursor))
        } else {
            UInt32(truncatingIfNeeded: cursor)
        }
        let instruction = decode(word, at: 0, features: .arm64e)
        let text = instruction.text

        hasher.combine(instruction.mnemonic.rawValue)
        hasher.combine(instruction.category.rawValue)
        hasher.combine(instruction.branchClass.rawValue)
        hasher.combine(UInt8(truncatingIfNeeded: instruction.operands.count))
        hasher.combine(FNV1a.hash(of: text))

        if instruction.isUndefined { undefined += 1 } else { defined += 1 }

        var violation: String?
        if instruction.encoding != word {
            violation = "\(hex32(word)): encoding not preserved (\(hex32(instruction.encoding)))"
        } else if instruction.address != 0 {
            violation = "\(hex32(word)): address not preserved"
        } else if text.isEmpty {
            violation = "\(hex32(word)): empty text"
        } else if instruction.isUndefined, instruction.mnemonic != .undefined {
            violation = "\(hex32(word)): undefined category with mnemonic \(instruction.mnemonic.name)"
        } else if instruction.isUndefined, !instruction.operands.isEmpty {
            violation = "\(hex32(word)): undefined record carries operands"
        }
        if let violation {
            violations += 1
            if samples.count < 4 { samples.append(violation) }
        }
        cursor += 1
    }
    return ChunkOutcome(
        index: index, digest: hasher.digest, defined: defined,
        undefined: undefined, violations: violations, violationSamples: samples,
    )
}

private func partitionWord(partition: UInt8, free28: UInt32) -> UInt32 {
    let high3 = (free28 >> 25) & 0x7
    let low25 = free28 & 0x1FFFFFF
    return (high3 << 29) | (UInt32(partition) << 25) | low25
}
