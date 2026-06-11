// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// iris-bench — the benchmark battery. Modes:
//
//   all              memory → bulk → parallel → tier0 → lookup → session → walk → text (default)
//   memory | bulk | parallel | tier0 | lookup | session | walk | text
//   view-experiment  the borrowing-view prototype measurements
//   smoke            the nightly regression smoke: short bulk + lookup
//                    + session lookup (64 MiB, 3 runs, 10^6 lookups
//                    unless overridden); with --baseline FILE compares
//                    medians one-sided against the checked-in
//                    thresholds and exits 1 on breach
//
// Options: --json (results document to stdout, progress to stderr) ·
// --runs N · --mib N · --seed 0xHEX|decimal · --jobs N ·
// --lookups N · --baseline FILE
//
// Methodology: every benchmark runs 1 unrecorded warmup + `runs`
// recorded runs; reported figure = MEDIAN, spread = (max−min)/median.
// Buffers are deterministic from the seed (recipe in Workloads.swift).
// Always run via `swift run -c release iris-bench` — debug numbers are
// meaningless and the tool warns on stderr.

import Foundation
import Iris

// MARK: - Argument parsing (fail-loud, parity-tool discipline)

func die(_ message: String) -> Never {
    FileHandle.standardError.write(Data("iris-bench: \(message)\n".utf8))
    exit(2)
}

var modes: [String] = []
var config = BenchConfig()
var explicitMiB: Int?
var explicitRuns: Int?
var explicitLookups: Int?
var jobsOption: Int?

var argIterator = CommandLine.arguments.dropFirst().makeIterator()
while let arg = argIterator.next() {
    switch arg {
    case "--json":
        config.json = true
    case "--runs", "--mib", "--seed", "--jobs", "--lookups", "--baseline":
        guard let value = argIterator.next() else { die("\(arg) requires a value") }
        switch arg {
        case "--runs":
            guard let n = Int(value), n >= 1 else { die("--runs: invalid value '\(value)'") }
            explicitRuns = n
        case "--mib":
            guard let n = Int(value), n >= 1 else { die("--mib: invalid value '\(value)'") }
            explicitMiB = n
        case "--seed":
            let parsed = value.hasPrefix("0x")
                ? UInt64(value.dropFirst(2), radix: 16)
                : UInt64(value)
            guard let s = parsed else { die("--seed: invalid value '\(value)'") }
            config.seed = s
        case "--jobs":
            guard let n = Int(value), n >= 1 else { die("--jobs: invalid value '\(value)'") }
            jobsOption = n
        case "--lookups":
            guard let n = Int(value), n >= 1 else { die("--lookups: invalid value '\(value)'") }
            explicitLookups = n
        default:
            config.baselinePath = value
        }
    case "all", "memory", "bulk", "parallel", "tier0", "lookup", "session", "walk", "text",
         "view-experiment", "smoke":
        modes.append(arg)
    default:
        die("unknown argument '\(arg)' (modes: all memory bulk parallel tier0 lookup session walk text view-experiment smoke; options: --json --runs --mib --seed --jobs --lookups --baseline)")
    }
}

if modes.isEmpty { modes = ["all"] }
let isSmoke = modes.contains("smoke")

// Smoke defaults (explicit flags still win): short buffer, fewer runs.
config.bufferBytes = (explicitMiB ?? (isSmoke ? 64 : 256)) * 1024 * 1024
config.runs = explicitRuns ?? (isSmoke ? 3 : 5)
config.lookups = explicitLookups ?? (isSmoke ? 1_000_000 : 10_000_000)
let machine = MachineInfo.capture()
let jobs = jobsOption ?? machine.logicalCores

@MainActor func progress(_ message: String) {
    if config.json {
        FileHandle.standardError.write(Data((message + "\n").utf8))
    } else {
        print(message)
    }
}

#if DEBUG
    progress("WARNING: debug build — numbers are meaningless; use swift run -c release iris-bench")
#endif

progress("iris-bench: \(machine.cpuBrand), \(machine.physicalCores) cores (\(machine.performanceCores.map(String.init) ?? "?")P+\(machine.efficiencyCores.map(String.init) ?? "?")E), \(machine.memoryBytes / (1024 * 1024 * 1024)) GiB")
progress("config: buffer \(config.bufferBytes / (1024 * 1024)) MiB, seed 0x\(String(config.seed, radix: 16)), runs \(config.runs), features arm64e")

progress("generating deterministic buffer…")
let buffer = makeMixedBuffer(byteCount: config.bufferBytes, seed: config.seed)
let wordCount = buffer.count / 4

@MainActor func wants(_ mode: String) -> Bool {
    modes.contains(mode) || modes.contains("all")
}

var results: [BenchResult] = []

// Order matters: memory first (monotone high-water — see benchMemory).
if wants("memory") {
    progress("memory-highwater…")
    results.append(benchMemory(buffer: buffer, config: config))
}

if wants("bulk") || isSmoke {
    progress("bulk-single…")
    results.append(benchBulkSingle(buffer: buffer, config: config))
}

if wants("parallel") {
    progress("bulk-parallel (jobs=\(jobs))…")
    await results.append(benchBulkParallel(buffer: buffer, config: config, jobs: jobs))
}

if wants("tier0") {
    progress("tier0-latency…")
    results.append(benchTier0(buffer: buffer, config: config))
}

/// The remaining benchmarks share one decoded stream.
var sharedStream: InstructionStream?
if wants("lookup") || wants("session") || wants("walk") || wants("text") || isSmoke || modes.contains("view-experiment") {
    progress("constructing shared stream…")
    sharedStream = InstructionStream(bytes: buffer, at: config.baseAddress, features: config.features)
}

if let stream = sharedStream {
    if wants("lookup") || isSmoke {
        progress("lookup-view / lookup-raw…")
        let addresses = makeLookupAddresses(
            count: config.lookups, wordCount: wordCount,
            baseAddress: config.baseAddress, seed: config.seed,
        )
        results.append(benchLookupView(stream: stream, addresses: addresses, config: config))
        results.append(benchLookupRaw(stream: stream, addresses: addresses, config: config))
    }
    if wants("session") || isSmoke {
        progress("session-lookup…")
        let addresses = makeLookupAddresses(
            count: config.lookups, wordCount: wordCount,
            baseAddress: config.baseAddress, seed: config.seed,
        )
        results.append(benchSessionLookup(stream: stream, addresses: addresses, config: config))
        if wants("session") {
            progress("session-walk…")
            results.append(benchSessionWalk(stream: stream, config: config))
        }
    }
    if wants("walk") {
        progress("walk-view / walk-record…")
        results.append(benchWalkView(stream: stream, config: config))
        results.append(benchWalkRecord(stream: stream, config: config))
    }
    if wants("text") {
        progress("text-throughput…")
        results.append(benchText(stream: stream, config: config))
    }
    if modes.contains("view-experiment") {
        progress("view-experiment…")
        let addresses = makeLookupAddresses(
            count: config.lookups, wordCount: wordCount,
            baseAddress: config.baseAddress, seed: config.seed,
        )
        results.append(contentsOf: runViewExperiment(stream: stream, addresses: addresses, config: config))
    }
}

// MARK: - Output

if config.json {
    var pairs = config.configPairs
    pairs.append(("modes", modes.joined(separator: ",")))
    pairs.append(("jobs", String(jobs)))
    print(renderJSON(machine: machine, config: pairs, results: results))
} else {
    print("\nresults (median over \(config.runs) runs, 1 warmup):")
    for result in results {
        printResult(result)
    }
}

// MARK: - Baseline comparison (the nightly regression guard)

if let baselinePath = config.baselinePath {
    let outcome = compareToBaseline(results: results, baselinePath: baselinePath, progress: progress)
    exit(outcome ? 0 : 1)
}

/// One-sided comparison against the checked-in baseline: throughput
/// metrics fail when median < baseline × (1 − tolerance); latency
/// metrics fail when median > baseline × (1 + tolerance). Every metric
/// listed in the baseline MUST be present in the run (a silently
/// missing metric is a failure, not a skip). Metrics the run produced
/// but the baseline does not list are reported, never gating.
@MainActor func compareToBaseline(results: [BenchResult], baselinePath: String, progress: (String) -> Void) -> Bool {
    guard let data = FileManager.default.contents(atPath: baselinePath) else {
        progress("baseline: cannot read \(baselinePath)")
        return false
    }
    guard
        let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
        let metrics = root["metrics"] as? [String: [String: Any]],
        let tolerance = (root["toleranceFraction"] as? NSNumber)?.doubleValue
    else {
        progress("baseline: malformed JSON at \(baselinePath)")
        return false
    }
    if let hostClass = root["hostClass"] as? String {
        progress("baseline: \(baselinePath) (host class: \(hostClass), tolerance ±\(Int(tolerance * 100))%)")
    }
    var pass = true
    for (name, entry) in metrics.sorted(by: { $0.key < $1.key }) {
        guard
            let baselineMedian = (entry["median"] as? NSNumber)?.doubleValue,
            let largerIsBetter = entry["largerIsBetter"] as? Bool
        else {
            progress("baseline: FAIL \(name) — malformed entry")
            pass = false
            continue
        }
        guard let result = results.first(where: { $0.name == name }) else {
            progress("baseline: FAIL \(name) — metric missing from this run")
            pass = false
            continue
        }
        let measured = result.median
        if largerIsBetter {
            let floor = baselineMedian * (1 - tolerance)
            if measured < floor {
                progress("baseline: FAIL \(name) — \(formatValue(measured, unit: result.unit)) \(result.unit) < floor \(formatValue(floor, unit: result.unit)) (baseline \(formatValue(baselineMedian, unit: result.unit)))")
                pass = false
            } else {
                progress("baseline: PASS \(name) — \(formatValue(measured, unit: result.unit)) \(result.unit) ≥ floor \(formatValue(floor, unit: result.unit))")
            }
        } else {
            let ceiling = baselineMedian * (1 + tolerance)
            if measured > ceiling {
                progress("baseline: FAIL \(name) — \(formatValue(measured, unit: result.unit)) \(result.unit) > ceiling \(formatValue(ceiling, unit: result.unit)) (baseline \(formatValue(baselineMedian, unit: result.unit)))")
                pass = false
            } else {
                progress("baseline: PASS \(name) — \(formatValue(measured, unit: result.unit)) \(result.unit) ≤ ceiling \(formatValue(ceiling, unit: result.unit))")
            }
        }
    }
    for result in results where metrics[result.name] == nil {
        progress("baseline: note — \(result.name) not in baseline (not gating)")
    }
    progress(pass ? "baseline: PASS" : "baseline: BREACH")
    return pass
}
