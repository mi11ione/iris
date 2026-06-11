// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Measurement substrate: monotonic timing, warmup + N-run medians with
// spread, a dead-code-elimination sink, deterministic SplitMix64,
// machine-info capture, and the JSON document the nightly regression
// guard consumes. Methodology (documented once, applied to every
// benchmark): 1 unrecorded warmup run, then `runs` recorded runs; the
// reported figure is the MEDIAN; spread = (max − min) / median over the
// recorded runs. Timing uses `ContinuousClock` (monotonic, suspends
// excluded on neither side — wall time).

import Foundation

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

// MARK: - Dead-code-elimination sink

/// Opaque sink the optimizer cannot see through; every timed loop folds
/// its observable results into a checksum and hands it here so the work
/// cannot be elided.
@inline(never)
func blackhole(_ value: UInt64) {
    Sink.value ^= value
}

enum Sink {
    nonisolated(unsafe) static var value: UInt64 = 0
}

// MARK: - Deterministic PRNG

/// SplitMix64 — the project's deterministic sweep generator (same
/// algorithm as the parity tool's), so buffers are reproducible from the
/// seed alone.
struct SplitMix64 {
    private var state: UInt64

    init(seed: UInt64) {
        state = seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

// MARK: - Timing

/// One benchmark's recorded runs and derived statistics.
struct BenchResult {
    /// Stable metric identifier (the baseline file keys on it).
    let name: String
    /// Unit of `median` (e.g. "words/s", "ns/op").
    let unit: String
    /// Whether larger values are better (throughput) or worse (latency) —
    /// drives the one-sided regression comparison.
    let largerIsBetter: Bool
    /// Every recorded run, in execution order.
    let runs: [Double]
    /// Optional free-form note (sample sizes, caveats).
    let note: String?

    var median: Double {
        let sorted = runs.sorted()
        let mid = sorted.count / 2
        if sorted.count % 2 == 1 { return sorted[mid] }
        return (sorted[mid - 1] + sorted[mid]) / 2
    }

    var min: Double {
        runs.min() ?? 0
    }

    var max: Double {
        runs.max() ?? 0
    }

    /// Relative spread: (max − min) / median; 0 when degenerate.
    var spread: Double {
        let m = median
        guard m != 0 else { return 0 }
        return (max - min) / m
    }
}

/// Run `body` once as warmup (unrecorded), then `runs` recorded times.
/// `body` returns the run's metric value (already in the result unit —
/// the caller converts duration to words/s or ns/op).
func measure(
    name: String,
    unit: String,
    largerIsBetter: Bool,
    runs: Int,
    note: String? = nil,
    body: () -> Double,
) -> BenchResult {
    _ = body()
    var recorded: [Double] = []
    recorded.reserveCapacity(runs)
    for _ in 0 ..< runs {
        recorded.append(body())
    }
    return BenchResult(
        name: name, unit: unit, largerIsBetter: largerIsBetter,
        runs: recorded, note: note,
    )
}

/// Async-workload variant of ``measure(name:unit:largerIsBetter:runs:note:body:)``.
func measure(
    name: String,
    unit: String,
    largerIsBetter: Bool,
    runs: Int,
    note: String? = nil,
    body: () async -> Double,
) async -> BenchResult {
    _ = await body()
    var recorded: [Double] = []
    recorded.reserveCapacity(runs)
    for _ in 0 ..< runs {
        await recorded.append(body())
    }
    return BenchResult(
        name: name, unit: unit, largerIsBetter: largerIsBetter,
        runs: recorded, note: note,
    )
}

/// Time one execution of `body`, returning seconds.
func timed(_ body: () -> Void) -> Double {
    let clock = ContinuousClock()
    let duration = clock.measure(body)
    let comps = duration.components
    return Double(comps.seconds) + Double(comps.attoseconds) * 1e-18
}

/// Async variant of ``timed(_:)``.
func timed(_ body: () async -> Void) async -> Double {
    let clock = ContinuousClock()
    let start = clock.now
    await body()
    let duration = clock.now - start
    let comps = duration.components
    return Double(comps.seconds) + Double(comps.attoseconds) * 1e-18
}

// MARK: - Machine info

struct MachineInfo {
    let cpuBrand: String
    let physicalCores: Int
    let logicalCores: Int
    let performanceCores: Int?
    let efficiencyCores: Int?
    let memoryBytes: UInt64
    let osVersion: String
    let swiftVersion: String

    static func capture() -> MachineInfo {
        MachineInfo(
            cpuBrand: sysctlString("machdep.cpu.brand_string") ?? linuxCPUModel() ?? "unknown",
            physicalCores: Int(sysctlUInt64("hw.physicalcpu") ?? UInt64(ProcessInfo.processInfo.processorCount)),
            logicalCores: Int(sysctlUInt64("hw.logicalcpu") ?? UInt64(ProcessInfo.processInfo.activeProcessorCount)),
            performanceCores: sysctlUInt64("hw.perflevel0.physicalcpu").map(Int.init),
            efficiencyCores: sysctlUInt64("hw.perflevel1.physicalcpu").map(Int.init),
            memoryBytes: sysctlUInt64("hw.memsize") ?? ProcessInfo.processInfo.physicalMemory,
            osVersion: ProcessInfo.processInfo.operatingSystemVersionString,
            swiftVersion: capturedSwiftVersion(),
        )
    }

    private static func sysctlString(_ name: String) -> String? {
        #if canImport(Darwin)
            var size = 0
            guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
            var buffer = [UInt8](repeating: 0, count: size)
            guard sysctlbyname(name, &buffer, &size, nil, 0) == 0 else { return nil }
            return String(decoding: buffer.prefix(while: { $0 != 0 }), as: UTF8.self)
        #else
            return nil
        #endif
    }

    private static func sysctlUInt64(_ name: String) -> UInt64? {
        #if canImport(Darwin)
            var value: UInt64 = 0
            var size = MemoryLayout<UInt64>.size
            guard sysctlbyname(name, &value, &size, nil, 0) == 0 else { return nil }
            return value
        #else
            return nil
        #endif
    }

    private static func linuxCPUModel() -> String? {
        guard let text = try? String(contentsOfFile: "/proc/cpuinfo", encoding: .utf8) else { return nil }
        for line in text.split(separator: "\n") where line.hasPrefix("model name") {
            if let colon = line.firstIndex(of: ":") {
                return line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }

    /// `swift --version`'s first line when the toolchain is reachable;
    /// otherwise the compiler-version bucket this binary was built with.
    private static func capturedSwiftVersion() -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["swift", "--version"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        if (try? process.run()) != nil {
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            if let line = String(data: data, encoding: .utf8)?
                .split(separator: "\n").first(where: { $0.contains("Swift version") })
            {
                return line.trimmingCharacters(in: .whitespaces)
            }
        }
        #if compiler(>=6.3)
            return "compiler >= 6.3 (toolchain query failed)"
        #elseif compiler(>=6.2)
            return "compiler >= 6.2 (toolchain query failed)"
        #else
            return "compiler >= 6.0 (toolchain query failed)"
        #endif
    }
}

// MARK: - Peak RSS

/// Process-lifetime peak resident set size in BYTES. `ru_maxrss` is
/// bytes on Darwin and KILOBYTES on Linux — normalized here. Monotone:
/// it never decreases, so a delta across an allocation is meaningful
/// only when the allocation pushes a NEW high-water mark.
func peakRSSBytes() -> UInt64 {
    var usage = rusage()
    guard getrusage(RUSAGE_SELF, &usage) == 0 else { return 0 }
    #if canImport(Darwin)
        return UInt64(usage.ru_maxrss)
    #else
        return UInt64(usage.ru_maxrss) * 1024
    #endif
}

// MARK: - Formatting + JSON

func groupedInt(_ value: Double) -> String {
    let v = Int64(value.rounded())
    var digits = Array(String(v.magnitude))
    var out: [Character] = []
    while digits.count > 3 {
        out.insert(contentsOf: ",\(String(digits.suffix(3)))", at: out.startIndex)
        digits.removeLast(3)
    }
    out.insert(contentsOf: String(digits), at: out.startIndex)
    return (v < 0 ? "-" : "") + String(out)
}

func formatValue(_ value: Double, unit _: String) -> String {
    if value < 1000 { return String(format: "%.2f", value) }
    return groupedInt(value)
}

/// Render the full results document as deterministic JSON (stable key
/// order, no Foundation Codable round-trip).
func renderJSON(machine: MachineInfo, config: [(String, String)], results: [BenchResult]) -> String {
    func esc(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
    }
    var lines: [String] = []
    lines.append("{")
    lines.append("  \"schema\": \"iris-bench/1\",")
    lines.append("  \"timestamp\": \"\(ISO8601DateFormatter().string(from: Date()))\",")
    lines.append("  \"machine\": {")
    lines.append("    \"cpu\": \"\(esc(machine.cpuBrand))\",")
    lines.append("    \"physicalCores\": \(machine.physicalCores),")
    lines.append("    \"logicalCores\": \(machine.logicalCores),")
    lines.append("    \"performanceCores\": \(machine.performanceCores.map(String.init) ?? "null"),")
    lines.append("    \"efficiencyCores\": \(machine.efficiencyCores.map(String.init) ?? "null"),")
    lines.append("    \"memoryBytes\": \(machine.memoryBytes),")
    lines.append("    \"os\": \"\(esc(machine.osVersion))\",")
    lines.append("    \"swift\": \"\(esc(machine.swiftVersion))\"")
    lines.append("  },")
    lines.append("  \"config\": {")
    lines.append(config.map { "    \"\($0.0)\": \"\(esc($0.1))\"" }.joined(separator: ",\n"))
    lines.append("  },")
    lines.append("  \"results\": [")
    var blocks: [String] = []
    for r in results {
        var b = "    {\n"
        b += "      \"name\": \"\(r.name)\",\n"
        b += "      \"unit\": \"\(r.unit)\",\n"
        b += "      \"largerIsBetter\": \(r.largerIsBetter),\n"
        b += "      \"runs\": [\(r.runs.map { String($0) }.joined(separator: ", "))],\n"
        b += "      \"median\": \(r.median),\n"
        b += "      \"min\": \(r.min),\n"
        b += "      \"max\": \(r.max),\n"
        b += "      \"spread\": \(r.spread)"
        if let note = r.note {
            b += ",\n      \"note\": \"\(esc(note))\""
        }
        b += "\n    }"
        blocks.append(b)
    }
    lines.append(blocks.joined(separator: ",\n"))
    lines.append("  ]")
    lines.append("}")
    return lines.joined(separator: "\n")
}

/// Human-readable result line for the console mode.
func printResult(_ r: BenchResult) {
    let runsText = r.runs.map { formatValue($0, unit: r.unit) }.joined(separator: " / ")
    var line = "  \(r.name): median \(formatValue(r.median, unit: r.unit)) \(r.unit)"
    line += "  (runs: \(runsText); spread \(String(format: "%.1f", r.spread * 100))%)"
    print(line)
    if let note = r.note {
        print("    note: \(note)")
    }
}
