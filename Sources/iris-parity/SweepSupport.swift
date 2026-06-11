// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Shared sweep machinery: deterministic randomness (SplitMix64),
// deterministic hashing (FNV-1a 64), repo-root resolution for in-repo
// fixtures/docs, parse-or-die option-value parsing, the streaming TSV
// line reader, and console helpers.

import Foundation

/// Deterministic 64-bit generator (SplitMix64). Seeded sweeps are
/// reproducible run to run and across platforms.
struct SplitMix64 {
    var state: UInt64

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

    mutating func nextWord() -> UInt32 {
        UInt32(truncatingIfNeeded: next())
    }
}

/// FNV-1a 64 running hash. Process-independent (unlike `Hasher`), so
/// digests compare across runs, processes, and platforms.
struct FNV1a {
    private(set) var digest: UInt64 = 0xCBF2_9CE4_8422_2325

    mutating func combine(_ byte: UInt8) {
        digest = (digest ^ UInt64(byte)) &* 0x0000_0100_0000_01B3
    }

    mutating func combine(_ value: UInt16) {
        combine(UInt8(truncatingIfNeeded: value))
        combine(UInt8(truncatingIfNeeded: value >> 8))
    }

    mutating func combine(_ value: UInt32) {
        combine(UInt16(truncatingIfNeeded: value))
        combine(UInt16(truncatingIfNeeded: value >> 16))
    }

    mutating func combine(_ value: UInt64) {
        combine(UInt32(truncatingIfNeeded: value))
        combine(UInt32(truncatingIfNeeded: value >> 32))
    }

    mutating func combine(_ text: String) {
        for byte in text.utf8 {
            combine(byte)
        }
    }

    /// One-shot FNV-1a 64 of a string's UTF-8 bytes.
    static func hash(of text: String) -> UInt64 {
        var h = FNV1a()
        h.combine(text)
        return h.digest
    }
}

/// Package root resolved from this source file's compile-time path, with
/// a working-directory fallback for relocated binaries. Used to locate
/// `Tests/Fixtures/Decode/` and `KNOWN-DEVIATIONS.md`.
func repositoryRoot() -> URL {
    let compiled = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent() // iris-parity
        .deletingLastPathComponent() // Sources
        .deletingLastPathComponent() // <package root>
    if FileManager.default.fileExists(atPath: compiled.appendingPathComponent("Package.swift").path) {
        return compiled
    }
    return URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
}

func eprint(_ message: String) {
    FileHandle.standardError.write(Data((message + "\n").utf8))
}

/// Parse a decimal option value or die: a malformed `--count`/`--jobs`/
/// `--limit`/`--chunk` must never fall back to a default — the run
/// that proceeds would silently not be the run that was asked for.
/// `minimum` rejects degenerate values a subcommand cannot honor
/// (`--chunk 0` / `--jobs 0` would never make progress).
/// Failures name the flag and the offending value on stderr, exit 1.
func parseDecimalOption(_ flag: String, in args: [String], at index: Int, for subcommand: String, minimum: Int = 0) -> Int {
    let raw = optionValue(flag, in: args, at: index, for: subcommand)
    guard let value = Int(raw), value >= minimum else {
        eprint("\(subcommand): \(flag): cannot parse `\(raw)` (expects a decimal integer >= \(minimum))")
        exit(1)
    }
    return value
}

/// Parse a `--seed` value or die. Seeds are naturally written in hex,
/// so 0x-prefixed hex is accepted alongside decimal.
func parseSeedOption(_ flag: String, in args: [String], at index: Int, for subcommand: String) -> UInt64 {
    let raw = optionValue(flag, in: args, at: index, for: subcommand)
    let parsed = raw.hasPrefix("0x") || raw.hasPrefix("0X")
        ? UInt64(raw.dropFirst(2), radix: 16)
        : UInt64(raw)
    guard let value = parsed else {
        eprint("\(subcommand): \(flag): cannot parse `\(raw)` (expects decimal or 0x-prefixed hex)")
        exit(1)
    }
    return value
}

/// The raw value of an option, or die when the flag is last.
private func optionValue(_ flag: String, in args: [String], at index: Int, for subcommand: String) -> String {
    guard args.indices.contains(index) else {
        eprint("\(subcommand): \(flag) needs a value")
        exit(1)
    }
    return args[index]
}

func hex32(_ value: UInt32) -> String {
    let h = String(value, radix: 16)
    return "0x" + String(repeating: "0", count: max(0, 8 - h.count)) + h
}

func hex64(_ value: UInt64) -> String {
    let h = String(value, radix: 16)
    return "0x" + String(repeating: "0", count: max(0, 16 - h.count)) + h
}

/// Wall-clock duration as a compact human string.
func secondsText(_ seconds: Double) -> String {
    if seconds < 120 { return String(format: "%.1fs", seconds) }
    return String(format: "%dm%02ds", Int(seconds) / 60, Int(seconds) % 60)
}

/// Buffered incremental line reader so multi-GB corpus TSVs stream at
/// constant memory.
final class TSVLineReader {
    private let handle: FileHandle
    private var buffer = Data()
    private var offset = 0
    private var eof = false
    private(set) var lineNumber = 0
    private let chunkSize = 8 << 20

    init?(path: String) {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        self.handle = handle
    }

    deinit {
        handle.closeFile()
    }

    func nextLine() -> String? {
        while true {
            if let newlineIndex = buffer[offset...].firstIndex(of: 0x0A) {
                let lineData = buffer[offset ..< newlineIndex]
                offset = newlineIndex + 1
                lineNumber += 1
                var line = String(decoding: lineData, as: UTF8.self)
                if line.hasSuffix("\r") { line.removeLast() }
                return line
            }
            if eof {
                if offset < buffer.count {
                    let lineData = buffer[offset...]
                    offset = buffer.count
                    lineNumber += 1
                    return String(decoding: lineData, as: UTF8.self)
                }
                return nil
            }
            buffer = buffer[offset...]
            offset = buffer.startIndex
            let chunk = handle.readData(ofLength: chunkSize)
            if !chunk.isEmpty {
                buffer.append(chunk)
            } else {
                eof = true
            }
            // Re-base indices after append so Data slice indexing stays valid.
            buffer = Data(buffer)
            offset = 0
        }
    }
}

func grouped(_ value: Int) -> String {
    let raw = String(value)
    var out: [Character] = []
    for (index, ch) in raw.reversed().enumerated() {
        if index > 0, index % 3 == 0, ch != "-" { out.append(",") }
        out.append(ch)
    }
    return String(out.reversed())
}
