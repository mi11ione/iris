// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
import Iris
import IrisValidation

enum LLVMMC {
    /// Locate llvm-mc. Order: `IRIS_LLVM_MC` env, Homebrew prefixes (Apple
    /// Silicon, Intel), PATH entries, apt llvm layouts (versioned names
    /// newest-first). Returns nil when nothing executable is found.
    static func locate() -> String? {
        let fm = FileManager.default
        var candidates: [String] = []
        if let override = ProcessInfo.processInfo.environment["IRIS_LLVM_MC"] {
            candidates.append(override)
        }
        candidates.append("/opt/homebrew/opt/llvm/bin/llvm-mc")
        candidates.append("/usr/local/opt/llvm/bin/llvm-mc")
        if let path = ProcessInfo.processInfo.environment["PATH"] {
            for dir in path.split(separator: ":") {
                candidates.append("\(dir)/llvm-mc")
            }
        }
        var versioned: [(Int, String)] = []
        if let entries = try? fm.contentsOfDirectory(atPath: "/usr/lib") {
            for entry in entries where entry.hasPrefix("llvm-") {
                if let n = Int(entry.dropFirst("llvm-".count)) {
                    versioned.append((n, "/usr/lib/\(entry)/bin/llvm-mc"))
                }
            }
        }
        if let entries = try? fm.contentsOfDirectory(atPath: "/usr/bin") {
            for entry in entries where entry.hasPrefix("llvm-mc-") {
                if let n = Int(entry.dropFirst("llvm-mc-".count)) {
                    versioned.append((n, "/usr/bin/\(entry)"))
                }
            }
        }
        candidates.append(contentsOf: versioned.sorted { $0.0 > $1.0 }.map(\.1))
        for candidate in candidates where fm.isExecutableFile(atPath: candidate) {
            return candidate
        }
        return nil
    }

    /// First line of `llvm-mc --version` carrying the version, e.g. "Homebrew
    /// LLVM version 22.1.8".
    static func version(_ llvmMC: String) -> String {
        guard let result = runSubprocess(llvmMC, ["--version"], timeoutSeconds: 30) else {
            return "unknown"
        }
        for line in result.stdout.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.lowercased().contains("version") { return trimmed }
        }
        return "unknown"
    }

    /// Feature names in `mattr` this llvm-mc does not recognize.
    static func unrecognizedFeatures(_ llvmMC: String, mattr: String) -> [String] {
        let probe = Data("0x1f 0x20 0x03 0xd5\n".utf8)
        guard let result = runSubprocess(
            llvmMC, ["-triple=arm64-apple-macos", "-mattr=\(mattr)", "-disassemble"],
            stdin: probe, timeoutSeconds: 60,
        ) else { return ["<llvm-mc failed to run>"] }
        if result.timedOut { return ["<llvm-mc timed out probing -mattr>"] }
        var missing: [String] = []
        for line in result.stderr.split(separator: "\n") {
            guard line.contains("is not a recognized feature") else { continue }
            if let start = line.firstIndex(of: "'"),
               let end = line[line.index(after: start)...].firstIndex(of: "'")
            {
                missing.append(String(line[line.index(after: start) ..< end]))
            }
        }
        return missing
    }

    /// Disassemble `encodings` via one llvm-mc subprocess at `-mattr=mattr`,
    /// returning normalized text per encoding in input order, `""` for a
    /// rejected one.
    static func disassemble(_ encodings: [UInt32], llvmMC: String, mattr: String) -> [String]? {
        if encodings.isEmpty { return [] }
        let hexDigits: [UInt8] = Array("0123456789abcdef".utf8)
        var payload: [UInt8] = []
        payload.reserveCapacity(encodings.count * 20)
        for encoding in encodings {
            var shift: UInt32 = 0
            for byteIndex in 0 ..< 4 {
                if byteIndex > 0 { payload.append(0x20) }
                let byte = UInt8((encoding >> shift) & 0xFF)
                payload.append(0x30)
                payload.append(0x78)
                payload.append(hexDigits[Int(byte >> 4)])
                payload.append(hexDigits[Int(byte & 0xF)])
                shift &+= 8
            }
            payload.append(0x0A)
        }
        let timeoutSeconds = 600.0
        guard let result = runSubprocess(
            llvmMC, ["-triple=arm64-apple-macos", "-mattr=\(mattr)", "-disassemble"],
            stdin: Data(payload), timeoutSeconds: timeoutSeconds,
        ) else {
            eprint("llvm-mc: ORACLE FAILURE — \(llvmMC) failed to launch")
            return nil
        }
        if result.timedOut {
            eprint("llvm-mc: ORACLE FAILURE — timed out after \(Int(timeoutSeconds))s disassembling \(encodings.count) words at -mattr=\(mattr); a partial capture must not be scored")
            return nil
        }
        let invalid = invalidInputLines(result.stderr)
        let lines = result.stdout.split(separator: "\n", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix(".") }
        var cursor = 0
        var out: [String] = []
        out.reserveCapacity(encodings.count)
        for index in encodings.indices {
            if invalid.contains(index + 1) {
                out.append("")
                continue
            }
            if cursor < lines.count {
                out.append(normalizeDisassembly(lines[cursor]))
                cursor &+= 1
            } else {
                out.append("")
            }
        }
        return out
    }

    /// 1-based input line numbers rejected with `invalid instruction encoding`
    /// (no stdout line emitted for these).
    private static func invalidInputLines(_ stderr: String) -> Set<Int> {
        var result: Set<Int> = []
        for raw in stderr.split(separator: "\n") {
            let line = String(raw)
            guard line.hasPrefix("<stdin>:"), line.contains("invalid instruction encoding") else { continue }
            let afterPrefix = line.dropFirst("<stdin>:".count)
            let colonIndex = afterPrefix.firstIndex(of: ":") ?? afterPrefix.endIndex
            if let n = Int(String(afterPrefix[..<colonIndex])) {
                result.insert(n)
            }
        }
        return result
    }
}
