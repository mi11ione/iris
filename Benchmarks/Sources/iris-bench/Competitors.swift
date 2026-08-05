// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Whole-file disassembly against every other ARM64 disassembler on the
// machine.
//
// The Capstone harness next door times a decode loop in-process, which is
// the fair way to compare two libraries. It cannot compare against a tool
// that only ships as a binary, and it does not measure what a person
// actually waits for: point a disassembler at a file, get text out. This
// measures that — same file, same bytes, wall clock, one process each.
//
// FAIRNESS, stated rather than assumed. These tools do not do identical
// work: some resolve symbols, some apply relocations, some build a CFG.
// The line counts are reported next to the timings precisely so a tool
// producing a fraction of the output is visible rather than looking fast.
// Every input is a THIN arm64e slice, so no tool is picking a different
// architecture out of a fat file, and every tool is given the flags that
// make it do the least work compatible with "disassemble this file".

import Foundation

/// One external disassembler and how to drive it.
struct Competitor {
    let name: String
    let launchPath: String
    /// Arguments, with `%FILE%` replaced by the input path and
    /// `%COUNT%` by the section's instruction count.
    let arguments: [String]
    /// What this tool does beyond decoding, so the number can be read.
    let note: String

    static func resolve(_ candidates: [String]) -> String? {
        for path in candidates where FileManager.default.isExecutableFile(atPath: path) {
            return path
        }
        return nil
    }
}

/// Result of timing one tool over one file.
struct CompetitorRun {
    let name: String
    let seconds: Double
    let outputLines: Int
    let outputBytes: Int
}

enum CompetitorBench {
    /// Every tool present on this machine, in a fixed order.
    static func available(irisPath: String) -> [Competitor] {
        var out: [Competitor] = [
            Competitor(
                name: "iris", launchPath: irisPath, arguments: ["%FILE%"],
                note: "symbols, function starts, symbolicated branch targets, data-in-code",
            ),
        ]
        if let p = Competitor.resolve([
            "/opt/homebrew/opt/llvm/bin/llvm-objdump", "/usr/local/opt/llvm/bin/llvm-objdump",
        ]) {
            out.append(Competitor(
                name: "llvm-objdump", launchPath: p,
                arguments: ["-d", "--no-show-raw-insn", "%FILE%"],
                note: "LLVM MC — the same engine iris is diffed against for correctness",
            ))
        }
        if let p = Competitor.resolve(["/usr/bin/objdump"]) {
            out.append(Competitor(
                name: "objdump(apple)", launchPath: p,
                arguments: ["-d", "--no-show-raw-insn", "%FILE%"],
                note: "Apple's LLVM-derived objdump",
            ))
        }
        if let p = Competitor.resolve(["/usr/bin/otool"]) {
            out.append(Competitor(
                name: "otool", launchPath: p, arguments: ["-tV", "%FILE%"],
                note: "Apple's classic disassembler, symbolicated",
            ))
        }
        if let p = Competitor.resolve(["/opt/homebrew/bin/rizin", "/usr/local/bin/rizin"]) {
            out.append(Competitor(
                name: "rizin", launchPath: p,
                arguments: [
                    "-q", "-e", "scr.color=0",
                    "-c", "s section..__TEXT.__text; pd %COUNT%", "%FILE%",
                ],
                // `pd <count>` rather than `pD <bytes>`: the latter is the
                // same disassembly with rizin's analysis annotations left
                // on, and it costs 85 s on a 3,847-instruction section
                // against 0.44 s here — comparing against that would be
                // measuring the annotations, not the disassembler.
                note: "reverse-engineering framework; loads the binary and symbolicates",
            ))
        }
        return out
    }

    /// Run one tool once, discarding output through a pipe we drain, so the
    /// measurement includes producing the text but not writing it to a
    /// terminal.
    /// Wall-clock ceiling for one invocation. A framework that analyses a
    /// binary before printing anything can take minutes on a large input;
    /// that is a real property of the tool, but it must be REPORTED rather
    /// than allowed to stall the battery.
    static let defaultDeadlineSeconds = 20.0

    private static func run(
        _ c: Competitor, file: String, words: Int, deadline: Double,
    ) -> CompetitorRun? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: c.launchPath)
        process.arguments = c.arguments.map {
            $0.replacingOccurrences(of: "%FILE%", with: file)
                .replacingOccurrences(of: "%COUNT%", with: String(words))
        }
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        var data = Data()
        let clock = ContinuousClock()
        let start = clock.now
        do { try process.run() } catch { return nil }
        let watchdog = DispatchWorkItem { if process.isRunning { process.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + deadline, execute: watchdog)
        defer { watchdog.cancel() }
        // Drain while it runs; a full pipe buffer would otherwise deadlock.
        let handle = pipe.fileHandleForReading
        while true {
            let chunk = handle.availableData
            if chunk.isEmpty { break }
            data.append(chunk)
        }
        // The drain above returns when the pipe closes, which is process
        // exit; the deadline is enforced by a watchdog that terminates a
        // tool still running past it.
        process.waitUntilExit()
        let duration = clock.now - start
        let comps = duration.components
        let seconds = Double(comps.seconds) + Double(comps.attoseconds) * 1e-18
        guard process.terminationStatus == 0 else { return nil }
        var lines = 0
        for byte in data where byte == 0x0A {
            lines += 1
        }
        return CompetitorRun(
            name: c.name, seconds: seconds, outputLines: lines, outputBytes: data.count,
        )
    }

    /// Median of `runs` timed executions, after one unrecorded warmup so the
    /// file is in page cache for every tool alike.
    static func measure(
        _ c: Competitor, file: String, words: Int, runs: Int, deadline: Double,
    ) -> CompetitorRun? {
        guard let warm = run(c, file: file, words: words, deadline: deadline) else { return nil }
        var seconds: [Double] = []
        seconds.reserveCapacity(runs)
        for _ in 0 ..< runs {
            guard let r = run(c, file: file, words: words, deadline: deadline) else { return nil }
            seconds.append(r.seconds)
        }
        let sorted = seconds.sorted()
        let median = sorted.count % 2 == 1
            ? sorted[sorted.count / 2]
            : (sorted[sorted.count / 2 - 1] + sorted[sorted.count / 2]) / 2
        return CompetitorRun(
            name: c.name, seconds: median,
            outputLines: warm.outputLines, outputBytes: warm.outputBytes,
        )
    }
}

/// Thin arm64/arm64e slices for the comparison.
///
/// A fat file makes every tool choose an architecture, and they do not all
/// choose the same one — `llvm-objdump` takes the x86_64 slice of a
/// universal binary by default, which would have it "disassembling" a
/// different instruction set than everything else. Extracting the slice
/// once removes the variable entirely.
enum ThinCorpus {
    static func prepare(_ paths: [String], into directory: String) -> [String] {
        let fm = FileManager.default
        try? fm.createDirectory(atPath: directory, withIntermediateDirectories: true)
        var out: [String] = []
        for path in paths {
            guard fm.isReadableFile(atPath: path) else { continue }
            let destination = directory + "/" + (path as NSString).lastPathComponent
            if extract(path, arch: "arm64e", to: destination)
                || extract(path, arch: "arm64", to: destination)
            {
                out.append(destination)
                continue
            }
            // Already thin: use it where it is.
            if MachO.text(at: path) != nil { out.append(path) }
        }
        return out
    }

    private static func extract(_ path: String, arch: String, to destination: String) -> Bool {
        guard FileManager.default.isExecutableFile(atPath: "/usr/bin/lipo") else { return false }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/lipo")
        p.arguments = [path, "-thin", arch, "-output", destination]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return false }
        p.waitUntilExit()
        return p.terminationStatus == 0 && MachO.text(at: destination) != nil
    }
}
