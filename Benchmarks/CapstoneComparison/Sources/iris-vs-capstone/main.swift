// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// iris-vs-capstone — same-buffer decode-throughput comparison between
// Iris and Capstone v5 (via the capstone-swift `next` bindings; the
// hot loops call the C engine directly through `Ccapstone` so Capstone
// is measured at its fastest, not through binding overhead).
//
// WHAT IS COMPARED (and what is not — README-quotable):
//
// - Same deterministic buffer for every contender (byte-identical to
//   the iris-bench recipe: 3:1 llvm-mc-verified prologue pattern :
//   SplitMix64 random words; ≈84% defined).
// - `capstone-text`: cs_disasm_iter, detail OFF, SKIPDATA ON (4-byte
//   steps on AArch64 — undecodable words become `.byte` pseudo-insns,
//   the closest analogue of Iris's honest-UNDEFINED `.long` records).
//   Output: mnemonic + op_str text per instruction. No semantics.
// - `capstone-detail`: the same loop with detail ON — operands,
//   register reads/writes, groups. This is Capstone's closest
//   configuration to what Iris ALWAYS computes; Capstone documents
//   detail mode as substantially slower and OFF by default.
// - `iris-stream`: InstructionStream construction. Records + operands +
//   full semantics (register sets, branch class, memory class, flag
//   effects) are always on — there is no reduced mode to toggle. Text
//   is lazy and NOT rendered here.
// - `iris-stream-text`: construction PLUS `.text` rendered for every
//   record — output-parity with `capstone-text` (which always renders),
//   while still carrying full semantics Capstone-text does not produce.
// - `bindings-probe`: capstone-swift's high-level `disassemble()`
//   (cs_disasm + Swift object materialization) over a 1 MiB slice —
//   quantifies what the C-direct loops deliberately bypass.
//
// Both engines run single-threaded (a Capstone handle is not
// thread-safe; Iris's parallel-by-chunks figure lives in iris-bench).
// Methodology: 1 unrecorded warmup + N recorded runs, median reported.
// Self-check before timing: the 12 prologue words must decode to the
// expected mnemonic sequence on BOTH engines (catches a libcapstone
// version/ABI mismatch loudly, never silently).

import Capstone
import Ccapstone
import Foundation
import Iris

// MARK: - Shared helpers (deliberate copies of the iris-bench recipe —

// two standalone packages; constants must stay byte-identical)

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

let prologuePattern: [UInt32] = [
    0xA9BF_7BFD, 0x9100_03FD, 0xD101_03FF, 0x9000_0008,
    0x9104_0108, 0xF940_0100, 0x9400_0000, 0x7100_001F,
    0x5400_0081, 0xA8C1_7BFD, 0x9101_03FF, 0xD65F_03C0,
]

func makeMixedBuffer(byteCount: Int, seed: UInt64) -> UnsafeRawBufferPointer {
    let wordCount = byteCount / 4
    let raw = UnsafeMutableRawBufferPointer.allocate(byteCount: wordCount * 4, alignment: 4)
    var rng = SplitMix64(seed: seed)
    var patternCursor = 0
    let words = raw.bindMemory(to: UInt32.self)
    for i in 0 ..< wordCount {
        if i % 4 == 3 {
            words[i] = UInt32(truncatingIfNeeded: rng.next()).littleEndian
        } else {
            words[i] = prologuePattern[patternCursor].littleEndian
            patternCursor = (patternCursor + 1) % prologuePattern.count
        }
    }
    return UnsafeRawBufferPointer(raw)
}

@inline(never)
func blackhole(_ value: UInt64) {
    Sink.value ^= value
}

enum Sink {
    nonisolated(unsafe) static var value: UInt64 = 0
}

func timed(_ body: () -> Void) -> Double {
    let clock = ContinuousClock()
    let duration = clock.measure(body)
    let comps = duration.components
    return Double(comps.seconds) + Double(comps.attoseconds) * 1e-18
}

struct RunStats {
    let name: String
    let unit: String
    let runs: [Double]
    let note: String
    var median: Double {
        let s = runs.sorted()
        let mid = s.count / 2
        return s.count % 2 == 1 ? s[mid] : (s[mid - 1] + s[mid]) / 2
    }

    var spread: Double {
        guard let lo = runs.min(), let hi = runs.max(), median != 0 else { return 0 }
        return (hi - lo) / median
    }
}

func measureRuns(name: String, unit: String, runs: Int, note: String, body: () -> Double) -> RunStats {
    _ = body()
    var recorded: [Double] = []
    for _ in 0 ..< runs {
        recorded.append(body())
    }
    return RunStats(name: name, unit: unit, runs: recorded, note: note)
}

func die(_ message: String) -> Never {
    FileHandle.standardError.write(Data("iris-vs-capstone: \(message)\n".utf8))
    exit(2)
}

// MARK: - Options

var bufferMiB = 64
var runCount = 3
var seed: UInt64 = 0xC_0FFE_E001_5BAD
var jsonOutput = false

var argIterator = CommandLine.arguments.dropFirst().makeIterator()
while let arg = argIterator.next() {
    switch arg {
    case "--json":
        jsonOutput = true
    case "--mib":
        guard let v = argIterator.next(), let n = Int(v), n >= 1 else { die("--mib: invalid value") }
        bufferMiB = n
    case "--runs":
        guard let v = argIterator.next(), let n = Int(v), n >= 1 else { die("--runs: invalid value") }
        runCount = n
    case "--seed":
        guard let v = argIterator.next() else { die("--seed requires a value") }
        let parsed = v.hasPrefix("0x") ? UInt64(v.dropFirst(2), radix: 16) : UInt64(v)
        guard let s = parsed else { die("--seed: invalid value '\(v)'") }
        seed = s
    default:
        die("unknown argument '\(arg)' (options: --json --mib N --runs N --seed VALUE)")
    }
}

// MARK: - Capstone session helpers (C engine, direct)

func openCapstoneHandle(detail: Bool) -> csh {
    var handle: csh = 0
    let err = cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle)
    guard err == CS_ERR_OK else { die("cs_open failed: \(err)") }
    guard cs_option(handle, CS_OPT_SKIPDATA, numericCast(CS_OPT_ON.rawValue)) == CS_ERR_OK else {
        die("cs_option(SKIPDATA) failed")
    }
    if detail {
        guard cs_option(handle, CS_OPT_DETAIL, numericCast(CS_OPT_ON.rawValue)) == CS_ERR_OK else {
            die("cs_option(DETAIL) failed")
        }
    }
    return handle
}

/// One full-buffer cs_disasm_iter pass; returns (instructions, fold).
func capstonePass(handle: csh, buffer: UnsafeRawBufferPointer, baseAddress: UInt64, detail: Bool) -> (UInt64, UInt64) {
    guard let insn = cs_malloc(handle) else { die("cs_malloc failed") }
    defer {
        cs_free(insn, 1)
    }
    var code = buffer.baseAddress!.assumingMemoryBound(to: UInt8.self) as UnsafePointer<UInt8>?
    var size = buffer.count
    var address = baseAddress
    var count: UInt64 = 0
    var fold: UInt64 = 0
    while cs_disasm_iter(handle, &code, &size, &address, insn) {
        count &+= 1
        fold &+= UInt64(insn.pointee.id) &+ UInt64(insn.pointee.size)
        if detail, let d = insn.pointee.detail {
            fold &+= UInt64(d.pointee.arm64.op_count)
            fold &+= UInt64(d.pointee.regs_read_count) &+ UInt64(d.pointee.regs_write_count)
        }
    }
    return (count, fold)
}

// MARK: - Self-check (fail-loud version/ABI gate before any timing)

let capstoneVersionRaw = cs_version(nil, nil)
let capstoneMajor = Int(capstoneVersionRaw >> 8)
let capstoneMinor = Int(capstoneVersionRaw & 0xFF)
guard capstoneMajor == 5 else {
    die("libcapstone \(capstoneMajor).\(capstoneMinor) found; this harness pins the v5 detail ABI (capstone-swift `next`). Install capstone 5.x.")
}

let expectedMnemonics = ["stp", "mov", "sub", "adrp", "add", "ldr", "bl", "cmp", "b.ne", "ldp", "add", "ret"]
do {
    let checkHandle = openCapstoneHandle(detail: false)
    defer { var h = checkHandle; cs_close(&h) }
    var bytes: [UInt8] = []
    for word in prologuePattern {
        bytes.append(contentsOf: withUnsafeBytes(of: word.littleEndian, Array.init))
    }
    var got: [String] = []
    bytes.withUnsafeBufferPointer { buf in
        guard let insn = cs_malloc(checkHandle) else { die("cs_malloc failed (self-check)") }
        defer { cs_free(insn, 1) }
        var code: UnsafePointer<UInt8>? = buf.baseAddress
        var size = buf.count
        var address: UInt64 = 0
        while cs_disasm_iter(checkHandle, &code, &size, &address, insn) {
            got.append(withUnsafeBytes(of: insn.pointee.mnemonic) { raw in
                String(decoding: raw.prefix(while: { $0 != 0 }), as: UTF8.self)
            })
        }
    }
    guard got == expectedMnemonics else {
        die("capstone self-check failed: got \(got), expected \(expectedMnemonics) — libcapstone/bindings mismatch")
    }
    let irisGot = prologuePattern.map { Iris.decode($0).mnemonic.name }
    let irisExpected = expectedMnemonics.map { $0 == "b.ne" ? "b.cond" : $0 }
    guard irisGot == irisExpected else {
        die("iris self-check failed: got \(irisGot)")
    }
}

// MARK: - The comparison

let baseAddress: UInt64 = 0x1_0000_0000
let byteCount = bufferMiB * 1024 * 1024
let buffer = makeMixedBuffer(byteCount: byteCount, seed: seed)
let wordCount = buffer.count / 4

@MainActor func progress(_ s: String) {
    if jsonOutput { FileHandle.standardError.write(Data((s + "\n").utf8)) } else { print(s) }
}

progress("iris-vs-capstone: libcapstone \(capstoneMajor).\(capstoneMinor), buffer \(bufferMiB) MiB, seed 0x\(String(seed, radix: 16)), runs \(runCount), single-thread")

var stats: [RunStats] = []

progress("capstone-text (detail off, SKIPDATA on)…")
do {
    let handle = openCapstoneHandle(detail: false)
    defer { var h = handle; cs_close(&h) }
    stats.append(measureRuns(
        name: "capstone-text", unit: "words/s", runs: runCount,
        note: "cs_disasm_iter, detail OFF, SKIPDATA ON; text always rendered by the engine",
    ) {
        var fold: UInt64 = 0
        let seconds = timed {
            let (count, f) = capstonePass(handle: handle, buffer: buffer, baseAddress: baseAddress, detail: false)
            fold = count &+ f
        }
        blackhole(fold)
        return Double(wordCount) / seconds
    })
}

progress("capstone-detail (detail on, SKIPDATA on)…")
do {
    let handle = openCapstoneHandle(detail: true)
    defer { var h = handle; cs_close(&h) }
    stats.append(measureRuns(
        name: "capstone-detail", unit: "words/s", runs: runCount,
        note: "cs_disasm_iter, detail ON (operands + reg reads/writes + groups) — Capstone's closest configuration to Iris's always-on semantics",
    ) {
        var fold: UInt64 = 0
        let seconds = timed {
            let (count, f) = capstonePass(handle: handle, buffer: buffer, baseAddress: baseAddress, detail: true)
            fold = count &+ f
        }
        blackhole(fold)
        return Double(wordCount) / seconds
    })
}

progress("iris-stream (full semantics, no text)…")
stats.append(measureRuns(
    name: "iris-stream", unit: "words/s", runs: runCount,
    note: "InstructionStream construction; operands + register sets + branch class + memory class + flag effects always on; text lazy, not rendered",
) {
    var fold: UInt64 = 0
    let seconds = timed {
        let stream = InstructionStream(bytes: buffer, at: baseAddress, features: .arm64e)
        fold = UInt64(stream.records.count) &+ UInt64(stream.operands.count)
    }
    blackhole(fold)
    return Double(wordCount) / seconds
})

progress("iris-stream-text (full semantics + text for every record)…")
stats.append(measureRuns(
    name: "iris-stream-text", unit: "words/s", runs: runCount,
    note: "InstructionStream construction + .text rendered for EVERY record — output-parity with capstone-text, still carrying full semantics",
) {
    var fold: UInt64 = 0
    let seconds = timed {
        let stream = InstructionStream(bytes: buffer, at: baseAddress, features: .arm64e)
        var textFold: UInt64 = 0
        for instruction in stream {
            textFold &+= UInt64(instruction.text.utf8.count)
        }
        fold = UInt64(stream.records.count) &+ textFold
    }
    blackhole(fold)
    return Double(wordCount) / seconds
})

progress("bindings-probe (capstone-swift disassemble, 1 MiB slice)…")
do {
    let probeBytes = 1024 * 1024
    let capstone = try Capstone(arch: .arm64, mode: Mode.endian.little)
    try capstone.set(option: .skipDataEnabled(true))
    let probeData = Data(bytes: buffer.baseAddress!, count: probeBytes)
    stats.append(measureRuns(
        name: "capstone-bindings-probe", unit: "words/s", runs: runCount,
        note: "capstone-swift high-level disassemble() incl. Swift object materialization, 1 MiB slice (quantifies binding overhead the C-direct loops bypass)",
    ) {
        var fold: UInt64 = 0
        let seconds = timed {
            let instructions: [Arm64Instruction] = (try? capstone.disassemble(code: probeData, address: baseAddress)) ?? []
            fold = UInt64(instructions.count)
        }
        blackhole(fold)
        return Double(probeBytes / 4) / seconds
    })
} catch {
    progress("bindings-probe SKIPPED: \(error)")
}

// MARK: - Output

func grouped(_ value: Double) -> String {
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

if jsonOutput {
    var lines = ["{"]
    lines.append("  \"schema\": \"iris-vs-capstone/1\",")
    lines.append("  \"libcapstone\": \"\(capstoneMajor).\(capstoneMinor)\",")
    lines.append("  \"bufferBytes\": \(byteCount),")
    lines.append("  \"seed\": \"0x\(String(seed, radix: 16))\",")
    lines.append("  \"runs\": \(runCount),")
    lines.append("  \"results\": [")
    lines.append(stats.map { s in
        "    {\"name\": \"\(s.name)\", \"unit\": \"\(s.unit)\", \"runs\": [\(s.runs.map { String($0) }.joined(separator: ", "))], \"median\": \(s.median), \"spread\": \(s.spread), \"note\": \"\(s.note)\"}"
    }.joined(separator: ",\n"))
    lines.append("  ]")
    lines.append("}")
    print(lines.joined(separator: "\n"))
} else {
    print("\nresults (median over \(runCount) runs, 1 warmup, single-thread):")
    for s in stats {
        print("  \(s.name): median \(grouped(s.median)) \(s.unit) (spread \(String(format: "%.1f", s.spread * 100))%)")
        print("    \(s.note)")
    }
}
