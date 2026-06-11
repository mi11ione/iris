// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// The measured workloads. Buffer recipe (deterministic, documented):
// words are generated 3:1 pattern:random — three consecutive words from
// a cycling 12-word real-function template (each word verified against
// llvm-mc 22.1.4: stp/mov/sub/adrp/add/ldr/bl/cmp/b.ne/ldp/add/ret),
// then one SplitMix64 word from the run's seed. This mirrors the
// implementation-gate harness recipe ("real-prologue pattern
// interleaved 3:1 with seeded random words") at a larger default size.
// The random quarter exercises the undefined/exotic paths (≈35% of
// uniform words decode defined per the exhaustive 2^32 census), the
// pattern quarters exercise
// hot real-code paths; the blend decodes ≈84% defined. Features:
// `.arm64e` throughout (the parity and exhaustive instruments'
// configuration).

import Foundation
import Iris

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

// MARK: - Deterministic buffer

/// The 12-word function template (little-endian encodings; each verified
/// to round-trip through llvm-mc -triple=arm64-apple-macos).
let prologuePattern: [UInt32] = [
    0xA9BF_7BFD, // stp x29, x30, [sp, #-16]!
    0x9100_03FD, // mov x29, sp
    0xD101_03FF, // sub sp, sp, #64
    0x9000_0008, // adrp x8, #0
    0x9104_0108, // add x8, x8, #256
    0xF940_0100, // ldr x0, [x8]
    0x9400_0000, // bl #0
    0x7100_001F, // cmp w0, #0
    0x5400_0081, // b.ne #16
    0xA8C1_7BFD, // ldp x29, x30, [sp], #16
    0x9101_03FF, // add sp, sp, #64
    0xD65F_03C0, // ret
]

/// Fill an allocation with the deterministic mixed words: 3 pattern
/// words then 1 random word, repeating. The allocation outlives every
/// benchmark (freed at process exit), so chunk pointers handed to
/// concurrent tasks stay valid without closure-scoped pinning.
func makeMixedBuffer(byteCount: Int, seed: UInt64) -> UnsafeRawBufferPointer {
    let wordCount = byteCount / 4
    let raw = UnsafeMutableRawBufferPointer.allocate(byteCount: wordCount * 4, alignment: 4)
    var rng = SplitMix64(seed: seed)
    var patternCursor = 0
    let words = raw.bindMemory(to: UInt32.self)
    for i in 0 ..< wordCount {
        let word: UInt32
        if i % 4 == 3 {
            word = UInt32(truncatingIfNeeded: rng.next())
        } else {
            word = prologuePattern[patternCursor]
            patternCursor = (patternCursor + 1) % prologuePattern.count
        }
        words[i] = word.littleEndian
    }
    return UnsafeRawBufferPointer(raw)
}

// MARK: - Shared benchmark configuration

struct BenchConfig {
    var bufferBytes: Int = 256 * 1024 * 1024
    var seed: UInt64 = 0xC_0FFE_E001_5BAD
    var runs: Int = 5
    var lookups: Int = 10_000_000
    var tier0Ops: Int = 10_000_000
    var textStride: Int = 16
    var baseAddress: UInt64 = 0x1_0000_0000
    var features: Features = .arm64e
    var json: Bool = false
    var baselinePath: String?

    var configPairs: [(String, String)] {
        [
            ("bufferBytes", String(bufferBytes)),
            ("seed", "0x" + String(seed, radix: 16)),
            ("runs", String(runs)),
            ("lookups", String(lookups)),
            ("tier0Ops", String(tier0Ops)),
            ("textStride", String(textStride)),
            ("baseAddress", "0x" + String(baseAddress, radix: 16)),
            ("features", "arm64e"),
            ("recipe", "3:1 prologue-pattern:SplitMix64, 12-word llvm-mc-verified template"),
        ]
    }
}

// MARK: - Workloads

/// Bulk decode, single thread: one `InstructionStream` over the whole
/// buffer per run; metric = words / wall seconds.
func benchBulkSingle(buffer: UnsafeRawBufferPointer, config: BenchConfig) -> BenchResult {
    let wordCount = buffer.count / 4
    return measure(
        name: "bulk-single", unit: "words/s", largerIsBetter: true, runs: config.runs,
        note: "one InstructionStream over the full \(buffer.count / (1024 * 1024)) MiB buffer; records+operands+semantics committed, text not rendered",
    ) {
        var fold: UInt64 = 0
        let seconds = timed {
            let stream = InstructionStream(
                bytes: buffer, at: config.baseAddress, features: config.features,
            )
            fold = UInt64(stream.records.count) &+ UInt64(stream.operands.count)
        }
        blackhole(fold)
        return Double(wordCount) / seconds
    }
}

/// Bulk decode, parallel by chunks: the buffer split into `jobs`
/// contiguous word-aligned chunks, one `InstructionStream` per chunk
/// constructed concurrently in a TaskGroup; metric = total words / wall
/// seconds. Chunk seams are word-aligned, so per-word decode results
/// are identical to the single-thread pass (decode is per-word pure).
func benchBulkParallel(buffer: UnsafeRawBufferPointer, config: BenchConfig, jobs: Int) async -> BenchResult {
    let wordCount = buffer.count / 4
    // Raw buffer pointers are not Sendable; tasks receive the chunk as
    // (bitPattern, byteCount) integers. The allocation is process-lived.
    let base = UInt(bitPattern: buffer.baseAddress)
    let wordsPerChunk = (wordCount + jobs - 1) / jobs
    let baseAddress = config.baseAddress
    let features = config.features
    return await measure(
        name: "bulk-parallel", unit: "words/s", largerIsBetter: true, runs: config.runs,
        note: "\(jobs) word-aligned chunks decoded concurrently (TaskGroup), one stream each",
    ) {
        var fold: UInt64 = 0
        let seconds = await timed {
            let total = await withTaskGroup(of: UInt64.self) { group -> UInt64 in
                var startWord = 0
                while startWord < wordCount {
                    let chunkWords = Swift.min(wordsPerChunk, wordCount - startWord)
                    let chunkBitPattern = base + UInt(startWord * 4)
                    let chunkAddress = baseAddress &+ UInt64(startWord * 4)
                    group.addTask {
                        let chunk = UnsafeRawBufferPointer(
                            start: UnsafeRawPointer(bitPattern: chunkBitPattern),
                            count: chunkWords * 4,
                        )
                        let stream = InstructionStream(
                            bytes: chunk, at: chunkAddress, features: features,
                        )
                        return UInt64(stream.records.count)
                    }
                    startWord += chunkWords
                }
                var sum: UInt64 = 0
                for await part in group {
                    sum &+= part
                }
                return sum
            }
            fold = total
        }
        blackhole(fold)
        if fold != UInt64(wordCount) {
            FileHandle.standardError.write(Data("iris-bench: FATAL — parallel chunks decoded \(fold) records, expected \(wordCount)\n".utf8))
            exit(70)
        }
        return Double(wordCount) / seconds
    }
}

/// Tier-0 `decode(_:at:features:)` latency: `tier0Ops` single-word
/// decodes over a pool of the buffer's leading words (cycled), folding
/// mnemonic + operand count; metric = ns/op.
func benchTier0(buffer: UnsafeRawBufferPointer, config: BenchConfig) -> BenchResult {
    let wordCount = buffer.count / 4
    var poolCount = 1
    while poolCount * 2 <= Swift.min(wordCount, 1 << 20) {
        poolCount *= 2
    }
    var words = [UInt32](repeating: 0, count: poolCount)
    let src = buffer.bindMemory(to: UInt32.self)
    for i in 0 ..< poolCount {
        words[i] = UInt32(littleEndian: src[i])
    }
    let mask = poolCount - 1
    let ops = config.tier0Ops
    let features = config.features
    return measure(
        name: "tier0-latency", unit: "ns/op", largerIsBetter: false, runs: config.runs,
        note: "\(ops) decode() calls over a \(poolCount)-word pool; includes Instruction materialization",
    ) {
        var fold: UInt64 = 0
        let seconds = timed {
            for i in 0 ..< ops {
                let instruction = decode(words[i & mask], at: 0, features: features)
                fold &+= UInt64(instruction.mnemonic.rawValue) &+ UInt64(instruction.operands.count)
            }
        }
        blackhole(fold)
        return seconds * 1e9 / Double(ops)
    }
}

/// Precompute the deterministic random word-aligned lookup addresses
/// shared by the view and raw lookup benchmarks.
func makeLookupAddresses(count: Int, wordCount: Int, baseAddress: UInt64, seed: UInt64) -> [UInt64] {
    var rng = SplitMix64(seed: seed ^ 0xA5A5_A5A5)
    var addresses = [UInt64](repeating: 0, count: count)
    for i in 0 ..< count {
        let word = Int(rng.next() % UInt64(wordCount))
        addresses[i] = baseAddress &+ UInt64(word * 4)
    }
    return addresses
}

/// `instruction(at:)` lookup latency through the ergonomic view
/// (Instruction formation includes the operand-view ARC retain).
func benchLookupView(stream: InstructionStream, addresses: [UInt64], config: BenchConfig) -> BenchResult {
    measure(
        name: "lookup-view", unit: "ns/op", largerIsBetter: false, runs: config.runs,
        note: "\(addresses.count) random word-aligned instruction(at:) calls; folds encoding",
    ) {
        var fold: UInt64 = 0
        let seconds = timed {
            for address in addresses {
                if let instruction = stream.instruction(at: address) {
                    fold &+= UInt64(instruction.encoding)
                }
            }
        }
        blackhole(fold)
        return seconds * 1e9 / Double(addresses.count)
    }
}

/// Raw-record lookup latency: the documented hot-path alternative —
/// modular delta arithmetic + `records[index]`, the same guards
/// `instruction(at:)` performs, no Instruction view formed.
func benchLookupRaw(stream: InstructionStream, addresses: [UInt64], config: BenchConfig) -> BenchResult {
    let records = stream.records
    let baseAddress = stream.baseAddress
    let byteCount = stream.byteCount
    return measure(
        name: "lookup-raw", unit: "ns/op", largerIsBetter: false, runs: config.runs,
        note: "same addresses via records[] index arithmetic (guards retained, no view formed)",
    ) {
        var fold: UInt64 = 0
        let seconds = timed {
            for address in addresses {
                let delta = address &- baseAddress
                if delta < byteCount, delta % 4 == 0 {
                    let index = Int(delta / 4)
                    if index < records.count {
                        fold &+= UInt64(records[index].encoding)
                    }
                }
            }
        }
        blackhole(fold)
        return seconds * 1e9 / Double(addresses.count)
    }
}

/// Full-field walk through the Instruction view: `for instruction in
/// stream`, touching every semantic field; metric = ns/element.
func benchWalkView(stream: InstructionStream, config: BenchConfig) -> BenchResult {
    let count = stream.count
    return measure(
        name: "walk-view", unit: "ns/elem", largerIsBetter: false, runs: config.runs,
        note: "full collection walk touching address/encoding/mnemonic/reads/writes/branchClass/access/ordering/flags/category/operandCount",
    ) {
        var fold: UInt64 = 0
        let seconds = timed {
            for instruction in stream {
                fold &+= instruction.address
                fold &+= UInt64(instruction.encoding)
                fold &+= UInt64(instruction.mnemonic.rawValue)
                fold &+= instruction.semanticReads.mask
                fold &+= instruction.semanticWrites.mask
                fold &+= UInt64(instruction.branchClass.rawValue)
                fold &+= UInt64(instruction.memoryAccess.rawValue)
                fold &+= UInt64(instruction.memoryOrdering.rawValue)
                fold &+= UInt64(instruction.flagEffect.rawValue)
                fold &+= UInt64(instruction.category.rawValue)
                fold &+= UInt64(instruction.operands.count)
            }
        }
        blackhole(fold)
        return seconds * 1e9 / Double(count)
    }
}

/// The same full-field walk over raw records (`stream.records`), the
/// zero-view baseline.
func benchWalkRecord(stream: InstructionStream, config: BenchConfig) -> BenchResult {
    let records = stream.records
    return measure(
        name: "walk-record", unit: "ns/elem", largerIsBetter: false, runs: config.runs,
        note: "same field walk over stream.records (no Instruction view)",
    ) {
        var fold: UInt64 = 0
        let seconds = timed {
            for record in records {
                fold &+= record.address
                fold &+= UInt64(record.encoding)
                fold &+= UInt64(record.mnemonic.rawValue)
                fold &+= record.semanticReads.mask
                fold &+= record.semanticWrites.mask
                fold &+= UInt64(record.branchClass.rawValue)
                fold &+= UInt64(record.memoryAccess.rawValue)
                fold &+= UInt64(record.memoryOrdering.rawValue)
                fold &+= UInt64(record.flagEffect.rawValue)
                fold &+= UInt64(record.category.rawValue)
                fold &+= UInt64(record.operandCount)
            }
        }
        blackhole(fold)
        return seconds * 1e9 / Double(records.count)
    }
}

/// The shipped session API: `instruction(at:)` lookup latency inside
/// one `withSession` scope — the production form of the experiment
/// prototype's `exp-lookup-borrowed-session` (same addresses, same
/// encoding + operand-count fold), so the two are directly comparable.
func benchSessionLookup(stream: InstructionStream, addresses: [UInt64], config: BenchConfig) -> BenchResult {
    measure(
        name: "session-lookup", unit: "ns/op", largerIsBetter: false, runs: config.runs,
        note: "withSession + session.instruction(at:); folds encoding + operand count (exp-lookup-borrowed-session shape)",
    ) {
        var fold: UInt64 = 0
        let seconds = timed {
            stream.withSession { session in
                for address in addresses {
                    if let view = session.instruction(at: address) {
                        fold &+= UInt64(view.record.encoding) &+ UInt64(view.operands.count)
                    }
                }
            }
        }
        blackhole(fold)
        return seconds * 1e9 / Double(addresses.count)
    }
}

/// The shipped session API: full walk through `for view in
/// session`, dereferencing every operand — the production form of the
/// experiment prototype's `exp-walk-borrowed-session` (same fields,
/// same operandTag fold).
func benchSessionWalk(stream: InstructionStream, config: BenchConfig) -> BenchResult {
    measure(
        name: "session-walk", unit: "ns/elem", largerIsBetter: false, runs: config.runs,
        note: "for view in session — record fields + operandTag over every operand (exp-walk-borrowed-session shape)",
    ) {
        var fold: UInt64 = 0
        let seconds = timed {
            stream.withSession { session in
                for view in session {
                    fold &+= UInt64(view.record.encoding)
                    fold &+= UInt64(view.record.mnemonic.rawValue)
                    fold &+= view.record.semanticReads.mask
                    for op in view.operands {
                        fold &+= operandTag(op)
                    }
                }
            }
        }
        blackhole(fold)
        return seconds * 1e9 / Double(stream.count)
    }
}

/// Text rendering throughput: `.text` for every `textStride`-th record
/// across the whole stream (mixed ≈84% defined / 16% `.long` sentinel);
/// metric = rendered instructions / second.
func benchText(stream: InstructionStream, config: BenchConfig) -> BenchResult {
    let sampleCount = (stream.count + config.textStride - 1) / config.textStride
    return measure(
        name: "text-throughput", unit: "instr/s", largerIsBetter: true, runs: config.runs,
        note: "every \(config.textStride)th record (\(sampleCount) renders) across the full stream; folds utf8 length",
    ) {
        var fold: UInt64 = 0
        let seconds = timed {
            var i = 0
            while i < stream.count {
                fold &+= UInt64(stream[i].text.utf8.count)
                i += config.textStride
            }
        }
        blackhole(fold)
        return seconds > 0 ? Double(sampleCount) / seconds : 0
    }
}

/// Stream-construction memory high-water: `ru_maxrss` before and after
/// one construction. CAVEATS (also in Benchmarks/README.md): peak RSS is
/// process-lifetime MONOTONE, so the delta is meaningful only when this
/// runs before anything larger (the `all` battery orders it first,
/// right after buffer generation); the figure includes allocator slack
/// and is a ceiling on the stream's true footprint, not a byte-exact
/// size. Single run by design — a second construction inside one
/// process cannot raise the high-water mark again.
func benchMemory(buffer: UnsafeRawBufferPointer, config: BenchConfig) -> BenchResult {
    let before = peakRSSBytes()
    var foldValue: UInt64 = 0
    let seconds = timed {
        let stream = InstructionStream(
            bytes: buffer, at: config.baseAddress, features: config.features,
        )
        foldValue = UInt64(stream.records.count) &+ UInt64(stream.operands.count)
    }
    blackhole(foldValue)
    let after = peakRSSBytes()
    let delta = after >= before ? after - before : 0
    let wordCount = buffer.count / 4
    let bytesPerWord = Double(delta) / Double(wordCount)
    return BenchResult(
        name: "memory-highwater", unit: "bytes", largerIsBetter: false,
        runs: [Double(delta)],
        note: "peak-RSS delta across one construction (monotone ru_maxrss; ceiling, not exact); "
            + "\(String(format: "%.1f", bytesPerWord)) bytes/word over \(wordCount) words; "
            + "construction \(String(format: "%.2f", seconds))s; before=\(before) after=\(after)",
    )
}
