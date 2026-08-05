// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Workloads over real `__TEXT,__text`, and the allocation counters.
//
// Two things the synthetic battery could not answer. First, anything
// shaped by real code: operand density drives the operand buffer, and the
// synthetic mix is not representative of it. Second, allocation counts —
// a timing median on a busy machine moves by tens of percent between
// runs, while "mallocs per word" is the same number every time. When a
// timing question and a counting question disagree, the counter is the
// one that is not a sample.

import Foundation
import Iris

// MARK: - Allocation counting

#if canImport(Darwin)
    import Darwin

    /// Live heap blocks and bytes, from the default zone.
    ///
    /// Deltas across a workload that RETAINS its results measure what the
    /// workload allocated and kept — which is exactly the per-word storage
    /// question (records, operand buffer, rendered text). Transient churn
    /// that is freed again does not show here, and is not what these
    /// numbers claim to measure.
    func heapInUse() -> (blocks: UInt64, bytes: UInt64) {
        var stats = malloc_statistics_t()
        malloc_zone_statistics(malloc_default_zone(), &stats)
        return (UInt64(stats.blocks_in_use), UInt64(stats.size_in_use))
    }
#else
    func heapInUse() -> (blocks: UInt64, bytes: UInt64) {
        (0, 0)
    }
#endif

// MARK: - Real-binary decode

/// Bulk decode over real code: one stream per section, results retained
/// so the heap delta reports what a decoded binary actually costs.
func benchRealBulk(_ corpus: [RealText], config: BenchConfig) -> BenchResult {
    let totalWords = corpus.reduce(0) { $0 + $1.wordCount }
    return measure(
        name: "real-bulk", unit: "words/s", largerIsBetter: true, runs: config.runs,
        note: "\(corpus.count) shipped binaries, \(groupedInt(Double(totalWords))) words of real __TEXT,__text",
    ) {
        var streams: [InstructionStream] = []
        streams.reserveCapacity(corpus.count)
        let seconds = timed {
            for text in corpus {
                text.bytes.withUnsafeBufferPointer { raw in
                    streams.append(InstructionStream(
                        bytes: UnsafeRawBufferPointer(raw),
                        at: text.baseAddress,
                        features: text.features,
                    ))
                }
            }
        }
        blackhole(UInt64(streams.reduce(0) { $0 + $1.records.count }))
        return Double(totalWords) / seconds
    }
}

/// Operand density and retained footprint per decoded word, over real
/// code. This is the number the operand reserve is tuned against.
func benchRealFootprint(_ corpus: [RealText]) -> [BenchResult] {
    var streams: [InstructionStream] = []
    streams.reserveCapacity(corpus.count)
    let before = heapInUse()
    for text in corpus {
        text.bytes.withUnsafeBufferPointer { raw in
            streams.append(InstructionStream(
                bytes: UnsafeRawBufferPointer(raw),
                at: text.baseAddress,
                features: text.features,
            ))
        }
    }
    let after = heapInUse()
    let words = streams.reduce(0) { $0 + $1.records.count }
    let operands = streams.reduce(0) { $0 + $1.operands.count }
    let bytes = Double(after.bytes &- before.bytes)
    blackhole(UInt64(words))

    return [
        BenchResult(
            name: "real-operands-per-word", unit: "operands", largerIsBetter: false,
            runs: [Double(operands) / Double(words)],
            note: "structural: what the operand-buffer reserve is sized against",
        ),
        BenchResult(
            name: "real-retained-bytes-per-word", unit: "bytes", largerIsBetter: false,
            runs: [bytes / Double(words)],
            note: "live-heap delta across construction of \(groupedInt(Double(words))) words, streams retained",
        ),
    ]
}

// MARK: - Text over real code

/// Whole-stream listing through the public byte path, plus the
/// per-instruction `String` entry point over the same records, so the two
/// text shapes are timed on identical input in one binary.
func benchRealText(_ corpus: [RealText], config: BenchConfig) -> [BenchResult] {
    var streams: [InstructionStream] = []
    for text in corpus {
        text.bytes.withUnsafeBufferPointer { raw in
            streams.append(InstructionStream(
                bytes: UnsafeRawBufferPointer(raw),
                at: text.baseAddress,
                features: text.features,
            ))
        }
    }
    let words = streams.reduce(0) { $0 + $1.records.count }

    let listing = measure(
        name: "real-listing", unit: "instr/s", largerIsBetter: true, runs: config.runs,
        note: "DisassemblyListing.render over every record of every section",
    ) {
        var bytes = 0
        let seconds = timed {
            for stream in streams {
                bytes &+= DisassemblyListing.render(stream).utf8.count
            }
        }
        blackhole(UInt64(bytes))
        return Double(words) / seconds
    }

    let perInstruction = measure(
        name: "real-text-each", unit: "instr/s", largerIsBetter: true, runs: config.runs,
        note: "Instruction.text per record — one String per instruction, same records",
    ) {
        var bytes = 0
        let seconds = timed {
            for stream in streams {
                for instruction in stream {
                    bytes &+= instruction.text.utf8.count
                }
            }
        }
        blackhole(UInt64(bytes))
        return Double(words) / seconds
    }

    // Allocation cost of one whole listing, counted rather than timed.
    let before = heapInUse()
    var held: [String] = []
    held.reserveCapacity(streams.count)
    for stream in streams {
        held.append(DisassemblyListing.render(stream))
    }
    let after = heapInUse()
    blackhole(UInt64(held.reduce(0) { $0 + $1.utf8.count }))
    let listingBytes = BenchResult(
        name: "real-listing-bytes-per-word", unit: "bytes", largerIsBetter: false,
        runs: [Double(after.bytes &- before.bytes) / Double(words)],
        note: "live-heap delta for the rendered listing text, retained",
    )

    return [listing, perInstruction, listingBytes]
}

/// The semantic column — the layer nothing else prints, and which nothing
/// in the battery measured. Reads every record's semantic fields off real
/// code.
func benchRealSemantics(_ corpus: [RealText], config: BenchConfig) -> BenchResult {
    var streams: [InstructionStream] = []
    for text in corpus {
        text.bytes.withUnsafeBufferPointer { raw in
            streams.append(InstructionStream(
                bytes: UnsafeRawBufferPointer(raw),
                at: text.baseAddress,
                features: text.features,
            ))
        }
    }
    let words = streams.reduce(0) { $0 + $1.records.count }
    return measure(
        name: "real-semantics", unit: "instr/s", largerIsBetter: true, runs: config.runs,
        note: "reads/writes masks, branch class, memory access + ordering, flag effect per record",
    ) {
        var fold: UInt64 = 0
        let seconds = timed {
            for stream in streams {
                for instruction in stream {
                    fold &+= instruction.semanticReads.mask
                    fold &+= instruction.semanticWrites.mask
                    fold &+= UInt64(instruction.branchClass.rawValue)
                    fold &+= UInt64(instruction.memoryAccess.rawValue)
                    fold &+= UInt64(instruction.memoryOrdering.rawValue)
                    fold &+= UInt64(instruction.flagEffect.rawValue)
                }
            }
        }
        blackhole(fold)
        return Double(words) / seconds
    }
}
