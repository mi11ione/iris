// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// The borrowing-view experiment (decide-with-evidence; the public
// library API is not changed by this harness). The original
// implementation-gate measurements found that
// `instruction(at:)`'s ~40 ns is dominated by the Instruction/Operands
// view-formation ARC retain (~32 ns over the 7.69 ns raw-record path)
// and deferred the question: would a retain-free borrowed view be
// worth an API change? This file prototypes the candidate shapes
// OUTSIDE the library, over public API only:
//
// 1. `BorrowedInstruction` — a trivial struct (40-byte record copy +
//    `UnsafeBufferPointer<Operand>` slice). Formation performs zero ARC.
//    Two driving shapes are measured: a session scope that pins the
//    stream's arrays once around many lookups (the
//    `withInstructionSession { }` candidate), and a per-call pin (the
//    `withInstruction(at:) { }` candidate).
// 2. A `Span`-based session (`Array.span`, Swift 6.2 stdlib) — the safe
//    borrowed path. Compile-gated on 6.2, runtime-gated on the aligned
//    stdlib availability (macOS 26); records span + operand span are
//    formed once per session, elements are read per lookup. A custom
//    ~Escapable view STRUCT holding Spans would additionally need
//    lifetime-dependence annotations (`@_lifetime`, still underscored
//    in 6.2, rejected without an experimental flag) — that variant is
//    not modeled here.
//
// Lookup variants fold encoding + operand count (symmetric with the
// shipping benchmark); walk variants additionally dereference every
// operand through `operandTag` so the operand storage is actually read
// through each view shape.

import Foundation
import Iris

/// Retain-free instruction view candidate: a record copy plus an
/// unowned slice of the stream's operand buffer. Trivial — formation
/// is a 40-byte copy and a (pointer, length) pair, no ARC.
struct BorrowedInstruction {
    let record: InstructionRecord
    let operands: UnsafeBufferPointer<Operand>
}

/// Force a real read of operand payload memory (one branch per case;
/// the optimizer cannot skip the load).
@inline(__always)
func operandTag(_ op: Operand) -> UInt64 {
    switch op {
    case .register: 1
    case .vectorRegister: 2
    case .immediate: 3
    case .unsignedImmediate: 4
    case .floatImmediate: 5
    case .label: 6
    case .memory: 7
    case .shiftedRegister: 8
    case .extendedRegister: 9
    case .systemRegister: 10
    case .conditionCode: 11
    case .pstateField: 12
    case .barrierOption: 13
    case .prefetchOperation: 14
    case .systemOp: 15
    case .amxField: 16
    case .amxUnknown: 17
    case .shiftAmount: 18
    case .pageLabel: 19
    }
}

/// The operand-count rule `Operands` formation applies: truncated-tail
/// records reuse `operandCount` as the residual byte count and carry no
/// operands — a borrowed view former must mirror it.
@inline(__always)
private func viewOperandCount(_ record: InstructionRecord) -> Int {
    record.category == .truncatedTail ? 0 : Int(record.operandCount)
}

func runViewExperiment(
    stream: InstructionStream,
    addresses: [UInt64],
    config: BenchConfig,
) -> [BenchResult] {
    var results: [BenchResult] = []
    let baseAddress = stream.baseAddress
    let byteCount = stream.byteCount

    // -- Lookup: shipping view, folding encoding ONLY (the exact
    //    benchLookupView loop). A/B with exp-lookup-shipping below: the
    //    loops differ only in whether operands.count joins the fold, and
    //    the measured delta is the optimizer-context-sensitive ARC
    //    retain/release the implementation record attributed the
    //    ~40 ns to.
    results.append(measure(
        name: "exp-lookup-shipping-encoding", unit: "ns/op", largerIsBetter: false, runs: config.runs,
        note: "instruction(at:) — Instruction view; folds encoding only (benchLookupView shape)",
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
    })

    // -- Lookup: shipping ergonomic view (ARC retain per formation).
    results.append(measure(
        name: "exp-lookup-shipping", unit: "ns/op", largerIsBetter: false, runs: config.runs,
        note: "instruction(at:) — Instruction view; folds encoding + operand count",
    ) {
        var fold: UInt64 = 0
        let seconds = timed {
            for address in addresses {
                if let instruction = stream.instruction(at: address) {
                    fold &+= UInt64(instruction.encoding) &+ UInt64(instruction.operands.count)
                }
            }
        }
        blackhole(fold)
        return seconds * 1e9 / Double(addresses.count)
    })

    // -- Lookup: raw record, no operand view of any kind (floor).
    let records = stream.records
    results.append(measure(
        name: "exp-lookup-raw", unit: "ns/op", largerIsBetter: false, runs: config.runs,
        note: "records[] arithmetic only; folds encoding + record operand count",
    ) {
        var fold: UInt64 = 0
        let seconds = timed {
            for address in addresses {
                let delta = address &- baseAddress
                if delta < byteCount, delta % 4 == 0 {
                    let index = Int(delta / 4)
                    if index < records.count {
                        let record = records[index]
                        fold &+= UInt64(record.encoding) &+ UInt64(viewOperandCount(record))
                    }
                }
            }
        }
        blackhole(fold)
        return seconds * 1e9 / Double(addresses.count)
    })

    // -- Lookup: BorrowedInstruction, session scope (arrays pinned once).
    results.append(measure(
        name: "exp-lookup-borrowed-session", unit: "ns/op", largerIsBetter: false, runs: config.runs,
        note: "withInstructionSession candidate — records+operands pinned once, BorrowedInstruction formed per call",
    ) {
        var fold: UInt64 = 0
        let seconds = timed {
            stream.records.withUnsafeBufferPointer { recs in
                stream.operands.withUnsafeBufferPointer { ops in
                    for address in addresses {
                        let delta = address &- baseAddress
                        if delta < byteCount, delta % 4 == 0 {
                            let index = Int(delta / 4)
                            if index < recs.count {
                                let record = recs[index]
                                let start = Int(record.operandStart)
                                let count = viewOperandCount(record)
                                let view = BorrowedInstruction(
                                    record: record,
                                    operands: UnsafeBufferPointer(rebasing: ops[start ..< start + count]),
                                )
                                fold &+= UInt64(view.record.encoding) &+ UInt64(view.operands.count)
                            }
                        }
                    }
                }
            }
        }
        blackhole(fold)
        return seconds * 1e9 / Double(addresses.count)
    })

    // -- Lookup: BorrowedInstruction, per-call pin (withInstruction(at:) candidate).
    results.append(measure(
        name: "exp-lookup-borrowed-percall", unit: "ns/op", largerIsBetter: false, runs: config.runs,
        note: "withInstruction(at:) candidate — operand buffer pinned per call",
    ) {
        var fold: UInt64 = 0
        let seconds = timed {
            for address in addresses {
                let delta = address &- baseAddress
                if delta < byteCount, delta % 4 == 0 {
                    let index = Int(delta / 4)
                    if index < records.count {
                        let record = records[index]
                        stream.operands.withUnsafeBufferPointer { ops in
                            let start = Int(record.operandStart)
                            let count = viewOperandCount(record)
                            let view = BorrowedInstruction(
                                record: record,
                                operands: UnsafeBufferPointer(rebasing: ops[start ..< start + count]),
                            )
                            fold &+= UInt64(view.record.encoding) &+ UInt64(view.operands.count)
                        }
                    }
                }
            }
        }
        blackhole(fold)
        return seconds * 1e9 / Double(addresses.count)
    })

    // -- Lookup: Span session (safe borrowed path), where the toolchain
    //    and host stdlib provide it.
    #if compiler(>=6.2)
        if #available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *) {
            results.append(measure(
                name: "exp-lookup-span-session", unit: "ns/op", largerIsBetter: false, runs: config.runs,
                note: "Array.span session — records span read per call (safe borrowed access, no ARC)",
            ) {
                var fold: UInt64 = 0
                let seconds = timed {
                    let recSpan = stream.records.span
                    for address in addresses {
                        let delta = address &- baseAddress
                        if delta < byteCount, delta % 4 == 0 {
                            let index = Int(delta / 4)
                            if index < recSpan.count {
                                let record = recSpan[index]
                                fold &+= UInt64(record.encoding) &+ UInt64(viewOperandCount(record))
                            }
                        }
                    }
                }
                blackhole(fold)
                return seconds * 1e9 / Double(addresses.count)
            })
        } else {
            FileHandle.standardError.write(Data("view-experiment: Span session SKIPPED (host stdlib predates aligned availability)\n".utf8))
        }
    #endif

    // -- Walk: shipping view, all fields + every operand dereferenced.
    results.append(measure(
        name: "exp-walk-shipping", unit: "ns/elem", largerIsBetter: false, runs: config.runs,
        note: "for instruction in stream — full fields + operandTag over every operand",
    ) {
        var fold: UInt64 = 0
        let seconds = timed {
            for instruction in stream {
                fold &+= UInt64(instruction.encoding)
                fold &+= UInt64(instruction.mnemonic.rawValue)
                fold &+= instruction.semanticReads.mask
                for op in instruction.operands {
                    fold &+= operandTag(op)
                }
            }
        }
        blackhole(fold)
        return seconds * 1e9 / Double(stream.count)
    })

    // -- Walk: BorrowedInstruction session.
    results.append(measure(
        name: "exp-walk-borrowed-session", unit: "ns/elem", largerIsBetter: false, runs: config.runs,
        note: "pinned-arrays walk — same fields + operandTag through BorrowedInstruction",
    ) {
        var fold: UInt64 = 0
        let seconds = timed {
            stream.records.withUnsafeBufferPointer { recs in
                stream.operands.withUnsafeBufferPointer { ops in
                    for index in 0 ..< recs.count {
                        let record = recs[index]
                        let start = Int(record.operandStart)
                        let count = viewOperandCount(record)
                        let view = BorrowedInstruction(
                            record: record,
                            operands: UnsafeBufferPointer(rebasing: ops[start ..< start + count]),
                        )
                        fold &+= UInt64(view.record.encoding)
                        fold &+= UInt64(view.record.mnemonic.rawValue)
                        fold &+= view.record.semanticReads.mask
                        for op in view.operands {
                            fold &+= operandTag(op)
                        }
                    }
                }
            }
        }
        blackhole(fold)
        return seconds * 1e9 / Double(stream.count)
    })

    // -- Walk: pinned buffers, direct indexed access, NO per-element
    //    view struct or slice formation — isolates whether the borrowed
    //    walk's cost over the span walk is view formation (slice
    //    rebasing + struct) or the access path itself.
    results.append(measure(
        name: "exp-walk-pinned-direct", unit: "ns/elem", largerIsBetter: false, runs: config.runs,
        note: "pinned-arrays walk — same folds via direct ops[start+k] indexing, no view formed",
    ) {
        var fold: UInt64 = 0
        let seconds = timed {
            stream.records.withUnsafeBufferPointer { recs in
                stream.operands.withUnsafeBufferPointer { ops in
                    for index in 0 ..< recs.count {
                        let record = recs[index]
                        let start = Int(record.operandStart)
                        let count = viewOperandCount(record)
                        fold &+= UInt64(record.encoding)
                        fold &+= UInt64(record.mnemonic.rawValue)
                        fold &+= record.semanticReads.mask
                        for k in start ..< start + count {
                            fold &+= operandTag(ops[k])
                        }
                    }
                }
            }
        }
        blackhole(fold)
        return seconds * 1e9 / Double(stream.count)
    })

    // -- Walk: Span session.
    #if compiler(>=6.2)
        if #available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *) {
            results.append(measure(
                name: "exp-walk-span-session", unit: "ns/elem", largerIsBetter: false, runs: config.runs,
                note: "Array.span walk — same fields + operandTag through spans",
            ) {
                var fold: UInt64 = 0
                let seconds = timed {
                    let recSpan = stream.records.span
                    let opSpan = stream.operands.span
                    for index in 0 ..< recSpan.count {
                        let record = recSpan[index]
                        let start = Int(record.operandStart)
                        let count = viewOperandCount(record)
                        fold &+= UInt64(record.encoding)
                        fold &+= UInt64(record.mnemonic.rawValue)
                        fold &+= record.semanticReads.mask
                        for k in start ..< start + count {
                            fold &+= operandTag(opSpan[k])
                        }
                    }
                }
                blackhole(fold)
                return seconds * 1e9 / Double(stream.count)
            })
        }
    #endif

    return results
}
