// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// OperandSink. The flat operand buffer a decode writes into, threaded
// through the family decoders as `inout` so no operand ever lives on the
// draft.
//
// Carrying operands on `DecodedDraft` costs the decode path however the
// storage is chosen. A heap `[Operand]` is one allocation per decoded
// word. Inline storage with a heap spill trades that for two worse
// forces: below capacity 2 a spilled word costs far more than the single
// allocation it replaced, because the spill grows by doubling; above it
// `init()` writes every slot to a filler value, so capacity N costs
// N × 24 bytes of stores on every construction whether the operands are
// used or not. Any capacity wide enough to be lossless is the expensive
// end of that trade. A spill field also makes the draft non-POD, so every
// copy through the decode return chain calls outlined copy and destroy
// instead of a memcpy.
//
// With the operands here instead, `DecodedDraft` is trivial, the spill
// allocation is gone, and the commit is a direct append.

/// The flat operand buffer for one stream, written by the family decoders.
///
/// A decoder emits its operands through ``emit(_:)`` and its overloads,
/// which return the count to store on the draft. The stream reads back the
/// range for a word as `[wordStart ..< wordStart + count]`, so the draft
/// carries neither the operands nor a start index — the buffer's own
/// length before the call is the start.
///
/// `Operand` is a trivial type (every payload is an integer or a
/// raw-valued enum), so the buffer is a plain contiguous array with no
/// reference traffic per element.
struct OperandSink {
    private var storage: [Operand]

    init() {
        storage = []
    }

    /// Reserve for a whole buffer up front, so the per-word appends never
    /// grow.
    init(reservingCapacity capacity: Int) {
        storage = []
        storage.reserveCapacity(capacity)
    }

    /// Everything emitted so far, in emission order.
    var operands: [Operand] {
        storage
    }

    /// The index the next emitted operand will occupy — the start of the
    /// word about to be decoded.
    @inline(__always)
    var mark: Int {
        storage.count
    }

    /// The operands emitted since `mark`, as a count that fits a draft.
    @inline(__always)
    func count(since mark: Int) -> UInt8 {
        UInt8(truncatingIfNeeded: storage.count &- mark)
    }

    /// Append one operand without reporting a count — for the decoders
    /// that build their operand list in a loop and close it with
    /// ``count(since:)``.
    @inline(__always)
    mutating func append(_ operand: Operand) {
        reserveFirstBlock()
        storage.append(operand)
    }

    /// Size the first allocation to the widest operand list any decoder
    /// emits, so a word that emits operands allocates once and never grows.
    ///
    /// Lazy rather than eager, because the alternative costs more than it
    /// saves at the word tier: reserving in the initializer allocates for
    /// EVERY word, including the unallocated encodings that emit nothing —
    /// and those are the majority of the 32-bit space. A stream reserves
    /// its whole buffer up front and never reaches this; the test is one
    /// compare against an already-loaded field.
    @inline(__always)
    private mutating func reserveFirstBlock() {
        if storage.capacity == 0 { storage.reserveCapacity(8) }
    }
}

// One overload per arity rather than a variadic. A Swift variadic
// parameter is itself an `Array`: it stack-promotes in a small function
// the optimizer can see through, and does not across the decode tree, so
// a variadic emission point reintroduces the per-word allocation the sink
// exists to remove. The widest operand list any decoder writes as a
// literal is five; longer lists come from append-loops, which close with
// ``count(since:)`` instead.
extension OperandSink {
    @inline(__always)
    mutating func emit(_ a0: Operand) -> UInt8 {
        reserveFirstBlock()
        storage.append(a0)
        return 1
    }

    @inline(__always)
    mutating func emit(_ a0: Operand, _ a1: Operand) -> UInt8 {
        reserveFirstBlock()
        storage.append(a0)
        storage.append(a1)
        return 2
    }

    @inline(__always)
    mutating func emit(_ a0: Operand, _ a1: Operand, _ a2: Operand) -> UInt8 {
        reserveFirstBlock()
        storage.append(a0)
        storage.append(a1)
        storage.append(a2)
        return 3
    }

    @inline(__always)
    mutating func emit(_ a0: Operand, _ a1: Operand, _ a2: Operand, _ a3: Operand) -> UInt8 {
        reserveFirstBlock()
        storage.append(a0)
        storage.append(a1)
        storage.append(a2)
        storage.append(a3)
        return 4
    }

    @inline(__always)
    mutating func emit(
        _ a0: Operand, _ a1: Operand, _ a2: Operand, _ a3: Operand, _ a4: Operand,
    ) -> UInt8 {
        reserveFirstBlock()
        storage.append(a0)
        storage.append(a1)
        storage.append(a2)
        storage.append(a3)
        storage.append(a4)
        return 5
    }
}
