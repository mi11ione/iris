// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// BorrowedInstruction. The session tier's element: a copied 40-byte
// record plus a borrowed slice of a pinned operand buffer. Formation
// performs no reference counting and no allocation, the measured
// property the session API ships for (the borrowing-view experiment,
// Benchmarks/Sources/iris-bench/ViewExperiment.swift).

/// A decoded ARM64 instruction borrowed from pinned stream storage.
///
/// `BorrowedInstruction` is the hot-loop counterpart of ``Instruction``,
/// produced by ``InstructionStream/Session`` lookups and iteration inside
/// ``InstructionStream/withSession(_:)``. It carries the same packed
/// ``record``, with ``operands`` presented as an `UnsafeBufferPointer`
/// slice of the session's pinned side buffer instead of a retained view.
/// Forming one is a 40-byte copy plus a (pointer, length) pair, no
/// reference counting, no heap allocation, which is what makes session
/// access faster and context-independent compared to forming
/// ``Instruction`` values (the measured contract is documented on
/// ``InstructionStream/withSession(_:)``).
///
/// **Validity.** ``operands`` borrows memory that is guaranteed only for
/// the lifetime of the session closure that produced this value (or, for
/// hand-constructed values, whatever scope pinned the buffer passed to
/// ``init(record:operands:)``). Do not store a `BorrowedInstruction`,
/// return it from the session body, or capture it in an escaping closure
/// or task. To keep data past the scope, copy it out: ``record`` is an
/// independent value, and `Array(view.operands)` materializes the
/// operands. The type is deliberately not `Sendable`: the borrowed
/// pointer must never cross a concurrency boundary.
///
/// The semantic projection surface a hot loop reaches for is mirrored
/// here from ``Instruction``: the record-derived conveniences
/// (``mnemonic``, ``category``, ``address``, the register sets, the flag
/// effect, ``isUndefined``, …), the predicates (``isCall``, ``readsMemory``,
/// ``usesPointerAuthentication``, …), and the resolved ``branchTarget`` /
/// ``pcRelativeTarget``. Each delegates to the same implementation
/// ``Instruction`` uses, so a session loop reads them directly without
/// dropping to the ``Instruction`` tier for a second pass. The one
/// projection deliberately absent is ``Instruction/text``: rendering
/// allocates a `String`, which this retain-free tier exists to avoid, so
/// copy the ``record`` out when text is needed.
@frozen
public struct BorrowedInstruction {
    /// The packed 40-byte record, copied by value, safe to copy out of
    /// the session scope.
    public let record: InstructionRecord

    /// This instruction's operands, zero-based, borrowed from the pinned
    /// side buffer. Truncated-tail, UNDEFINED, and data-marker records
    /// carry an empty slice. Valid only within the pinning scope.
    public let operands: UnsafeBufferPointer<Operand>

    /// Pair a record with a borrowed operand slice. Ordinary value
    /// construction: the caller owns the pinning scope of `operands` and
    /// the record/slice correspondence, ``InstructionStream/Session``
    /// is the checked producer.
    @inlinable
    public init(record: InstructionRecord, operands: UnsafeBufferPointer<Operand>) {
        self.record = record
        self.operands = operands
    }
}
