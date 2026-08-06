// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// A decoded ARM64 instruction borrowed from pinned stream storage — the
/// retain-free counterpart of ``Instruction``, produced inside
/// ``InstructionStream/withSession(_:)``.
///
/// ``operands`` dangles once the session closure returns: do not store,
/// return or capture this value. Copy out instead. ``Instruction/text`` is
/// deliberately absent, since rendering allocates.
@frozen
public struct BorrowedInstruction {
    /// The packed 57-byte record, copied by value, safe to copy out of
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
