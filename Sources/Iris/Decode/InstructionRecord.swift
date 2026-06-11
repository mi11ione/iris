// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// InstructionRecord. Field order is load-bearing: it is what produces
// the exact 40-byte natural-alignment layout the packed-storage design
// depends on. Reordering breaks the layout budget.
//
// Layout (40 bytes, alignment 8):
//   offset 0   address          UInt64        8B
//   offset 8   semanticReads    RegisterSet   8B
//   offset 16  semanticWrites   RegisterSet   8B
//   offset 24  encoding         UInt32        4B
//   offset 28  operandStart     UInt32        4B
//   offset 32  mnemonic         Mnemonic      2B
//   offset 34  branchClass      BranchClass   1B
//   offset 35  memoryAccess     MemoryAccess  1B
//   offset 36  memoryOrdering   MemoryOrdering 1B
//   offset 37  flagEffect       FlagEffect    1B
//   offset 38  category         Category      1B
//   offset 39  operandCount     UInt8         1B

/// A single decoded ARM64 instruction record — the packed 40-byte storage
/// unit of ``InstructionStream``.
///
/// `InstructionRecord` is the raw, maximum-throughput tier: bulk scans
/// iterate ``InstructionStream/records`` directly with no view formation.
/// Operands live in the parent ``InstructionStream/operands`` side
/// buffer; this record holds the `(operandStart, operandCount)` indices
/// into it. The ergonomic per-instruction view over a record is
/// ``Instruction``.
///
/// Equality and hashing are synthesized over **all** stored fields,
/// including the `operandStart`/`operandCount` side-buffer indices —
/// index equality is the correct meaning for raw storage. This is
/// deliberately different from ``Instruction``, whose custom equality
/// excludes the side-buffer indices and compares operand *content*, so
/// that semantically identical instructions from different streams
/// compare equal.
@frozen
public struct InstructionRecord: Sendable, Hashable {
    /// Source VM address of the 4-byte word, formed as the stream's
    /// `baseAddress` plus the word's buffer offset, modulo 2^64.
    public let address: UInt64
    /// Bitmask of registers semantically read by this instruction.
    public let semanticReads: RegisterSet
    /// Bitmask of registers semantically written by this instruction.
    public let semanticWrites: RegisterSet
    /// Raw 4-byte instruction encoding, in host byte order (ARM64 = LE).
    /// For truncated-tail records, packs the residual 1-3 bytes at the
    /// low bits with high bits zero.
    public let encoding: UInt32
    /// Index into ``InstructionStream/operands`` where this
    /// instruction's operands begin.
    public let operandStart: UInt32
    /// Canonical preferred-alias-resolved mnemonic.
    public let mnemonic: Mnemonic
    /// Control-flow classification.
    public let branchClass: BranchClass
    /// Memory-effect classification.
    public let memoryAccess: MemoryAccess
    /// Memory-ordering bits (acquire / release).
    public let memoryOrdering: MemoryOrdering
    /// PSTATE.NZCV write effect.
    public let flagEffect: FlagEffect
    /// Encoding-family attribution / provenance witness.
    public let category: Category
    /// Number of operands at ``operandStart`` — except on truncated-tail
    /// records (`category == .truncatedTail`), where it carries the
    /// residual byte count (1…3) instead; tail records have no operands.
    /// ``tailByteCount`` makes the dual meaning explicit.
    public let operandCount: UInt8

    @inlinable
    public init(
        address: UInt64,
        semanticReads: RegisterSet,
        semanticWrites: RegisterSet,
        encoding: UInt32,
        operandStart: UInt32,
        mnemonic: Mnemonic,
        branchClass: BranchClass,
        memoryAccess: MemoryAccess,
        memoryOrdering: MemoryOrdering,
        flagEffect: FlagEffect,
        category: Category,
        operandCount: UInt8,
    ) {
        self.address = address
        self.semanticReads = semanticReads
        self.semanticWrites = semanticWrites
        self.encoding = encoding
        self.operandStart = operandStart
        self.mnemonic = mnemonic
        self.branchClass = branchClass
        self.memoryAccess = memoryAccess
        self.memoryOrdering = memoryOrdering
        self.flagEffect = flagEffect
        self.category = category
        self.operandCount = operandCount
    }
}

public extension InstructionRecord {
    /// Residual byte count for a truncated-tail record; 0 for all other
    /// records.
    ///
    /// A truncated-tail record (`category == .truncatedTail`) represents
    /// the residual 1-3 bytes of a buffer whose size is not a multiple
    /// of 4. Tail records carry no operands, so `operandCount` is free
    /// to carry the residual length — this accessor names that meaning.
    @inlinable
    var tailByteCount: Int {
        category == .truncatedTail ? Int(operandCount) : 0
    }
}
