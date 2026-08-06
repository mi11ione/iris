// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// A single decoded ARM64 instruction record — the packed 57-byte (stride-64)
/// storage unit of ``InstructionStream``, below ``Instruction``.
///
/// Operands live in ``InstructionStream/operands``; this holds the indices.
/// Field order produces the layout and must not be reordered. Equality is
/// synthesized over all fields, side-buffer indices included.
@frozen
public struct InstructionRecord: Sendable, Hashable {
    /// Source VM address of the 4-byte word, formed as the stream's
    /// `baseAddress` plus the word's buffer offset, modulo 2^64.
    public let address: UInt64
    /// Bitmask of registers semantically read by this instruction.
    public let semanticReads: RegisterSet
    /// Bitmask of registers semantically written by this instruction.
    public let semanticWrites: RegisterSet
    /// Scalable (SVE/SME) state semantically read — predicates, FFR, ZT0,
    /// `ZA`. Empty for every base-ISA record. `Z_n` reads ride the SIMD
    /// bit `32+n` in ``semanticReads`` (they alias `V_n`), not here.
    public let scalableReads: ScalableRegisterSet
    /// Scalable (SVE/SME) state semantically written. Empty for every
    /// base-ISA record.
    public let scalableWrites: ScalableRegisterSet
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
    /// Per-instruction scalable/streaming effect flags (partial-write,
    /// streaming-mode relationship, fault behavior). `.none` for every
    /// base-ISA record.
    public let scalableEffect: ScalableEffect

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
        scalableReads: ScalableRegisterSet = .empty,
        scalableWrites: ScalableRegisterSet = .empty,
        scalableEffect: ScalableEffect = .none,
    ) {
        self.address = address
        self.semanticReads = semanticReads
        self.semanticWrites = semanticWrites
        self.scalableReads = scalableReads
        self.scalableWrites = scalableWrites
        self.encoding = encoding
        self.operandStart = operandStart
        self.mnemonic = mnemonic
        self.branchClass = branchClass
        self.memoryAccess = memoryAccess
        self.memoryOrdering = memoryOrdering
        self.flagEffect = flagEffect
        self.category = category
        self.operandCount = operandCount
        self.scalableEffect = scalableEffect
    }
}

public extension InstructionRecord {
    /// Residual byte count (1...3) for a truncated-tail record; 0 for
    /// every other record.
    @inlinable
    var tailByteCount: Int {
        category == .truncatedTail ? Int(operandCount) : 0
    }
}
