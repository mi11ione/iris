// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

public extension BorrowedInstruction {
    /// Source VM address of the instruction word (modulo 2^64).
    @inlinable var address: UInt64 {
        record.address
    }

    /// Raw 4-byte instruction encoding (truncated-tail records pack their
    /// residual bytes at the low bits).
    @inlinable var encoding: UInt32 {
        record.encoding
    }

    /// Canonical preferred-alias-resolved mnemonic.
    @inlinable var mnemonic: Mnemonic {
        record.mnemonic
    }

    /// Bitmask of registers semantically read by this instruction.
    @inlinable var semanticReads: RegisterSet {
        record.semanticReads
    }

    /// Bitmask of registers semantically written by this instruction.
    @inlinable var semanticWrites: RegisterSet {
        record.semanticWrites
    }

    /// Scalable (SVE/SME) state semantically read.
    @inlinable var scalableReads: ScalableRegisterSet {
        record.scalableReads
    }

    /// Scalable (SVE/SME) state semantically written.
    @inlinable var scalableWrites: ScalableRegisterSet {
        record.scalableWrites
    }

    /// Per-instruction scalable/streaming effect flags.
    @inlinable var scalableEffect: ScalableEffect {
        record.scalableEffect
    }

    /// Control-flow classification.
    @inlinable var branchClass: BranchClass {
        record.branchClass
    }

    /// Memory-effect classification.
    @inlinable var memoryAccess: MemoryAccess {
        record.memoryAccess
    }

    /// Memory-ordering bits (acquire / release).
    @inlinable var memoryOrdering: MemoryOrdering {
        record.memoryOrdering
    }

    /// PSTATE.NZCV read/write effect.
    @inlinable var flagEffect: FlagEffect {
        record.flagEffect
    }

    /// Encoding-family attribution / provenance witness.
    @inlinable var category: Category {
        record.category
    }

    /// True when this record is the decoder's UNDEFINED witness.
    @inlinable var isUndefined: Bool {
        record.projectedIsUndefined
    }
}

public extension BorrowedInstruction {
    /// Absolute target of a direct control-flow transfer, the retain-free mirror
    /// of ``Instruction/branchTarget``. `nil` when control flow is indirect,
    /// exception-generating, or absent.
    @inlinable var branchTarget: UInt64? {
        record.projectedBranchTarget(operands)
    }

    /// Absolute PC-relative data address this instruction forms, the
    /// retain-free mirror of ``Instruction/pcRelativeTarget``.
    @inlinable var pcRelativeTarget: UInt64? {
        record.projectedPCRelativeTarget(operands)
    }
}

public extension BorrowedInstruction {
    /// True for BL/BLR and their authenticated variants. Mirrors
    /// ``Instruction/isCall``.
    @inlinable var isCall: Bool {
        record.projectedIsCall
    }

    /// True for RET/RETAA/RETAB.
    @inlinable var isReturn: Bool {
        record.projectedIsReturn
    }

    /// True for conditional branches and condition-consuming non-branches (a
    /// `.conditionCode` operand).
    @inlinable var isConditional: Bool {
        record.projectedIsConditional(operands)
    }

    /// True when the instruction semantically reads memory.
    @inlinable var readsMemory: Bool {
        record.projectedReadsMemory
    }

    /// True when the instruction semantically writes memory.
    @inlinable var writesMemory: Bool {
        record.projectedWritesMemory
    }

    /// True for single-instruction atomic read-modify-writes.
    @inlinable var isAtomic: Bool {
        record.projectedIsAtomic
    }

    /// True for one half of an exclusive-monitor pair.
    @inlinable var isExclusive: Bool {
        record.projectedIsExclusive
    }

    /// True when any of N/Z/C/V is consumed.
    @inlinable var readsFlags: Bool {
        record.projectedReadsFlags
    }

    /// True when any of N/Z/C/V is written.
    @inlinable var writesFlags: Bool {
        record.projectedWritesFlags
    }

    /// True when the mnemonic is in the pointer-authentication set.
    @inlinable var usesPointerAuthentication: Bool {
        record.projectedUsesPointerAuthentication
    }
}
