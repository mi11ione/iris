// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// The session tier's semantic projection surface. BorrowedInstruction now
// mirrors the surface a hot loop reaches for on Instruction: the record-
// derived conveniences (mnemonic, category, address, the register sets, the
// flag effect, isUndefined, …) and the full semantic layer (the predicates
// and the resolved control-flow / PC-relative targets). Every projection
// delegates to the shared core in InstructionProjections.swift, the same
// implementation Instruction delegates to, so a session loop is a complete
// substitute for the Instruction path and the two tiers cannot drift (the
// equality suite pins it). The borrowed operand slice feeds the operand-
// dependent projections directly, no materialization. Each member is
// @inlinable, matching the tier's other conveniences, so the whole surface
// is overhead-free inside the pinning scope.
//
// text/description are deliberately NOT mirrored: rendering allocates a
// String, which the retain-free tier exists to avoid. Copy the record out
// (Instruction(record:operands:) or stream lookup) when text is needed.

public extension BorrowedInstruction {
    // Record-derived conveniences, direct loads from the borrowed record,
    // so a session loop never reaches through `.record.` for the common
    // fields. Each mirrors the same-named projection on ``Instruction``.

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

    /// True when this record is the decoder's UNDEFINED witness. Mirrors
    /// ``Instruction/isUndefined``.
    @inlinable var isUndefined: Bool {
        record.projectedIsUndefined
    }
}

public extension BorrowedInstruction {
    // Resolved targets, the projections that previously forced a session
    // loop to drop to the Instruction tier for a second pass. Identical
    // results to ``Instruction/branchTarget`` / ``Instruction/pcRelativeTarget``
    // on the same record and operands.

    /// Absolute target of a direct control-flow transfer, the retain-free
    /// mirror of ``Instruction/branchTarget``: `address &+ label byte
    /// offset` modulo 2^64 for B, BL, B.cond, BC.cond, CBZ/CBNZ, TBZ/TBNZ,
    /// and the FEAT_CMPBR compare-and-branch family. `nil` when control
    /// flow is indirect (BR, BLR, RET), exception-generating (SVC/BRK/UDF),
    /// or absent.
    @inlinable var branchTarget: UInt64? {
        record.projectedBranchTarget(operands)
    }

    /// Absolute PC-relative data address this instruction forms, the
    /// retain-free mirror of ``Instruction/pcRelativeTarget``: ADR
    /// (`address &+ offset`), ADRP (`(address & ~0xFFF) &+ page offset`,
    /// the page math lives in the projection), and the PC-literal
    /// loads/prefetch (`address &+ displacement`). All arithmetic modulo
    /// 2^64. `nil` for everything else.
    @inlinable var pcRelativeTarget: UInt64? {
        record.projectedPCRelativeTarget(operands)
    }
}

public extension BorrowedInstruction {
    // Semantic predicates, the retain-free mirrors of the ``Instruction``
    // predicate set, each an allocation-free projection of the record's
    // existing classifications. See the ``Instruction`` member of the same
    // name for the full contract and documented non-claims.

    /// True for BL/BLR and their authenticated variants. Mirrors
    /// ``Instruction/isCall``.
    @inlinable var isCall: Bool {
        record.projectedIsCall
    }

    /// True for RET/RETAA/RETAB. Mirrors ``Instruction/isReturn``.
    @inlinable var isReturn: Bool {
        record.projectedIsReturn
    }

    /// True for conditional branches and condition-consuming non-branches
    /// (a `.conditionCode` operand). Mirrors ``Instruction/isConditional``.
    @inlinable var isConditional: Bool {
        record.projectedIsConditional(operands)
    }

    /// True when the instruction semantically reads memory. Mirrors
    /// ``Instruction/readsMemory``.
    @inlinable var readsMemory: Bool {
        record.projectedReadsMemory
    }

    /// True when the instruction semantically writes memory. Mirrors
    /// ``Instruction/writesMemory``.
    @inlinable var writesMemory: Bool {
        record.projectedWritesMemory
    }

    /// True for single-instruction atomic read-modify-writes. Mirrors
    /// ``Instruction/isAtomic``.
    @inlinable var isAtomic: Bool {
        record.projectedIsAtomic
    }

    /// True for one half of an exclusive-monitor pair. Mirrors
    /// ``Instruction/isExclusive``.
    @inlinable var isExclusive: Bool {
        record.projectedIsExclusive
    }

    /// True when any of N/Z/C/V is consumed. Mirrors
    /// ``Instruction/readsFlags``.
    @inlinable var readsFlags: Bool {
        record.projectedReadsFlags
    }

    /// True when any of N/Z/C/V is written. Mirrors
    /// ``Instruction/writesFlags``.
    @inlinable var writesFlags: Bool {
        record.projectedWritesFlags
    }

    /// True when the mnemonic is in the pointer-authentication set. Mirrors
    /// ``Instruction/usesPointerAuthentication``.
    @inlinable var usesPointerAuthentication: Bool {
        record.projectedUsesPointerAuthentication
    }
}
