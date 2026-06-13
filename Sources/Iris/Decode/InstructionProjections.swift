// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// The shared semantic-projection core. The predicates (isCall, readsMemory,
// usesPointerAuthentication, …) and the resolved targets (branchTarget,
// pcRelativeTarget) are pure functions of a record's classification fields
// plus, for the operand-dependent ones, the instruction's operands. Both
// the ergonomic Instruction tier and the retain-free BorrowedInstruction
// tier project the same surface, so the formulas live here ONCE and each
// tier delegates. One implementation means the two tiers cannot drift, a
// property the equality suite pins.
//
// The operand-dependent projections are generic over `some Sequence<Operand>`
// so the same body serves Instruction.Operands (a RandomAccessCollection)
// and BorrowedInstruction's UnsafeBufferPointer<Operand> with no copy. Each
// helper is @usableFromInline so both tiers' @inlinable projections inline
// through it with no call overhead in a hot loop.

extension InstructionRecord {
    // Pure-record predicates: classification-field reads, no operands.

    /// Backs ``Instruction/isCall`` and
    /// ``BorrowedInstruction/isCall``, `branchClass == .call`.
    @usableFromInline
    var projectedIsCall: Bool {
        branchClass == .call
    }

    /// Backs ``Instruction/isReturn`` and
    /// ``BorrowedInstruction/isReturn``, `branchClass == .return`.
    @usableFromInline
    var projectedIsReturn: Bool {
        branchClass == .return
    }

    /// Backs ``Instruction/readsMemory`` and
    /// ``BorrowedInstruction/readsMemory``, `memoryAccess` ∈
    /// {load, atomic, exclusiveLoad}.
    @usableFromInline
    var projectedReadsMemory: Bool {
        memoryAccess == .load
            || memoryAccess == .atomic
            || memoryAccess == .exclusiveLoad
    }

    /// Backs ``Instruction/writesMemory`` and
    /// ``BorrowedInstruction/writesMemory``, `memoryAccess` ∈
    /// {store, atomic, exclusiveStore}.
    @usableFromInline
    var projectedWritesMemory: Bool {
        memoryAccess == .store
            || memoryAccess == .atomic
            || memoryAccess == .exclusiveStore
    }

    /// Backs ``Instruction/isAtomic`` and
    /// ``BorrowedInstruction/isAtomic``, `memoryAccess == .atomic`.
    @usableFromInline
    var projectedIsAtomic: Bool {
        memoryAccess == .atomic
    }

    /// Backs ``Instruction/isExclusive`` and
    /// ``BorrowedInstruction/isExclusive``, `memoryAccess` ∈
    /// {exclusiveLoad, exclusiveStore}.
    @usableFromInline
    var projectedIsExclusive: Bool {
        memoryAccess == .exclusiveLoad
            || memoryAccess == .exclusiveStore
    }

    /// Backs ``Instruction/readsFlags`` and
    /// ``BorrowedInstruction/readsFlags``, any of N/Z/C/V consumed.
    @usableFromInline
    var projectedReadsFlags: Bool {
        flagEffect.readsAnyFlag
    }

    /// Backs ``Instruction/writesFlags`` and
    /// ``BorrowedInstruction/writesFlags``, any of N/Z/C/V written.
    @usableFromInline
    var projectedWritesFlags: Bool {
        flagEffect.writesAnyFlag
    }

    /// Backs ``Instruction/usesPointerAuthentication`` and
    /// ``BorrowedInstruction/usesPointerAuthentication``, the mnemonic is
    /// in the pointer-authentication set.
    @usableFromInline
    var projectedUsesPointerAuthentication: Bool {
        Mnemonic.involvesPointerAuthentication(mnemonic)
    }

    /// Backs ``Instruction/isUndefined`` and
    /// ``BorrowedInstruction/isUndefined``, `category == .undefined`.
    @usableFromInline
    var projectedIsUndefined: Bool {
        category == .undefined
    }

    // Operand-dependent projections: generic over the operand sequence so
    // one body serves both tiers' operand collection types.

    /// Backs ``Instruction/isConditional`` and
    /// ``BorrowedInstruction/isConditional``: a conditional branch, or any
    /// instruction carrying a `.conditionCode` operand.
    @usableFromInline
    func projectedIsConditional(_ operands: some Sequence<Operand>) -> Bool {
        if branchClass == .conditional { return true }
        for operand in operands {
            if case .conditionCode = operand { return true }
        }
        return false
    }

    /// Backs ``Instruction/branchTarget`` and
    /// ``BorrowedInstruction/branchTarget``: the absolute target of a
    /// direct control-flow transfer (`address &+ label byte offset`,
    /// modulo 2^64), or `nil` when control flow is indirect, exception-
    /// generating, or absent.
    @usableFromInline
    func projectedBranchTarget(_ operands: some Sequence<Operand>) -> UInt64? {
        switch branchClass {
        case .direct, .conditional, .call:
            for operand in operands {
                if case let .label(byteOffset) = operand {
                    return address &+ UInt64(bitPattern: byteOffset)
                }
            }
            return nil
        default:
            return nil
        }
    }

    /// Backs ``Instruction/pcRelativeTarget`` and
    /// ``BorrowedInstruction/pcRelativeTarget``: the absolute PC-relative
    /// data address an ADR/ADRP or PC-literal load/prefetch forms (the
    /// ADRP page math lives here), modulo 2^64; `nil` for everything else.
    @usableFromInline
    func projectedPCRelativeTarget(_ operands: some Sequence<Operand>) -> UInt64? {
        for operand in operands {
            switch operand {
            case let .pageLabel(byteOffset):
                return (address & ~UInt64(0xFFF)) &+ UInt64(bitPattern: byteOffset)
            case let .label(byteOffset) where mnemonic == .adr:
                return address &+ UInt64(bitPattern: byteOffset)
            case let .memory(memory):
                if case .pc = memory.base {
                    return address &+ UInt64(bitPattern: memory.displacement)
                }
            default:
                continue
            }
        }
        return nil
    }
}
