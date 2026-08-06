// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension InstructionRecord {
    /// Backs ``Instruction/isCall`` and ``BorrowedInstruction/isCall``,
    /// `branchClass == .call`.
    @usableFromInline
    var projectedIsCall: Bool {
        branchClass == .call
    }

    /// Backs ``Instruction/isReturn`` and ``BorrowedInstruction/isReturn``,
    /// `branchClass == .return`.
    @usableFromInline
    var projectedIsReturn: Bool {
        branchClass == .return
    }

    /// Backs ``Instruction/readsMemory`` and
    /// ``BorrowedInstruction/readsMemory``, `memoryAccess` ∈ {load, atomic,
    /// exclusiveLoad}.
    @usableFromInline
    var projectedReadsMemory: Bool {
        memoryAccess == .load
            || memoryAccess == .atomic
            || memoryAccess == .exclusiveLoad
    }

    /// Backs ``Instruction/writesMemory`` and
    /// ``BorrowedInstruction/writesMemory``, `memoryAccess` ∈ {store, atomic,
    /// exclusiveStore}.
    @usableFromInline
    var projectedWritesMemory: Bool {
        memoryAccess == .store
            || memoryAccess == .atomic
            || memoryAccess == .exclusiveStore
    }

    /// Backs ``Instruction/isAtomic`` and ``BorrowedInstruction/isAtomic``,
    /// `memoryAccess == .atomic`.
    @usableFromInline
    var projectedIsAtomic: Bool {
        memoryAccess == .atomic
    }

    /// Backs ``Instruction/isExclusive`` and
    /// ``BorrowedInstruction/isExclusive``, `memoryAccess` ∈ {exclusiveLoad,
    /// exclusiveStore}.
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
    /// ``BorrowedInstruction/usesPointerAuthentication``, the mnemonic is in
    /// the pointer-authentication set.
    @usableFromInline
    var projectedUsesPointerAuthentication: Bool {
        Mnemonic.involvesPointerAuthentication(mnemonic)
    }

    /// Backs ``Instruction/isUndefined``: the decoder recognised nothing, so
    /// the mnemonic is the `.undefined` sentinel. Covers both the base
    /// reserved tier and an in-scope but unallocated SVE/SME hole. Data
    /// markers and truncated tails carry their own sentinels and are excluded.
    @usableFromInline
    var projectedIsUndefined: Bool {
        mnemonic == .undefined
    }

    /// Backs ``Instruction/isConditional`` and
    /// ``BorrowedInstruction/isConditional``.
    @usableFromInline
    func projectedIsConditional(_ operands: some Sequence<Operand>) -> Bool {
        if branchClass == .conditional { return true }
        for operand in operands {
            if case .conditionCode = operand { return true }
        }
        return false
    }

    /// Backs ``Instruction/branchTarget`` and
    /// ``BorrowedInstruction/branchTarget``.
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
    /// ``BorrowedInstruction/pcRelativeTarget``.
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
