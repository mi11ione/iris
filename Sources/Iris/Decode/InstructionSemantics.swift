// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

public extension Instruction {
    /// Absolute target of a direct control-flow transfer, `address &+ label
    /// offset` modulo 2^64. `nil` when control flow is indirect,
    /// exception-generating or absent — `BL` resolves while `BLR` is nil with
    /// `branchClass == .call`, so the two stay distinguishable.
    @inlinable
    var branchTarget: UInt64? {
        record.projectedBranchTarget(operands)
    }

    /// Absolute PC-relative *data* address this instruction forms or
    /// references.
    @inlinable
    var pcRelativeTarget: UInt64? {
        record.projectedPCRelativeTarget(operands)
    }
}

public extension Instruction {
    /// True for BL/BLR and their authenticated variants — the transfers that
    /// write the link register (`branchClass == .call`).
    ///
    /// Claims nothing about whether the callee returns, and does not separate
    /// direct from indirect; that is ``branchTarget`` being non-nil.
    @inlinable
    var isCall: Bool {
        record.projectedIsCall
    }

    /// True for RET/RETAA/RETAB (`branchClass == .return`).
    @inlinable
    var isReturn: Bool {
        record.projectedIsReturn
    }

    /// True when the architectural effect depends on a condition code or an
    /// encoded register/bit test.
    @inlinable
    var isConditional: Bool {
        record.projectedIsConditional(operands)
    }

    /// True when the instruction semantically reads memory (`memoryAccess` ∈
    /// {load, atomic, exclusiveLoad}); `.atomic` is both a read and a write.
    @inlinable
    var readsMemory: Bool {
        record.projectedReadsMemory
    }

    /// True when the instruction semantically writes memory (`memoryAccess` ∈
    /// {store, atomic, exclusiveStore}); `.atomic` (read-modify-write) is both
    /// a read and a write.
    @inlinable
    var writesMemory: Bool {
        record.projectedWritesMemory
    }

    /// True for single-instruction atomic read-modify-writes (the LSE atomics,
    /// CAS, SWP, `memoryAccess == .atomic`).
    @inlinable
    var isAtomic: Bool {
        record.projectedIsAtomic
    }

    /// True for one half of an exclusive-monitor pair (`memoryAccess` ∈
    /// {exclusiveLoad, exclusiveStore}).
    @inlinable
    var isExclusive: Bool {
        record.projectedIsExclusive
    }

    /// True when any of N/Z/C/V is consumed (`flagEffect`).
    @inlinable
    var readsFlags: Bool {
        record.projectedReadsFlags
    }

    /// True when any of N/Z/C/V is written (`flagEffect`).
    @inlinable
    var writesFlags: Bool {
        record.projectedWritesFlags
    }

    /// True for the pointer-authentication mnemonic set.
    @inlinable
    var usesPointerAuthentication: Bool {
        record.projectedUsesPointerAuthentication
    }
}

extension Mnemonic {
    /// The fixed pointer-authentication mnemonic set behind
    /// ``Instruction/usesPointerAuthentication``, derived from the decoders.
    @usableFromInline
    static func involvesPointerAuthentication(_ m: Mnemonic) -> Bool {
        switch m {
        case .pacia, .pacib, .pacda, .pacdb,
             .paciza, .pacizb, .pacdza, .pacdzb,
             .autia, .autib, .autda, .autdb,
             .autiza, .autizb, .autdza, .autdzb,
             .xpaci, .xpacd, .pacga:
            true
        case .braa, .brab, .braaz, .brabz,
             .blraa, .blrab, .blraaz, .blrabz,
             .retaa, .retab, .eretaa, .eretab:
            true
        case .xpaclri,
             .pacia1716, .pacib1716, .autia1716, .autib1716,
             .paciaz, .paciasp, .pacibz, .pacibsp,
             .autiaz, .autiasp, .autibz, .autibsp:
            true
        case .ldraa, .ldrab:
            true
        default:
            false
        }
    }
}
