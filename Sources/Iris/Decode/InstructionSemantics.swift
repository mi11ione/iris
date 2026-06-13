// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// The Instruction semantics surface: resolved PC-relative control flow
// (absolute branch / address-formation targets as API, not caller
// arithmetic) and the semantic predicates, each an allocation-free
// projection of the record's existing classifications, never new
// analysis.

public extension Instruction {
    /// Absolute target of a direct control-flow transfer: B, BL, B.cond,
    /// BC.cond, CBZ/CBNZ, TBZ/TBNZ, and the FEAT_CMPBR
    /// compare-and-branch family, `address &+ label byte offset`,
    /// modulo 2^64 (the same address model as the stream's).
    ///
    /// `nil` when control flow is indirect (BR, BLR, RET, the target is
    /// a register value), exception-generating (SVC/BRK/UDF…, vectored,
    /// not encoded), or when the instruction does not branch. `BL`
    /// resolves; `BLR` is `nil` with `branchClass == .call`, direct vs
    /// indirect stays recoverable from ``branchClass`` plus nil-ness.
    @inlinable
    var branchTarget: UInt64? {
        record.projectedBranchTarget(operands)
    }

    /// Absolute PC-relative *data* address this instruction forms or
    /// references: ADR (`address &+ offset`), ADRP
    /// (`(address & ~0xFFF) &+ page offset`, the page math lives here,
    /// never in caller arithmetic), and the PC-literal loads/prefetch ,
    /// LDR/LDRSW (literal), PRFM (literal) (`address &+ displacement`).
    /// All arithmetic is modulo 2^64. `nil` for everything else.
    @inlinable
    var pcRelativeTarget: UInt64? {
        record.projectedPCRelativeTarget(operands)
    }
}

public extension Instruction {
    /// True for BL/BLR and their authenticated variants, the
    /// control-flow transfers that write the link register
    /// (`branchClass == .call`).
    ///
    /// Does NOT claim the callee returns, nor distinguish direct from
    /// indirect (that is ``branchTarget`` being non-nil, or the
    /// mnemonic).
    @inlinable
    var isCall: Bool {
        record.projectedIsCall
    }

    /// True for RET/RETAA/RETAB (`branchClass == .return`).
    ///
    /// Does NOT claim the return address is uncorrupted or that PAC
    /// authentication succeeds.
    @inlinable
    var isReturn: Bool {
        record.projectedIsReturn
    }

    /// True when the instruction's architectural effect depends on a
    /// condition code or an encoded register/bit test: conditional
    /// branches (B.cond / CBZ / TBZ / the compare-and-branch family,
    /// via `branchClass == .conditional`) plus condition-consuming
    /// non-branches (CSEL/CSINC/CCMP/FCSEL/FCCMP…, via a
    /// `.conditionCode` operand).
    ///
    /// Does NOT include flag-consuming arithmetic (ADC/SBC read C but
    /// execute unconditionally) and does NOT claim which path is taken.
    @inlinable
    var isConditional: Bool {
        record.projectedIsConditional(operands)
    }

    /// True when the instruction semantically reads memory
    /// (`memoryAccess` ∈ {load, atomic, exclusiveLoad}); `.atomic`
    /// (read-modify-write) is both a read and a write.
    ///
    /// PRFM/PRFUM are NOT reads (an architectural hint may access
    /// nothing), callers that care see `memoryAccess == .prefetch`.
    /// Does NOT claim the access completes (it may fault), nor the
    /// address (the operands carry that).
    @inlinable
    var readsMemory: Bool {
        record.projectedReadsMemory
    }

    /// True when the instruction semantically writes memory
    /// (`memoryAccess` ∈ {store, atomic, exclusiveStore}); `.atomic`
    /// (read-modify-write) is both a read and a write.
    ///
    /// Does NOT claim the access completes (it may fault), nor the
    /// address (the operands carry that).
    @inlinable
    var writesMemory: Bool {
        record.projectedWritesMemory
    }

    /// True for single-instruction atomic read-modify-writes (the LSE
    /// atomics, CAS, SWP, `memoryAccess == .atomic`).
    ///
    /// Does NOT cover exclusive-monitor halves: an LDXR/STXR pair is
    /// atomic only as a sequence, which a per-instruction predicate
    /// cannot honestly claim, that is ``isExclusive``.
    @inlinable
    var isAtomic: Bool {
        record.projectedIsAtomic
    }

    /// True for one half of an exclusive-monitor pair
    /// (`memoryAccess` ∈ {exclusiveLoad, exclusiveStore}).
    ///
    /// Does NOT claim pairing or success (STXR's status write is
    /// visible in ``semanticWrites``).
    @inlinable
    var isExclusive: Bool {
        record.projectedIsExclusive
    }

    /// True when any of N/Z/C/V is consumed (`flagEffect`). Does NOT
    /// claim *which* flags, that is ``FlagEffect/readFlags``.
    @inlinable
    var readsFlags: Bool {
        record.projectedReadsFlags
    }

    /// True when any of N/Z/C/V is written (`flagEffect`). Does NOT
    /// claim *which* flags, that is ``FlagEffect/writtenFlags``.
    @inlinable
    var writesFlags: Bool {
        record.projectedWritesFlags
    }

    /// True when the mnemonic is one of the pointer-authentication-
    /// involved set: the standalone PAC operations
    /// (PACIA…/AUTIA…/XPAC…/PACGA), the authenticated branch/return
    /// forms (RETAA/RETAB, ERETAA/ERETAB, BRAA/BRAB/BLRAA/BLRAB and
    /// their `z` forms), the hint-space PACI*/AUTI* forms and XPACLRI,
    /// and the authenticated loads LDRAA/LDRAB.
    ///
    /// Does NOT claim which key (A/B, the mnemonic spells it), the
    /// discriminator, or runtime authentication behavior. The check is
    /// an honest projection: the mnemonic *is* the record's
    /// classification of the encoding.
    @inlinable
    var usesPointerAuthentication: Bool {
        record.projectedUsesPointerAuthentication
    }
}

extension Mnemonic {
    /// The fixed pointer-authentication mnemonic set behind
    /// ``Instruction/usesPointerAuthentication``, derived from the
    /// decoders: every `category == .pointerAuthentication` member, the
    /// BES authenticated branch/return forms, the hint-space PAC forms,
    /// and the L/S authenticated loads. Pinned by its own golden table.
    @usableFromInline
    static func involvesPointerAuthentication(_ m: Mnemonic) -> Bool {
        switch m {
        // Standalone PAC (category == .pointerAuthentication).
        case .pacia, .pacib, .pacda, .pacdb,
             .paciza, .pacizb, .pacdza, .pacdzb,
             .autia, .autib, .autda, .autdb,
             .autiza, .autizb, .autdza, .autdzb,
             .xpaci, .xpacd, .pacga:
            true
        // BES authenticated branches and returns.
        case .braa, .brab, .braaz, .brabz,
             .blraa, .blrab, .blraaz, .blrabz,
             .retaa, .retab, .eretaa, .eretab:
            true
        // Hint-space PAC forms.
        case .xpaclri,
             .pacia1716, .pacib1716, .autia1716, .autib1716,
             .paciaz, .paciasp, .pacibz, .pacibsp,
             .autiaz, .autiasp, .autibz, .autibsp:
            true
        // Authenticated loads.
        case .ldraa, .ldrab:
            true
        default:
            false
        }
    }
}
