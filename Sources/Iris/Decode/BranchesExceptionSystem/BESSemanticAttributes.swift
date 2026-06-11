// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Per-mnemonic semantic attribute tables + verification
// helpers: the canonical encoding of the family's architectural
// expectations (branchClass,
// memoryAccess/Ordering, flagEffect, category, semanticReads/Writes
// per BES mnemonic). Any caller that wants to verify a decoded record
// against those expectations — parity tooling, test suites,
// downstream consumers — uses ``BESSemanticChecker/verify(_:)``.
//
// The register-mask helpers (`firstRegisterMask`, `lastRegisterMask`,
// `firstTwoRegistersMask`) are general-purpose operand-list utilities;
// they live here because they pair with the semantic check, but could
// reasonably migrate to a future `Operand+RegisterMasks` extension if a
// non-BES caller wants them too.

/// Concrete semantic-field discrepancy between a decoded record and the
/// expected-attribute table. Returned by ``BESSemanticChecker/verify(_:)``.
@frozen
@_spi(Validation)
public struct BESSemanticIssue: Sendable, Equatable {
    /// Name of the field that didn't match (e.g. "branchClass",
    /// "semanticReads.missing", "memoryAccess").
    public let field: String
    /// Stringified actual value from the instruction.
    public let actual: String
    /// Stringified expected value from the attribute table.
    public let expected: String

    @inlinable
    public init(field: String, actual: String, expected: String) {
        self.field = field
        self.actual = actual
        self.expected = expected
    }
}

/// Per-record semantic-field verification against the family's
/// per-mnemonic table. Returns `nil` when the record matches every
/// expected attribute; returns the first mismatch otherwise.
@_spi(Validation)
public enum BESSemanticChecker {
    /// Verify the record's classification fields. Every BES mnemonic has
    /// `memoryAccess == .none`, `memoryOrdering == []`, and
    /// `category == .branchesExceptionSystem` — universal invariants.
    /// `flagEffect`, `branchClass`, `semanticReads`, and `semanticWrites`
    /// are mnemonic-specific (the condition consumers B.cond/BC.cond read
    /// NZCV; CFINV / XAFLAG / AXFLAG read and write flags). UNDEFINED records
    /// are skipped (their semantic fields are empty by construction).
    @_effects(readonly)
    public static func verify(_ instruction: Instruction) -> BESSemanticIssue? {
        if instruction.mnemonic == .undefined { return nil }
        if instruction.memoryAccess != .none {
            return BESSemanticIssue(
                field: "memoryAccess",
                actual: "\(instruction.memoryAccess)",
                expected: "none",
            )
        }
        if instruction.memoryOrdering != [] {
            return BESSemanticIssue(
                field: "memoryOrdering",
                actual: "\(instruction.memoryOrdering)",
                expected: "[]",
            )
        }
        let expectedFlags = BESSemanticAttributes.expectedFlagEffect(for: instruction.mnemonic)
        if instruction.flagEffect != expectedFlags {
            return BESSemanticIssue(
                field: "flagEffect",
                actual: "\(instruction.flagEffect)",
                expected: "\(expectedFlags)",
            )
        }
        if instruction.category != .branchesExceptionSystem {
            return BESSemanticIssue(
                field: "category",
                actual: "\(instruction.category)",
                expected: "branchesExceptionSystem",
            )
        }
        let expectedClass = BESSemanticAttributes.expectedBranchClass(for: instruction.mnemonic)
        if instruction.branchClass != expectedClass {
            return BESSemanticIssue(
                field: "branchClass",
                actual: "\(instruction.branchClass)",
                expected: "\(expectedClass)",
            )
        }
        if let expectedReads = BESSemanticAttributes.expectedReadMask(for: instruction) {
            if instruction.semanticReads.mask & expectedReads.required != expectedReads.required {
                return BESSemanticIssue(
                    field: "semanticReads.missing",
                    actual: String(instruction.semanticReads.mask, radix: 16),
                    expected: "must-include 0x\(String(expectedReads.required, radix: 16))",
                )
            }
            if instruction.semanticReads.mask & ~expectedReads.allowed != 0 {
                return BESSemanticIssue(
                    field: "semanticReads.extraneous",
                    actual: String(instruction.semanticReads.mask, radix: 16),
                    expected: "must-be-subset-of 0x\(String(expectedReads.allowed, radix: 16))",
                )
            }
        }
        if let expectedWrites = BESSemanticAttributes.expectedWriteMask(for: instruction) {
            if instruction.semanticWrites.mask != expectedWrites {
                return BESSemanticIssue(
                    field: "semanticWrites",
                    actual: String(instruction.semanticWrites.mask, radix: 16),
                    expected: "0x\(String(expectedWrites, radix: 16))",
                )
            }
        }
        return nil
    }
}

/// Expected semantic-reads constraint per mnemonic. `required` is the
/// minimum bitset (must be a subset of `instruction.semanticReads.mask`);
/// `allowed` is the maximum (the actual mask must be a subset).
///
/// For variable-Rn instructions (BR, CBZ, etc.) the helpers use this
/// loose pair so callers don't need to extract Rn for every encoding —
/// they verify "Rn is in the reads, no extraneous regs."
@frozen
@_spi(Validation)
public struct BESExpectedReads: Sendable, Equatable {
    public let required: UInt64
    public let allowed: UInt64

    @inlinable
    public init(required: UInt64, allowed: UInt64) {
        self.required = required
        self.allowed = allowed
    }
}

/// Per-mnemonic semantic-attribute lookups encoding the family's
/// expected-attribute table. Pure functions; constant-folded at module load.
@_spi(Validation)
public enum BESSemanticAttributes {
    /// PSTATE.NZCV read/write effect for a BES mnemonic. Most BES
    /// instructions touch no flags; the exceptions are the condition
    /// consumers and the flag-format manipulators: B.cond / BC.cond read the
    /// condition; CFINV inverts (reads + writes) carry; XAFLAG / AXFLAG
    /// transform (read + write) all four flags.
    @_effects(readonly)
    public static func expectedFlagEffect(for m: Mnemonic) -> FlagEffect {
        switch m {
        case .bCond, .bcCond:
            .readsNZCV
        case .cfinv:
            [.writesC, .readsC]
        case .xaflag, .axflag:
            [.nzcv, .readsNZCV]
        default:
            .none
        }
    }

    /// The architecturally-correct ``BranchClass`` for a BES mnemonic
    /// (per ARM ARM § C4.1.5 + Apple ARM64E PAuth supplement). Returns
    /// `.none` for non-branch BES mnemonics (HINT / barrier / MSR /
    /// MRS / SYS / SYSL / WFET / WFIT / CFINV / XAFLAG / AXFLAG).
    @_effects(readonly)
    public static func expectedBranchClass(for m: Mnemonic) -> BranchClass {
        switch m {
        case .b: .direct
        case .bl, .blr, .blraa, .blrab, .blraaz, .blrabz: .call
        case .br, .braa, .brab, .braaz, .brabz: .indirect
        case .ret, .retaa, .retab, .eret, .eretaa, .eretab, .drps: .return
        case .bCond, .bcCond, .cbz, .cbnz, .tbz, .tbnz: .conditional
        case .cbgt, .cbge, .cbhi, .cbhs, .cbeq, .cbne, .cblt, .cblo,
             .cbbgt, .cbbge, .cbbhi, .cbbhs, .cbbeq, .cbbne,
             .cbhgt, .cbhge, .cbhhi, .cbhhs, .cbheq, .cbhne: .conditional
        case .svc, .hvc, .smc, .brk, .hlt, .dcps1, .dcps2, .dcps3: .exception
        // UDF (dispatcher-owned, routed to BES) generates an Undefined
        // Instruction exception — same class as BRK/HLT.
        case .udf: .exception
        default: .none
        }
    }

    /// Expected semantic-reads constraint for a decoded
    /// record. Returns `nil` for mnemonics whose reads are alias- or
    /// encoding-dependent (currently SYS / SYSL — the decoder gates
    /// reads on the alias table's `touchesRt(_:)`).
    @_effects(readonly)
    public static func expectedReadMask(for instruction: Instruction) -> BESExpectedReads? {
        let m = instruction.mnemonic
        switch m {
        case .b, .bl, .bCond, .bcCond,
             .svc, .hvc, .smc, .brk, .hlt,
             .dcps1, .dcps2, .dcps3,
             .eret, .eretaa, .eretab, .drps,
             .nop, .yield, .wfe, .wfi, .sev, .sevl,
             .dgh, .csdb, .esb, .psb, .tsb, .gcsbDsync, .xpaclri,
             .paciaz, .paciasp, .pacibz, .pacibsp,
             .autiaz, .autiasp, .autibz, .autibsp,
             .pacia1716, .pacib1716, .autia1716, .autib1716,
             .bti, .chkfeat, .clrbhb, .hint,
             .clrex, .dsb, .dmb, .isb, .sb, .ssbb, .pssbb,
             .cfinv, .xaflag, .axflag, .msrImm,
             .smstart, .smstop,
             .mrs:
            return BESExpectedReads(required: 0, allowed: 0)
        case .cbz, .cbnz, .tbz, .tbnz,
             .br, .blr, .ret,
             .braaz, .brabz, .blraaz, .blrabz,
             .wfet, .wfit:
            if let firstReg = BESSemanticAttributes.firstRegisterMask(Array(instruction.operands)) {
                return BESExpectedReads(required: firstReg, allowed: firstReg)
            }
            return BESExpectedReads(required: 0, allowed: 0xFFFF_FFFF_FFFF_FFFF)
        case .braa, .brab, .blraa, .blrab:
            let regs = BESSemanticAttributes.firstTwoRegistersMask(Array(instruction.operands))
            return BESExpectedReads(required: regs, allowed: regs)
        case .cbgt, .cbge, .cbhi, .cbhs, .cbeq, .cbne, .cblt, .cblo,
             .cbbgt, .cbbge, .cbbhi, .cbbhs, .cbbeq, .cbbne,
             .cbhgt, .cbhge, .cbhhi, .cbhhs, .cbheq, .cbhne:
            // Register/byte/halfword forms read Rt + Rm; immediate forms
            // read only Rt. Derive from the operand shape (the shared
            // mnemonics span both forms).
            let regs = BESSemanticAttributes.firstTwoRegistersMask(Array(instruction.operands))
            return BESExpectedReads(required: regs, allowed: regs)
        case .retaa, .retab:
            let lrBit = UInt64(1) << 30
            let spBit = UInt64(1) << 31
            return BESExpectedReads(required: lrBit | spBit, allowed: lrBit | spBit)
        case .msr:
            if let lastReg = BESSemanticAttributes.lastRegisterMask(Array(instruction.operands)) {
                return BESExpectedReads(required: lastReg, allowed: lastReg)
            }
            return BESExpectedReads(required: 0, allowed: 0xFFFF_FFFF_FFFF_FFFF)
        case .sys:
            // Alias-dependent: SYS reads Rt only when the alias touches
            // it. The checker mirrors the decoder's alias-table lookup
            // so mutations to the decoder's gating are caught.
            return sysExpectedReads(instruction)
        case .sysl:
            // SYSL never reads Rt (it WRITES Rt — handled in expectedWriteMask).
            return BESExpectedReads(required: 0, allowed: 0)
        case .mrrs:
            // MRRS reads the system register only (writes the GP pair).
            return BESExpectedReads(required: 0, allowed: 0)
        case .msrr:
            // MSRR reads the (Rt, Rt+1) GP pair.
            let regs = BESSemanticAttributes.firstTwoRegistersMask(Array(instruction.operands))
            return BESExpectedReads(required: regs, allowed: regs)
        case .sysp:
            // SYSP reads the (Rt, Rt+1) pair when present (alias or Rt != 31).
            return syspExpectedReads(instruction)
        default:
            return nil
        }
    }

    /// SYSP-specific expected reads: the (Rt, Rt+1) pair is read when a
    /// TLBIP alias matches (always) or when Rt != 31 (generic form renders
    /// the pair); a generic SYSP with Rt == 31 reads nothing.
    @_effects(readonly)
    private static func syspExpectedReads(_ instruction: Instruction) -> BESExpectedReads {
        let enc = instruction.encoding
        let op1 = UInt8((enc >> 16) & 0x7)
        let CRn = UInt8((enc >> 12) & 0xF)
        let CRm = UInt8((enc >> 8) & 0xF)
        let op2 = UInt8((enc >> 5) & 0x7)
        let Rt = UInt8(enc & 0x1F)
        let aliased = BESSyspAliasTable.lookup(op1: op1, CRn: CRn, CRm: CRm, op2: op2) != nil
        if aliased || Rt != 31 {
            let rt2: UInt8 = (Rt == 31) ? 31 : (Rt &+ 1)
            let mask = (UInt64(1) << UInt64(Rt)) | (UInt64(1) << UInt64(rt2))
            return BESExpectedReads(required: mask, allowed: mask)
        }
        return BESExpectedReads(required: 0, allowed: 0)
    }

    /// SYS-specific expected reads: extracts the (op1, CRn, CRm, op2)
    /// tuple from the encoding, looks it up in the SYS alias table, and
    /// derives the Rt-read mask from the alias's `touchesRt(_:)`.
    /// Without a matching alias, falls back to Rt != 31 heuristic
    /// (matching the decoder's behavior).
    @_effects(readonly)
    private static func sysExpectedReads(_ instruction: Instruction) -> BESExpectedReads {
        let enc = instruction.encoding
        let op1 = UInt8((enc >> 16) & 0x7)
        let CRn = UInt8((enc >> 12) & 0xF)
        let CRm = UInt8((enc >> 8) & 0xF)
        let op2 = UInt8((enc >> 5) & 0x7)
        let Rt = UInt8(enc & 0x1F)
        let alias = BESSysAliasTable.lookup(op1: op1, CRn: CRn, CRm: CRm, op2: op2)
        let readsRt = alias.map { $0.touchesRt(Rt) } ?? (Rt != 31)
        if readsRt {
            let mask = UInt64(1) << UInt64(Rt)
            return BESExpectedReads(required: mask, allowed: mask)
        }
        return BESExpectedReads(required: 0, allowed: 0)
    }

    /// Expected semantic-writes mask for a decoded record.
    /// Returns `nil` for mnemonics whose writes are encoding-dependent
    /// (currently SYSL — its Rt write depends on the encoded Rt field).
    @_effects(readonly)
    public static func expectedWriteMask(for instruction: Instruction) -> UInt64? {
        let m = instruction.mnemonic
        let lrBit = UInt64(1) << 30
        switch m {
        case .bl, .blr, .blraa, .blrab, .blraaz, .blrabz:
            return lrBit
        case .mrs:
            return BESSemanticAttributes.firstRegisterMask(Array(instruction.operands)) ?? 0
        case .mrrs:
            // MRRS writes the (Rt, Rt+1) GP pair.
            return BESSemanticAttributes.firstTwoRegistersMask(Array(instruction.operands))
        case .sysl:
            // SYSL writes Rt. An aliased SYSL gates Rt on its kind (e.g.
            // `gcspopm` doesn't write when Rt == 31); generic SYSL always
            // writes Rt (rendered verbatim, including xzr).
            let enc = instruction.encoding
            let op1 = UInt8((enc >> 16) & 0x7)
            let CRn = UInt8((enc >> 12) & 0xF)
            let CRm = UInt8((enc >> 8) & 0xF)
            let op2 = UInt8((enc >> 5) & 0x7)
            let Rt = UInt8(enc & 0x1F)
            let alias = BESSyslAliasTable.lookup(op1: op1, CRn: CRn, CRm: CRm, op2: op2)
            let writesRt = alias.map { $0.touchesRt(Rt) } ?? true
            return writesRt ? (UInt64(1) << UInt64(Rt)) : 0
        case .b, .bCond, .bcCond,
             .cbz, .cbnz, .tbz, .tbnz,
             .cbgt, .cbge, .cbhi, .cbhs, .cbeq, .cbne, .cblt, .cblo,
             .cbbgt, .cbbge, .cbbhi, .cbbhs, .cbbeq, .cbbne,
             .cbhgt, .cbhge, .cbhhi, .cbhhs, .cbheq, .cbhne,
             .br, .ret,
             .braa, .brab, .braaz, .brabz,
             .retaa, .retab, .eret, .eretaa, .eretab, .drps,
             .svc, .hvc, .smc, .brk, .hlt,
             .dcps1, .dcps2, .dcps3,
             .nop, .yield, .wfe, .wfi, .sev, .sevl,
             .dgh, .csdb, .esb, .psb, .tsb, .gcsbDsync, .xpaclri,
             .paciaz, .paciasp, .pacibz, .pacibsp,
             .autiaz, .autiasp, .autibz, .autibsp,
             .pacia1716, .pacib1716, .autia1716, .autib1716,
             .bti, .chkfeat, .clrbhb, .hint,
             .clrex, .dsb, .dmb, .isb, .sb, .ssbb, .pssbb,
             .cfinv, .xaflag, .axflag, .msrImm,
             .msr, .sys, .wfet, .wfit,
             .msrr, .sysp,
             .smstart, .smstop:
            return 0
        default:
            return nil
        }
    }

    /// Mask of the first ``Operand/register(_:)`` in the operand list,
    /// or `nil` if no register operand is present. Used to extract the
    /// per-mnemonic Rt / Rn for verification.
    @_effects(readonly)
    public static func firstRegisterMask(_ operands: [Operand]) -> UInt64? {
        for op in operands {
            if case let .register(reg) = op {
                return UInt64(1) << UInt64(reg.canonicalIndex)
            }
        }
        return nil
    }

    /// Mask of the last ``Operand/register(_:)`` in the operand list,
    /// or `nil` if no register operand is present. Used to extract the
    /// trailing Rt in MSR `[.systemRegister, .register(Rt)]` shape.
    @_effects(readonly)
    public static func lastRegisterMask(_ operands: [Operand]) -> UInt64? {
        for op in operands.reversed() {
            if case let .register(reg) = op {
                return UInt64(1) << UInt64(reg.canonicalIndex)
            }
        }
        return nil
    }

    /// Mask of the first two ``Operand/register(_:)`` entries in the
    /// operand list. Used to extract the (Rn, Rm) pair for two-operand
    /// auth-branches (BRAA / BRAB / BLRAA / BLRAB).
    @_effects(readonly)
    public static func firstTwoRegistersMask(_ operands: [Operand]) -> UInt64 {
        var mask: UInt64 = 0
        var count = 0
        for op in operands {
            if case let .register(reg) = op {
                mask |= UInt64(1) << UInt64(reg.canonicalIndex)
                count &+= 1
                if count >= 2 { break }
            }
        }
        return mask
    }
}
