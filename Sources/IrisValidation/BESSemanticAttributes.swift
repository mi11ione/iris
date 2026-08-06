// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

@frozen
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

/// Per-record semantic-field verification against the family's per-mnemonic
/// table.
public enum BESSemanticChecker {
    /// Verify the record's classification fields.
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
        let expectedFlags = BESSemanticAttributes.expectedFlagEffect(for: instruction)
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

/// Expected semantic-reads constraint per mnemonic.
@frozen
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
/// expected-attribute table.
public enum BESSemanticAttributes {
    /// PSTATE.NZCV read/write effect for a BES record. `NZCV` is the one
    /// system register whose MRS/MSR transfer is a condition-flag transfer,
    /// so the two moves are classified from the encoding rather than the
    /// mnemonic alone.
    @_effects(readonly)
    public static func expectedFlagEffect(for instruction: Instruction) -> FlagEffect {
        switch instruction.mnemonic {
        case .bCond, .bcCond:
            .readsNZCV
        case .cfinv:
            [.writesC, .readsC]
        case .xaflag, .axflag:
            [.nzcv, .readsNZCV]
        case .msr:
            BESSemanticAttributes.namesNZCV(instruction.encoding) ? .nzcv : .none
        case .mrs:
            BESSemanticAttributes.namesNZCV(instruction.encoding) ? .readsNZCV : .none
        default:
            .none
        }
    }

    /// Whether an MRS/MSR encoding names PSTATE's `NZCV` (op0 3, op1 3,
    /// CRn 4, CRm 2, op2 0).
    @_effects(readonly)
    public static func namesNZCV(_ encoding: UInt32) -> Bool {
        (encoding & 0x001F_FFE0) == 0x001B_4200
    }

    /// The architecturally-correct `BranchClass` for a BES mnemonic (per ARM
    /// ARM § C4.1.5 + Apple ARM64E PAuth supplement).
    @_effects(readonly)
    public static func expectedBranchClass(for m: Mnemonic) -> BranchClass {
        switch m {
        case .b: .direct
        case .bl, .blr, .blraa, .blrab, .blraaz, .blrabz: .call
        case .br, .braa, .brab, .braaz, .brabz: .indirect
        case .ret, .retaa, .retab, .eret, .eretaa, .eretab, .drps: .return
        case .retaasppc, .retabsppc, .retaasppcr, .retabsppcr: .return
        case .texit, .texitNb: .return
        case .tenter, .tenterNb: .exception
        case .bCond, .bcCond, .cbz, .cbnz, .tbz, .tbnz: .conditional
        case .cbgt, .cbge, .cbhi, .cbhs, .cbeq, .cbne, .cblt, .cblo,
             .cbbgt, .cbbge, .cbbhi, .cbbhs, .cbbeq, .cbbne,
             .cbhgt, .cbhge, .cbhhi, .cbhhs, .cbheq, .cbhne: .conditional
        case .svc, .hvc, .smc, .brk, .hlt, .dcps1, .dcps2, .dcps3: .exception
        case .udf: .exception
        default: .none
        }
    }

    /// Expected semantic-reads constraint for a decoded record.
    @_effects(readonly)
    public static func expectedReadMask(for instruction: Instruction) -> BESExpectedReads? {
        let m = instruction.mnemonic
        switch m {
        case .b, .bl, .bCond, .bcCond,
             .svc, .hvc, .smc, .brk, .hlt,
             .dcps1, .dcps2, .dcps3,
             .eret, .eretaa, .eretab, .drps,
             .nop, .yield, .wfe, .wfi, .sev, .sevl,
             .dgh, .csdb, .esb, .psb, .tsb, .gcsbDsync,
             .bti, .chkfeat, .clrbhb, .hint,
             .clrex, .dsb, .dmb, .isb, .sb, .ssbb, .pssbb,
             .cfinv, .xaflag, .axflag, .msrImm,
             .smstart, .smstop,
             .mrs,
             .pacm, .stshh, .shuh, .stcph, .dfb,
             .tenter, .tenterNb, .texit, .texitNb:
            return BESExpectedReads(required: 0, allowed: 0)
        case .tchangef, .tchangefNb, .tchangeb, .tchangebNb:
            let source = BESSemanticAttributes.tchangeSourceMask(instruction.operands)
            return BESExpectedReads(required: source, allowed: source)
        case .retaasppc, .retabsppc:
            let lrBit = UInt64(1) << 30
            let spBit = UInt64(1) << 31
            return BESExpectedReads(required: lrBit | spBit, allowed: lrBit | spBit)
        case .retaasppcr, .retabsppcr:
            let regs = (UInt64(1) << 30)
                | (BESSemanticAttributes.firstRegisterMask(instruction.operands) ?? 0)
            return BESExpectedReads(required: regs, allowed: regs)
        case .paciasp, .pacibsp, .autiasp, .autibsp:
            let mask = (UInt64(1) << 30) | (UInt64(1) << 31)
            return BESExpectedReads(required: mask, allowed: mask)
        case .paciaz, .pacibz, .autiaz, .autibz, .xpaclri:
            let mask = UInt64(1) << 30
            return BESExpectedReads(required: mask, allowed: mask)
        case .pacia1716, .pacib1716, .autia1716, .autib1716:
            let mask = (UInt64(1) << 17) | (UInt64(1) << 16)
            return BESExpectedReads(required: mask, allowed: mask)
        case .cbz, .cbnz, .tbz, .tbnz,
             .br, .blr, .ret,
             .braaz, .brabz, .blraaz, .blrabz,
             .wfet, .wfit:
            if let firstReg = BESSemanticAttributes.firstRegisterMask(instruction.operands) {
                return BESExpectedReads(required: firstReg, allowed: firstReg)
            }
            return BESExpectedReads(required: 0, allowed: 0xFFFF_FFFF_FFFF_FFFF)
        case .braa, .brab, .blraa, .blrab:
            let regs = BESSemanticAttributes.firstTwoRegistersMask(instruction.operands)
            return BESExpectedReads(required: regs, allowed: regs)
        case .cbgt, .cbge, .cbhi, .cbhs, .cbeq, .cbne, .cblt, .cblo,
             .cbbgt, .cbbge, .cbbhi, .cbbhs, .cbbeq, .cbbne,
             .cbhgt, .cbhge, .cbhhi, .cbhhs, .cbheq, .cbhne:
            let regs = BESSemanticAttributes.firstTwoRegistersMask(instruction.operands)
            return BESExpectedReads(required: regs, allowed: regs)
        case .retaa, .retab:
            let lrBit = UInt64(1) << 30
            let spBit = UInt64(1) << 31
            return BESExpectedReads(required: lrBit | spBit, allowed: lrBit | spBit)
        case .msr:
            if let lastReg = BESSemanticAttributes.lastRegisterMask(instruction.operands) {
                return BESExpectedReads(required: lastReg, allowed: lastReg)
            }
            return BESExpectedReads(required: 0, allowed: 0xFFFF_FFFF_FFFF_FFFF)
        case .sys:
            return sysExpectedReads(instruction)
        case .sysl:
            return BESExpectedReads(required: 0, allowed: 0)
        case .mrrs:
            return BESExpectedReads(required: 0, allowed: 0)
        case .msrr:
            let regs = BESSemanticAttributes.firstTwoRegistersMask(instruction.operands)
            return BESExpectedReads(required: regs, allowed: regs)
        case .sysp:
            return syspExpectedReads(instruction)
        default:
            return nil
        }
    }

    /// Mask of TCHANGE's `Xn` source, or 0 for the immediate form.
    @_effects(readonly)
    private static func tchangeSourceMask(_ operands: Instruction.Operands) -> UInt64 {
        guard operands.count >= 2, case let .register(reg) = operands[1] else { return 0 }
        return UInt64(1) << UInt64(reg.canonicalIndex)
    }

    /// SYSP-specific expected reads.
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

    /// SYS-specific expected reads.
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
    @_effects(readonly)
    public static func expectedWriteMask(for instruction: Instruction) -> UInt64? {
        let m = instruction.mnemonic
        let lrBit = UInt64(1) << 30
        switch m {
        case .bl, .blr, .blraa, .blrab, .blraaz, .blrabz:
            return lrBit
        case .mrs:
            return BESSemanticAttributes.firstRegisterMask(instruction.operands) ?? 0
        case .mrrs:
            return BESSemanticAttributes.firstTwoRegistersMask(instruction.operands)
        case .sysl:
            let enc = instruction.encoding
            let op1 = UInt8((enc >> 16) & 0x7)
            let CRn = UInt8((enc >> 12) & 0xF)
            let CRm = UInt8((enc >> 8) & 0xF)
            let op2 = UInt8((enc >> 5) & 0x7)
            let Rt = UInt8(enc & 0x1F)
            let alias = BESSyslAliasTable.lookup(op1: op1, CRn: CRn, CRm: CRm, op2: op2)
            let writesRt = alias.map { $0.touchesRt(Rt) } ?? true
            return writesRt ? (UInt64(1) << UInt64(Rt)) : 0
        case .paciasp, .pacibsp, .autiasp, .autibsp,
             .paciaz, .pacibz, .autiaz, .autibz,
             .xpaclri:
            return lrBit
        case .pacia1716, .pacib1716, .autia1716, .autib1716:
            return UInt64(1) << 17
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
             .dgh, .csdb, .esb, .psb, .tsb, .gcsbDsync,
             .bti, .chkfeat, .clrbhb, .hint,
             .clrex, .dsb, .dmb, .isb, .sb, .ssbb, .pssbb,
             .cfinv, .xaflag, .axflag, .msrImm,
             .msr, .sys, .wfet, .wfit,
             .msrr, .sysp,
             .smstart, .smstop,
             .pacm, .stshh, .shuh, .stcph, .dfb,
             .tenter, .tenterNb, .texit, .texitNb,
             .retaasppc, .retabsppc, .retaasppcr, .retabsppcr:
            return 0
        case .tchangef, .tchangefNb, .tchangeb, .tchangebNb:
            return BESSemanticAttributes.firstRegisterMask(instruction.operands) ?? 0
        default:
            return nil
        }
    }

    /// Mask of the first `Operand/register(_:)` in the operand list, or `nil`
    /// if no register operand is present.
    @_effects(readonly)
    public static func firstRegisterMask(_ operands: Instruction.Operands) -> UInt64? {
        for op in operands {
            if case let .register(reg) = op {
                return UInt64(1) << UInt64(reg.canonicalIndex)
            }
        }
        return nil
    }

    /// Mask of the last `Operand/register(_:)` in the operand list, or `nil`
    /// if no register operand is present.
    @_effects(readonly)
    public static func lastRegisterMask(_ operands: Instruction.Operands) -> UInt64? {
        for op in operands.reversed() {
            if case let .register(reg) = op {
                return UInt64(1) << UInt64(reg.canonicalIndex)
            }
        }
        return nil
    }

    /// Mask of the first two `Operand/register(_:)` entries in the operand
    /// list.
    @_effects(readonly)
    public static func firstTwoRegistersMask(_ operands: Instruction.Operands) -> UInt64 {
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
