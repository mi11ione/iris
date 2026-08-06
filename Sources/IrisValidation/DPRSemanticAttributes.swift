// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

@frozen
public struct DPRSemanticIssue: Sendable, Equatable {
    /// Name of the field that didn't match (e.g. "branchClass",
    /// "semanticReads.missing", "flagEffect").
    public let field: String
    /// Stringified actual value from the instruction.
    public let actual: String
    /// Stringified expected value from the spec table.
    public let expected: String

    @inlinable
    public init(field: String, actual: String, expected: String) {
        self.field = field
        self.actual = actual
        self.expected = expected
    }
}

/// Expected semantic-reads constraint.
@frozen
public struct DPRExpectedReads: Sendable, Equatable {
    public let required: UInt64
    public let allowed: UInt64

    @inlinable
    public init(required: UInt64, allowed: UInt64) {
        self.required = required
        self.allowed = allowed
    }
}

/// Per-record semantic-field verification against the ARM ARM's per-mnemonic
/// table.
public enum DPRSemanticChecker {
    /// Verify the record's classification fields against the per-mnemonic
    /// table.
    @_effects(readonly)
    @_optimize(speed)
    public static func verify(_ instruction: Instruction) -> DPRSemanticIssue? {
        if instruction.mnemonic == .undefined { return nil }
        if cryptoAppleExtensionsOwns(instruction.mnemonic) { return nil }
        if instruction.branchClass != .none {
            return DPRSemanticIssue(
                field: "branchClass",
                actual: "\(instruction.branchClass)",
                expected: "none",
            )
        }
        if instruction.memoryAccess != .none {
            return DPRSemanticIssue(
                field: "memoryAccess",
                actual: "\(instruction.memoryAccess)",
                expected: "none",
            )
        }
        if instruction.memoryOrdering != [] {
            return DPRSemanticIssue(
                field: "memoryOrdering",
                actual: "\(instruction.memoryOrdering)",
                expected: "[]",
            )
        }
        if instruction.category != .dataProcessingRegister {
            return DPRSemanticIssue(
                field: "category",
                actual: "\(instruction.category)",
                expected: "dataProcessingRegister",
            )
        }
        let expectedFlag = DPRSemanticAttributes.expectedFlagEffect(for: instruction)
        if instruction.flagEffect != expectedFlag {
            return DPRSemanticIssue(
                field: "flagEffect",
                actual: "\(instruction.flagEffect)",
                expected: "\(expectedFlag)",
            )
        }
        if let expectedReads = DPRSemanticAttributes.expectedReadMask(for: instruction) {
            if instruction.semanticReads.mask & expectedReads.required != expectedReads.required {
                return DPRSemanticIssue(
                    field: "semanticReads.missing",
                    actual: String(instruction.semanticReads.mask, radix: 16),
                    expected: "must-include 0x\(String(expectedReads.required, radix: 16))",
                )
            }
            if instruction.semanticReads.mask & ~expectedReads.allowed != 0 {
                return DPRSemanticIssue(
                    field: "semanticReads.extraneous",
                    actual: String(instruction.semanticReads.mask, radix: 16),
                    expected: "must-be-subset-of 0x\(String(expectedReads.allowed, radix: 16))",
                )
            }
        }
        if let expectedWrites = DPRSemanticAttributes.expectedWriteMask(for: instruction) {
            if instruction.semanticWrites.mask != expectedWrites {
                return DPRSemanticIssue(
                    field: "semanticWrites",
                    actual: String(instruction.semanticWrites.mask, radix: 16),
                    expected: "0x\(String(expectedWrites, radix: 16))",
                )
            }
        }
        return nil
    }
}

/// Per-mnemonic semantic-attribute lookups.
public enum DPRSemanticAttributes {
    /// The architecturally-correct `FlagEffect` for a DPR record.
    @_effects(readonly)
    public static func expectedFlagEffect(for instruction: Instruction) -> FlagEffect {
        switch instruction.mnemonic {
        case .adds, .subs, .ands, .bics, .cmp, .cmn, .tst, .negs:
            return .nzcv
        case .adc, .sbc, .ngc:
            return .readsC
        case .adcs, .sbcs, .ngcs:
            return [.nzcv, .readsC]
        case .ccmp, .ccmn:
            return [.nzcv, .readsNZCV]
        case .csel, .csinc, .csinv, .csneg, .cset, .csetm, .cinc, .cinv, .cneg:
            return .readsNZCV
        case .setf8, .setf16:
            return [.writesN, .writesZ, .writesV]
        case .rmif:
            guard instruction.operands.count >= 3,
                  case let .unsignedImmediate(value, _) = instruction.operands[2]
            else { return .nzcv }
            var fe: FlagEffect = []
            if value & 0x8 != 0 { fe.insert(.writesN) }
            if value & 0x4 != 0 { fe.insert(.writesZ) }
            if value & 0x2 != 0 { fe.insert(.writesC) }
            if value & 0x1 != 0 { fe.insert(.writesV) }
            return fe
        default:
            return .none
        }
    }

    /// Expected semantic-reads constraint for a decoded record.
    @_effects(readonly)
    public static func expectedReadMask(for instruction: Instruction) -> DPRExpectedReads? {
        let m = instruction.mnemonic
        switch m {
        case .add, .adds, .sub, .subs,
             .and, .orr, .eor, .ands,
             .bic, .orn, .eon, .bics,
             .adc, .adcs, .sbc, .sbcs,
             .udiv, .sdiv,
             .smax, .smin, .umax, .umin, .addpt, .subpt,
             .lsl, .lsr, .asr, .ror,
             .crc32b, .crc32h, .crc32w, .crc32x,
             .crc32cb, .crc32ch, .crc32cw, .crc32cx:
            let mask = registerMaskAt(operands: instruction.operands, index: 1, unwrapShiftExtend: false)
                | registerMaskAt(operands: instruction.operands, index: 2, unwrapShiftExtend: true)
            return DPRExpectedReads(required: mask, allowed: mask)
        case .cmp, .cmn, .tst:
            let mask = registerMaskAt(operands: instruction.operands, index: 0, unwrapShiftExtend: false)
                | registerMaskAt(operands: instruction.operands, index: 1, unwrapShiftExtend: true)
            return DPRExpectedReads(required: mask, allowed: mask)
        case .neg, .negs, .ngc, .ngcs, .mov, .mvn:
            let mask = registerMaskAt(operands: instruction.operands, index: 1, unwrapShiftExtend: true)
            return DPRExpectedReads(required: mask, allowed: mask)
        case .ccmp, .ccmn:
            var mask = registerMaskAt(operands: instruction.operands, index: 0, unwrapShiftExtend: false)
            mask |= registerMaskAt(operands: instruction.operands, index: 1, unwrapShiftExtend: false)
            return DPRExpectedReads(required: mask, allowed: mask)
        case .csel, .csinc, .csinv, .csneg:
            let mask = registerMaskAt(operands: instruction.operands, index: 1, unwrapShiftExtend: false)
                | registerMaskAt(operands: instruction.operands, index: 2, unwrapShiftExtend: false)
            return DPRExpectedReads(required: mask, allowed: mask)
        case .cset, .csetm:
            return DPRExpectedReads(required: 0, allowed: 0)
        case .cinc, .cinv, .cneg:
            let mask = registerMaskAt(operands: instruction.operands, index: 1, unwrapShiftExtend: false)
            return DPRExpectedReads(required: mask, allowed: mask)
        case .madd, .msub, .smaddl, .smsubl, .umaddl, .umsubl, .maddpt, .msubpt:
            let mask = registerMaskAt(operands: instruction.operands, index: 1, unwrapShiftExtend: false)
                | registerMaskAt(operands: instruction.operands, index: 2, unwrapShiftExtend: false)
                | registerMaskAt(operands: instruction.operands, index: 3, unwrapShiftExtend: false)
            return DPRExpectedReads(required: mask, allowed: mask)
        case .mul, .mneg, .smull, .smnegl, .umull, .umnegl, .smulh, .umulh:
            let mask = registerMaskAt(operands: instruction.operands, index: 1, unwrapShiftExtend: false)
                | registerMaskAt(operands: instruction.operands, index: 2, unwrapShiftExtend: false)
            return DPRExpectedReads(required: mask, allowed: mask)
        case .rbit, .rev, .rev16, .rev32, .clz, .cls, .abs, .ctz, .cnt:
            let mask = registerMaskAt(operands: instruction.operands, index: 1, unwrapShiftExtend: false)
            return DPRExpectedReads(required: mask, allowed: mask)
        case .rmif, .setf8, .setf16:
            let mask = registerMaskAt(operands: instruction.operands, index: 0, unwrapShiftExtend: false)
            return DPRExpectedReads(required: mask, allowed: mask)
        default:
            return nil
        }
    }

    /// Expected semantic-writes mask for a decoded record.
    @_effects(readonly)
    public static func expectedWriteMask(for instruction: Instruction) -> UInt64? {
        let m = instruction.mnemonic
        switch m {
        case .cmp, .cmn, .tst, .ccmp, .ccmn, .rmif, .setf8, .setf16:
            return 0
        case .add, .adds, .sub, .subs,
             .and, .orr, .eor, .ands,
             .bic, .orn, .eon, .bics,
             .adc, .adcs, .sbc, .sbcs,
             .neg, .negs, .ngc, .ngcs,
             .mov, .mvn,
             .csel, .csinc, .csinv, .csneg,
             .cset, .csetm, .cinc, .cinv, .cneg,
             .madd, .msub, .smaddl, .smsubl, .umaddl, .umsubl,
             .smulh, .umulh,
             .mul, .mneg, .smull, .smnegl, .umull, .umnegl,
             .udiv, .sdiv,
             .lsl, .lsr, .asr, .ror,
             .rbit, .rev, .rev16, .rev32, .clz, .cls,
             .abs, .ctz, .cnt, .smax, .smin, .umax, .umin,
             .addpt, .subpt, .maddpt, .msubpt,
             .crc32b, .crc32h, .crc32w, .crc32x,
             .crc32cb, .crc32ch, .crc32cw, .crc32cx:
            return registerMaskAt(operands: instruction.operands, index: 0, unwrapShiftExtend: false)
        default:
            return nil
        }
    }

    /// Extract the canonical-index bit-mask of the register at `index` in the
    /// operand list.
    @_effects(readonly)
    @inline(__always)
    public static func registerMaskAt(
        operands: Instruction.Operands, index: Int, unwrapShiftExtend: Bool,
    ) -> UInt64 {
        guard index >= 0, index < operands.count else { return 0 }
        let op = operands[index]
        let reg: RegisterRef? = switch op {
        case let .register(r): r
        case let .shiftedRegister(r, _, _): unwrapShiftExtend ? r : nil
        case let .extendedRegister(r, _, _): unwrapShiftExtend ? r : nil
        default: nil
        }
        guard let r = reg else { return 0 }
        if r.isZeroRegister { return 0 }
        return UInt64(1) << UInt64(r.canonicalIndex)
    }
}
