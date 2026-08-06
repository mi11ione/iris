// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

@frozen
public struct DPISemanticIssue: Sendable, Equatable {
    /// Field that didn't match (e.g. "flagEffect", "semanticReads.missing").
    public let field: String
    /// Stringified actual value from the instruction.
    public let actual: String
    /// Stringified expected value.
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
public struct DPIExpectedReads: Sendable, Equatable {
    public let required: UInt64
    public let allowed: UInt64

    @inlinable
    public init(required: UInt64, allowed: UInt64) {
        self.required = required
        self.allowed = allowed
    }
}

/// Per-record semantic-field verification for DPI.
public enum DPISemanticChecker {
    @_effects(readonly)
    @_optimize(speed)
    public static func verify(_ instruction: Instruction) -> DPISemanticIssue? {
        if instruction.mnemonic == .undefined { return nil }
        if cryptoAppleExtensionsOwns(instruction.mnemonic) { return nil }
        if instruction.branchClass != .none {
            return DPISemanticIssue(field: "branchClass", actual: "\(instruction.branchClass)", expected: "none")
        }
        if instruction.memoryAccess != .none {
            return DPISemanticIssue(field: "memoryAccess", actual: "\(instruction.memoryAccess)", expected: "none")
        }
        if instruction.memoryOrdering != [] {
            return DPISemanticIssue(field: "memoryOrdering", actual: "\(instruction.memoryOrdering)", expected: "[]")
        }
        if instruction.category != .dataProcessingImmediate {
            return DPISemanticIssue(
                field: "category", actual: "\(instruction.category)", expected: "dataProcessingImmediate",
            )
        }
        let expectedFlag = DPISemanticAttributes.expectedFlagEffect(for: instruction.mnemonic)
        if instruction.flagEffect != expectedFlag {
            return DPISemanticIssue(field: "flagEffect", actual: "\(instruction.flagEffect)", expected: "\(expectedFlag)")
        }
        if let reads = DPISemanticAttributes.expectedReadMask(for: instruction) {
            if instruction.semanticReads.mask & reads.required != reads.required {
                return DPISemanticIssue(
                    field: "semanticReads.missing",
                    actual: String(instruction.semanticReads.mask, radix: 16),
                    expected: "must-include 0x\(String(reads.required, radix: 16))",
                )
            }
            if instruction.semanticReads.mask & ~reads.allowed != 0 {
                return DPISemanticIssue(
                    field: "semanticReads.extraneous",
                    actual: String(instruction.semanticReads.mask, radix: 16),
                    expected: "must-be-subset-of 0x\(String(reads.allowed, radix: 16))",
                )
            }
        }
        if let writes = DPISemanticAttributes.expectedWriteMask(for: instruction) {
            if instruction.semanticWrites.mask != writes {
                return DPISemanticIssue(
                    field: "semanticWrites",
                    actual: String(instruction.semanticWrites.mask, radix: 16),
                    expected: "0x\(String(writes, radix: 16))",
                )
            }
        }
        return nil
    }
}

/// Per-mnemonic DPI semantic-attribute lookups.
public enum DPISemanticAttributes {
    /// The architecturally-correct `FlagEffect` for a DPI mnemonic.
    @_effects(readonly)
    public static func expectedFlagEffect(for m: Mnemonic) -> FlagEffect {
        switch m {
        case .adds, .subs, .ands, .cmp, .cmn, .tst:
            .nzcv
        default:
            .none
        }
    }

    /// Expected semantic-reads constraint for a decoded record, derived from
    /// its operand list.
    @_effects(readonly)
    public static func expectedReadMask(for instruction: Instruction) -> DPIExpectedReads? {
        let ops = instruction.operands
        func reg(_ i: Int) -> UInt64 {
            registerMaskAt(operands: ops, index: i)
        }
        switch instruction.mnemonic {
        case .add, .sub, .adds, .subs,
             .and, .orr, .eor, .ands,
             .asr, .lsr, .lsl, .ror,
             .sxtb, .sxth, .sxtw, .uxtb, .uxth,
             .sbfiz, .sbfx, .ubfiz, .ubfx,
             .sbfm, .ubfm:
            let m = reg(1)
            return DPIExpectedReads(required: m, allowed: m)
        case .cmp, .cmn, .tst:
            let m = reg(0)
            return DPIExpectedReads(required: m, allowed: m)
        case .mov:
            let m = reg(1)
            return DPIExpectedReads(required: m, allowed: m)
        case .movn, .movz, .adr, .adrp:
            return DPIExpectedReads(required: 0, allowed: 0)
        case .movk:
            let m = reg(0)
            return DPIExpectedReads(required: m, allowed: m)
        case .extr:
            let rm = reg(2)
            return DPIExpectedReads(required: rm, allowed: reg(1) | rm)
        case .bfi:
            let m = reg(0) | reg(1)
            return DPIExpectedReads(required: m, allowed: m)
        case .bfxil, .bfm:
            return DPIExpectedReads(required: reg(1), allowed: reg(0) | reg(1))
        case .bfc:
            return DPIExpectedReads(required: 0, allowed: reg(0))
        default:
            return nil
        }
    }

    /// Expected semantic-writes mask for a decoded record.
    @_effects(readonly)
    public static func expectedWriteMask(for instruction: Instruction) -> UInt64? {
        switch instruction.mnemonic {
        case .cmp, .cmn, .tst:
            0
        case .add, .sub, .adds, .subs,
             .and, .orr, .eor, .ands,
             .mov, .movn, .movz, .movk,
             .adr, .adrp,
             .extr, .ror,
             .bfm, .sbfm, .ubfm,
             .bfi, .bfxil, .bfc,
             .sbfiz, .sbfx, .ubfiz, .ubfx,
             .asr, .lsr, .lsl,
             .sxtb, .sxth, .sxtw, .uxtb, .uxth:
            registerMaskAt(operands: instruction.operands, index: 0)
        default:
            nil
        }
    }

    /// Canonical-index bit-mask of the register at `index`, or 0 if the index
    /// is out of range, the operand isn't a plain register, or the register is
    /// XZR/WZR (per the `insertingNonZero` convention the decoder uses).
    @_effects(readonly)
    @inline(__always)
    public static func registerMaskAt(operands: Instruction.Operands, index: Int) -> UInt64 {
        guard index >= 0, index < operands.count else { return 0 }
        guard case let .register(r) = operands[index] else { return 0 }
        if r.isZeroRegister { return 0 }
        return UInt64(1) << UInt64(r.canonicalIndex)
    }
}
