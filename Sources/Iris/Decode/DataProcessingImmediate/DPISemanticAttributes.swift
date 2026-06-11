// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Per-mnemonic semantic-attribute tables + verification for the Data
// Processing — Immediate family. Mirrors DPRSemanticAttributes' shape.
//
// Text parity proves mnemonic + operands against llvm-mc;
// disassembly text does NOT encode flagEffect, semanticReads, or
// semanticWrites, so this checker proves those independently. Expected
// reads/writes are derived from the (text-validated) operand list by
// architectural rule — a separate computation from the decoder's own
// attribute logic, so a divergence between the two surfaces a bug.
//
// Every DPI record has branchClass == .none, memoryAccess == .none,
// memoryOrdering == [], category == .dataProcessingImmediate — universal
// invariants. flagEffect, semanticReads, semanticWrites are mnemonic-specific.

/// Concrete semantic-field discrepancy between a decoded record and the
/// architectural expectation. Returned by ``DPISemanticChecker/verify(_:)``.
@frozen
@_spi(Validation)
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

/// Expected semantic-reads constraint. `required` is the minimum bitset
/// (must be a subset of the draft's reads); `allowed` is the maximum (the
/// reads must be a subset of it). The loose pair covers instructions whose
/// read set varies with immediate fields not present as register operands:
/// EXTR reads Rn only when the shift amount is non-zero, and the full-width
/// BFM forms overwrite all of Rd so they drop the read-modify-write Rd read.
@frozen
@_spi(Validation)
public struct DPIExpectedReads: Sendable, Equatable {
    public let required: UInt64
    public let allowed: UInt64

    @inlinable
    public init(required: UInt64, allowed: UInt64) {
        self.required = required
        self.allowed = allowed
    }
}

/// Per-record semantic-field verification for DPI. Returns `nil` when the
/// record matches every expected attribute; the first mismatch otherwise.
@_spi(Validation)
public enum DPISemanticChecker {
    @_effects(readonly)
    @_optimize(speed)
    public static func verify(_ instruction: Instruction) -> DPISemanticIssue? {
        if instruction.mnemonic == .undefined { return nil }
        // MTE ADDG/SUBG reach the DPI decoder via its op1=0b011 branch but
        // belong to the Crypto/Apple-extensions family; that family's own
        // checker verifies their attributes.
        if CryptoAppleExtensionsCanonicalizer.owns(instruction.mnemonic) { return nil }
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

/// Per-mnemonic DPI semantic-attribute lookups. Pure functions over the
/// decoded mnemonic and operand list.
@_spi(Validation)
public enum DPISemanticAttributes {
    /// The architecturally-correct ``FlagEffect`` for a DPI mnemonic:
    /// `.nzcv` for the flag-setting forms (and the CMP/CMN/TST aliases),
    /// `.none` for everything else.
    @_effects(readonly)
    public static func expectedFlagEffect(for m: Mnemonic) -> FlagEffect {
        switch m {
        case .adds, .subs, .ands, .cmp, .cmn, .tst:
            .nzcv
        default:
            .none
        }
    }

    /// Expected semantic-reads constraint for a decoded record, derived
    /// from its operand list.
    @_effects(readonly)
    public static func expectedReadMask(for instruction: Instruction) -> DPIExpectedReads? {
        let ops = Array(instruction.operands)
        func reg(_ i: Int) -> UInt64 {
            registerMaskAt(operands: ops, index: i)
        }
        switch instruction.mnemonic {
        // [Rd, Rn, ...] — reads Rn (operand[1]).
        case .add, .sub, .adds, .subs,
             .and, .orr, .eor, .ands,
             .asr, .lsr, .lsl, .ror,
             .sxtb, .sxth, .sxtw, .uxtb, .uxth,
             .sbfiz, .sbfx, .ubfiz, .ubfx,
             .sbfm, .ubfm:
            let m = reg(1)
            return DPIExpectedReads(required: m, allowed: m)
        // [Rn, ...] (Rd dropped) — reads operand[0].
        case .cmp, .cmn, .tst:
            let m = reg(0)
            return DPIExpectedReads(required: m, allowed: m)
        // MOV: [Rd, Rn] reads Rn; [Rd, #imm] reads nothing. reg(1) is 0
        // for the immediate form.
        case .mov:
            let m = reg(1)
            return DPIExpectedReads(required: m, allowed: m)
        // Write-only Rd; no register read.
        case .movn, .movz, .adr, .adrp:
            return DPIExpectedReads(required: 0, allowed: 0)
        // MOVK preserves the un-replaced bits of Rd, so it reads Rd (operand[0]).
        case .movk:
            let m = reg(0)
            return DPIExpectedReads(required: m, allowed: m)
        // EXTR [Rd, Rn, Rm, #lsb]: reads Rm (operand[2]) always; Rn
        // (operand[1]) only when the shift is non-zero.
        case .extr:
            let rm = reg(2)
            return DPIExpectedReads(required: rm, allowed: reg(1) | rm)
        // BFI [Rd, Rn, #lsb, #width]: read-modify-write reads Rd + Rn
        // (always a partial field — never the full-width form).
        case .bfi:
            let m = reg(0) | reg(1)
            return DPIExpectedReads(required: m, allowed: m)
        // BFXIL [Rd, Rn, #lsb, #width]: reads Rn always; reads Rd unless
        // the full-width copy form overwrites all of Rd.
        case .bfxil, .bfm:
            return DPIExpectedReads(required: reg(1), allowed: reg(0) | reg(1))
        // BFC [Rd, #lsb, #width]: Rn is XZR (dropped); reads Rd unless the
        // full-width form overwrites all of Rd.
        case .bfc:
            return DPIExpectedReads(required: 0, allowed: reg(0))
        default:
            return nil
        }
    }

    /// Expected semantic-writes mask for a decoded record. CMP/CMN/TST set
    /// flags only (no GP write); every other DPI mnemonic writes Rd
    /// (operand[0]).
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
            registerMaskAt(operands: Array(instruction.operands), index: 0)
        default:
            nil
        }
    }

    /// Canonical-index bit-mask of the register at `index`, or 0 if the
    /// index is out of range, the operand isn't a plain register, or the
    /// register is XZR/WZR (per the `insertingNonZero` convention the
    /// decoder uses). DPI register operands are always plain `.register`.
    @_effects(readonly)
    @inline(__always)
    public static func registerMaskAt(operands: [Operand], index: Int) -> UInt64 {
        guard index >= 0, index < operands.count else { return 0 }
        guard case let .register(r) = operands[index] else { return 0 }
        if r.isZeroRegister { return 0 }
        return UInt64(1) << UInt64(r.canonicalIndex)
    }
}
