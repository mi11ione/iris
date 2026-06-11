// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Per-mnemonic semantic attribute tables + verification
// helpers. Mirrors `Decode/BranchesExceptionSystem/BESSemanticAttributes.swift`
// shape exactly — same public types (`DPRSemanticIssue`,
// `DPRExpectedReads`, `DPRSemanticChecker`, `DPRSemanticAttributes`),
// same `verify(_:) -> DPRSemanticIssue?` entry point, same
// required+allowed pair semantics for read-mask expectations.
//
// Every DPR record has `branchClass == .none`, `memoryAccess == .none`,
// `memoryOrdering == []`, `category == .dataProcessingRegister` —
// universal invariants. `flagEffect`, `semanticReads`, `semanticWrites`
// are mnemonic-specific per the ARM ARM.

/// Concrete semantic-field discrepancy between a decoded record and the
/// expected attributes. Returned by ``DPRSemanticChecker/verify(_:)``.
@frozen
@_spi(Validation)
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

/// Expected semantic-reads constraint. `required` is the
/// minimum bitset (must be a subset of `instruction.semanticReads.mask`);
/// `allowed` is the maximum (the actual mask must be a subset). For
/// variable-Rn instructions the loose pair lets callers verify "Rn is in
/// the reads, no extraneous regs" without extracting Rn for every encoding.
@frozen
@_spi(Validation)
public struct DPRExpectedReads: Sendable, Equatable {
    public let required: UInt64
    public let allowed: UInt64

    @inlinable
    public init(required: UInt64, allowed: UInt64) {
        self.required = required
        self.allowed = allowed
    }
}

/// Per-record semantic-field verification against the ARM ARM's
/// per-mnemonic table. Returns `nil` when the record matches every
/// expected attribute; returns the first mismatch otherwise.
@_spi(Validation)
public enum DPRSemanticChecker {
    /// Verify the record's classification fields match the per-mnemonic
    /// table. Every DPR mnemonic has `branchClass == .none`,
    /// `memoryAccess == .none`, `memoryOrdering == []`,
    /// `category == .dataProcessingRegister` —
    /// these are universal invariants. `flagEffect`, `semanticReads`,
    /// `semanticWrites` are mnemonic-specific.
    /// UNDEFINED records are skipped (their semantic fields are
    /// empty by construction).
    @_effects(readonly)
    @_optimize(speed)
    public static func verify(_ instruction: Instruction) -> DPRSemanticIssue? {
        if instruction.mnemonic == .undefined { return nil }
        // PAC standalone / PACGA / MTE-DPR records flow through the
        // DPR family decoder via top-of-method delegation; their semantic
        // attributes are verified by the crypto/Apple-extensions checker,
        // not this one.
        if CryptoAppleExtensionsCanonicalizer.owns(instruction.mnemonic) { return nil }
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
/// Pure functions; constant-folded at module load.
@_spi(Validation)
public enum DPRSemanticAttributes {
    /// The architecturally-correct ``FlagEffect`` for a DPR record — both the
    /// flags written and the flags read. Carry-consuming arithmetic (the
    /// ADC/SBC family) reads C; conditional compare and select read the full
    /// condition; RMIF writes only its mask-selected flags and SETF8/SETF16
    /// preserve C.
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
            // Writes exactly the flags the imm4 mask operand selects (bit3→N,
            // bit2→Z, bit1→C, bit0→V); reads none.
            guard Array(instruction.operands).count >= 3,
                  case let .unsignedImmediate(value, _) = Array(instruction.operands)[2]
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

    /// Expected semantic-reads constraint for a decoded
    /// record. The mask is computed from the draft's operand list using
    /// per-family extraction (helpers below): the first/second/third
    /// register operand, possibly unwrapping `.shiftedRegister` or
    /// `.extendedRegister`.
    @_effects(readonly)
    public static func expectedReadMask(for instruction: Instruction) -> DPRExpectedReads? {
        let m = instruction.mnemonic
        switch m {
        // Three-operand reads: Rn (operand[1]) + Rm-wrapped (operand[2]).
        case .add, .adds, .sub, .subs,
             .and, .orr, .eor, .ands,
             .bic, .orn, .eon, .bics,
             .adc, .adcs, .sbc, .sbcs,
             .udiv, .sdiv,
             .smax, .smin, .umax, .umin, .addpt, .subpt,
             .lsl, .lsr, .asr, .ror,
             .crc32b, .crc32h, .crc32w, .crc32x,
             .crc32cb, .crc32ch, .crc32cw, .crc32cx:
            let mask = registerMaskAt(operands: Array(instruction.operands), index: 1, unwrapShiftExtend: false)
                | registerMaskAt(operands: Array(instruction.operands), index: 2, unwrapShiftExtend: true)
            return DPRExpectedReads(required: mask, allowed: mask)
        // CMP/CMN/TST: operand[0]=Rn, operand[1]=Rm-wrapped.
        case .cmp, .cmn, .tst:
            let mask = registerMaskAt(operands: Array(instruction.operands), index: 0, unwrapShiftExtend: false)
                | registerMaskAt(operands: Array(instruction.operands), index: 1, unwrapShiftExtend: true)
            return DPRExpectedReads(required: mask, allowed: mask)
        // NEG/NEGS: operand[0]=Rd, operand[1]=Rm-wrapped. Reads only Rm.
        // NGC/NGCS / MOV / MVN: operand[0]=Rd, operand[1]=Rm-possibly-wrapped.
        case .neg, .negs, .ngc, .ngcs, .mov, .mvn:
            let mask = registerMaskAt(operands: Array(instruction.operands), index: 1, unwrapShiftExtend: true)
            return DPRExpectedReads(required: mask, allowed: mask)
        // CCMP/CCMN register form: operand[0]=Rn, operand[1]=Rm.
        // CCMP/CCMN immediate form: operand[0]=Rn, operand[1]=imm5.
        // The mask is "first register" plus optional "second register if
        // operand[1] is a register"; helper handles both shapes.
        case .ccmp, .ccmn:
            var mask = registerMaskAt(operands: Array(instruction.operands), index: 0, unwrapShiftExtend: false)
            mask |= registerMaskAt(operands: Array(instruction.operands), index: 1, unwrapShiftExtend: false)
            return DPRExpectedReads(required: mask, allowed: mask)
        // CSEL/CSINC/CSINV/CSNEG base: operand[0]=Rd, [1]=Rn, [2]=Rm.
        case .csel, .csinc, .csinv, .csneg:
            let mask = registerMaskAt(operands: Array(instruction.operands), index: 1, unwrapShiftExtend: false)
                | registerMaskAt(operands: Array(instruction.operands), index: 2, unwrapShiftExtend: false)
            return DPRExpectedReads(required: mask, allowed: mask)
        // CSET/CSETM: operand[0]=Rd. Reads empty (Rn=Rm=XZR dropped).
        case .cset, .csetm:
            return DPRExpectedReads(required: 0, allowed: 0)
        // CINC/CINV/CNEG: operand[0]=Rd, [1]=Rn. Reads Rn only (Rn=Rm).
        case .cinc, .cinv, .cneg:
            let mask = registerMaskAt(operands: Array(instruction.operands), index: 1, unwrapShiftExtend: false)
            return DPRExpectedReads(required: mask, allowed: mask)
        // MADD/MSUB/SMADDL/SMSUBL/UMADDL/UMSUBL base 4-operand:
        // [0]=Rd, [1]=Rn, [2]=Rm, [3]=Ra. Reads {Rn, Rm, Ra}.
        case .madd, .msub, .smaddl, .smsubl, .umaddl, .umsubl, .maddpt, .msubpt:
            let mask = registerMaskAt(operands: Array(instruction.operands), index: 1, unwrapShiftExtend: false)
                | registerMaskAt(operands: Array(instruction.operands), index: 2, unwrapShiftExtend: false)
                | registerMaskAt(operands: Array(instruction.operands), index: 3, unwrapShiftExtend: false)
            return DPRExpectedReads(required: mask, allowed: mask)
        // MUL/MNEG/SMULL/SMNEGL/UMULL/UMNEGL aliases 3-operand:
        // [0]=Rd, [1]=Rn, [2]=Rm. Reads {Rn, Rm}.
        // SMULH/UMULH same shape.
        case .mul, .mneg, .smull, .smnegl, .umull, .umnegl, .smulh, .umulh:
            let mask = registerMaskAt(operands: Array(instruction.operands), index: 1, unwrapShiftExtend: false)
                | registerMaskAt(operands: Array(instruction.operands), index: 2, unwrapShiftExtend: false)
            return DPRExpectedReads(required: mask, allowed: mask)
        // Data-processing 1-source: [0]=Rd, [1]=Rn. Reads {Rn}. CSSC
        // ABS/CTZ/CNT share the shape.
        case .rbit, .rev, .rev16, .rev32, .clz, .cls, .abs, .ctz, .cnt:
            let mask = registerMaskAt(operands: Array(instruction.operands), index: 1, unwrapShiftExtend: false)
            return DPRExpectedReads(required: mask, allowed: mask)
        // FlagM: RMIF / SETF8 / SETF16 read Rn at operand[0] (RMIF's other
        // operands are immediates; SETF* has none).
        case .rmif, .setf8, .setf16:
            let mask = registerMaskAt(operands: Array(instruction.operands), index: 0, unwrapShiftExtend: false)
            return DPRExpectedReads(required: mask, allowed: mask)
        default:
            return nil
        }
    }

    /// Expected semantic-writes mask for a decoded record.
    /// All non-CMP/CMN/TST/CCMP/CCMN/CSET/CSETM DPR records write Rd
    /// (operand[0]); the flag-effect-only ones write nothing in the GP
    /// register set.
    @_effects(readonly)
    public static func expectedWriteMask(for instruction: Instruction) -> UInt64? {
        let m = instruction.mnemonic
        switch m {
        // No GP write — flag-effect-only or no-effect-by-encoding.
        case .cmp, .cmn, .tst, .ccmp, .ccmn, .rmif, .setf8, .setf16:
            return 0
        // Every other DPR mnemonic writes Rd (operand[0]).
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
            return registerMaskAt(operands: Array(instruction.operands), index: 0, unwrapShiftExtend: false)
        default:
            return nil
        }
    }

    /// Extract the canonical-index bit-mask of the register at `index`
    /// in the operand list. When `unwrapShiftExtend` is true, also
    /// unwraps `.shiftedRegister` and `.extendedRegister` to their inner
    /// register. Returns 0 if the index is out of range, the operand
    /// isn't a register variant, or the register is XZR/WZR (per the
    /// `insertingNonZero` convention used by the decoder).
    @_effects(readonly)
    @inline(__always)
    public static func registerMaskAt(
        operands: [Operand], index: Int, unwrapShiftExtend: Bool,
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
