// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

public struct SVEPCSemanticIssue: Sendable, Equatable {
    /// Field that didn't match (e.g. "flagEffect", "scalableEffect",
    /// "predicateWrites").
    public let field: String
    /// Stringified actual value from the draft.
    public let actual: String
    /// Stringified expected value.
    public let expected: String

    public init(field: String, actual: String, expected: String) {
        self.field = field
        self.actual = actual
        self.expected = expected
    }
}

/// Per-record semantic-field verification for SVE predicate & control.
public enum SVEPredicateControlSemanticChecker {
    @_effects(readonly)
    @_optimize(speed)
    public static func verify(draft: Instruction) -> SVEPCSemanticIssue? {
        if draft.mnemonic == .undefined { return nil }
        if draft.category != .sve {
            return SVEPCSemanticIssue(field: "category", actual: "\(draft.category)", expected: "sve")
        }
        if draft.branchClass != .none {
            return SVEPCSemanticIssue(field: "branchClass", actual: "\(draft.branchClass)", expected: "none")
        }
        if draft.memoryAccess != .none {
            return SVEPCSemanticIssue(field: "memoryAccess", actual: "\(draft.memoryAccess)", expected: "none")
        }
        if draft.memoryOrdering != [] {
            return SVEPCSemanticIssue(field: "memoryOrdering", actual: "\(draft.memoryOrdering)", expected: "[]")
        }
        let expFlag = SVEPredicateControlSemanticAttributes.expectedFlagEffect(for: draft.mnemonic)
        if draft.flagEffect != expFlag {
            return SVEPCSemanticIssue(field: "flagEffect", actual: "\(draft.flagEffect.rawValue)", expected: "\(expFlag.rawValue)")
        }
        let expEffect = SVEPredicateControlSemanticAttributes.expectedScalableEffect(for: draft)
        if draft.scalableEffect != expEffect {
            return SVEPCSemanticIssue(field: "scalableEffect", actual: "\(draft.scalableEffect.rawValue)", expected: "\(expEffect.rawValue)")
        }
        let (ffrR, ffrW) = SVEPredicateControlSemanticAttributes.expectedFFR(for: draft.mnemonic)
        if draft.scalableReads.containsFFR != ffrR {
            return SVEPCSemanticIssue(field: "ffrRead", actual: "\(draft.scalableReads.containsFFR)", expected: "\(ffrR)")
        }
        if draft.scalableWrites.containsFFR != ffrW {
            return SVEPCSemanticIssue(field: "ffrWrite", actual: "\(draft.scalableWrites.containsFFR)", expected: "\(ffrW)")
        }
        let expPredW = SVEPredicateControlSemanticAttributes.expectedPredicateWrites(draft.operands)
        if draft.scalableWrites.predicateMask != expPredW {
            return SVEPCSemanticIssue(
                field: "predicateWrites",
                actual: "0x\(String(draft.scalableWrites.predicateMask, radix: 16))",
                expected: "0x\(String(expPredW, radix: 16))",
            )
        }
        let expPredR = SVEPredicateControlSemanticAttributes.expectedPredicateReads(draft.operands)
        if draft.scalableReads.predicateMask != expPredR {
            return SVEPCSemanticIssue(
                field: "predicateReads",
                actual: "0x\(String(draft.scalableReads.predicateMask, radix: 16))",
                expected: "0x\(String(expPredR, radix: 16))",
            )
        }
        let expRegW = SVEPredicateControlSemanticAttributes.expectedRegisterWrites(for: draft)
        if draft.semanticWrites.mask != expRegW {
            return SVEPCSemanticIssue(
                field: "registerWrites",
                actual: "0x\(String(draft.semanticWrites.mask, radix: 16))",
                expected: "0x\(String(expRegW, radix: 16))",
            )
        }
        let expRegR = SVEPredicateControlSemanticAttributes.expectedRegisterReads(for: draft)
        if draft.semanticReads.mask != expRegR {
            return SVEPCSemanticIssue(
                field: "registerReads",
                actual: "0x\(String(draft.semanticReads.mask, radix: 16))",
                expected: "0x\(String(expRegR, radix: 16))",
            )
        }
        return nil
    }
}

/// Per-mnemonic / per-operand SVE predicate-control semantic-attribute
/// lookups.
public enum SVEPredicateControlSemanticAttributes {
    /// Architecturally-correct `FlagEffect`: `.nzcv` for the S-suffixed forms
    /// + PTEST/PFIRST/PNEXT/all WHILE; CTERM writes N,V and reads C (its own
    /// set); everything else `.none`.
    @_effects(readonly)
    public static func expectedFlagEffect(for m: Mnemonic) -> FlagEffect {
        switch m {
        case .ptrues, .ptest, .pfirst, .pnext,
             .ands, .bics, .eors, .orrs, .orns, .nands, .nors, .movs, .nots,
             .brkas, .brkbs, .brkns, .brkpas, .brkpbs, .rdffrs,
             .whilege, .whilegt, .whilelt, .whilele, .whilehs, .whilehi,
             .whilelo, .whilels, .whilerw, .whilewr:
            .nzcv
        case .ctermeq, .ctermne:
            [.writesN, .writesV, .readsC]
        default:
            .none
        }
    }

    /// Architecturally-correct `ScalableEffect`: `readsStreamingMode` on every
    /// in-scope form except CTERM and the SVL twins, and `partialWrite` on
    /// exactly BRKA/M, BRKB/M, PFIRST and MOVPRFX/M — the four lane-preserving
    /// RMW forms.
    @_effects(readonly)
    public static func expectedScalableEffect(for draft: Instruction) -> ScalableEffect {
        var e: ScalableEffect = []
        switch draft.mnemonic {
        case .ctermeq, .ctermne, .rdsvl, .addsvl, .addspl:
            break
        default:
            e.insert(.readsStreamingMode)
        }
        if draft.mnemonic == .pfirst {
            e.insert(.partialWrite)
        } else if draft.mnemonic == .brka || draft.mnemonic == .brkb || draft.mnemonic == .movprfx {
            if hasMergingGoverning(draft.operands) {
                e.insert(.partialWrite)
            }
        }
        return e
    }

    /// Expected (FFR-read, FFR-write) for a mnemonic.
    @_effects(readonly)
    public static func expectedFFR(for m: Mnemonic) -> (read: Bool, write: Bool) {
        switch m {
        case .rdffr, .rdffrs: (true, false)
        case .wrffr, .setffr: (false, true)
        default: (false, false)
        }
    }

    /// Predicate-write mask = the result-role predicate operands.
    @_effects(readonly)
    public static func expectedPredicateWrites(_ ops: Instruction.Operands) -> UInt16 {
        var mask: UInt16 = 0
        for op in ops {
            if case let .scalablePredicate(p) = op, p.role == .result {
                mask |= UInt16(1) << UInt16(p.registerIndex & 0xF)
            }
        }
        return mask
    }

    /// Predicate-read mask = every non-result predicate operand, plus the
    /// result predicate when a governing predicate is merging (`/M` reads the
    /// destination as an RMW source).
    @_effects(readonly)
    public static func expectedPredicateReads(_ ops: Instruction.Operands) -> UInt16 {
        var reads: UInt16 = 0
        var results: UInt16 = 0
        var merging = false
        for op in ops {
            guard case let .scalablePredicate(p) = op else { continue }
            let bit = UInt16(1) << UInt16(p.registerIndex & 0xF)
            if p.role == .result {
                results |= bit
            } else {
                reads |= bit
            }
            if p.qualifier == .merging { merging = true }
        }
        if merging { reads |= results }
        return reads
    }

    /// Register-write mask: the destination operand (operand 0) for the forms
    /// that write a GPR or a Z register; empty for the pure predicate/flag
    /// forms.
    @_effects(readonly)
    public static func expectedRegisterWrites(for draft: Instruction) -> UInt64 {
        switch draft.mnemonic {
        case .cntp, .rdvl, .rdsvl, .addvl, .addsvl, .addpl, .addspl,
             .cntb, .cnth, .cntw, .cntd,
             .incp, .decp, .sqincp, .uqincp, .sqdecp, .uqdecp,
             .incb, .inch, .incw, .incd, .decb, .dech, .decw, .decd,
             .sqincb, .sqinch, .sqincw, .sqincd, .uqincb, .uqinch, .uqincw, .uqincd,
             .sqdecb, .sqdech, .sqdecw, .sqdecd, .uqdecb, .uqdech, .uqdecw, .uqdecd,
             .index, .movprfx:
            operandRegisterMask(draft.operands, 0)
        default:
            0
        }
    }

    /// Register-read mask, per-mnemonic rule over the operand list.
    @_effects(readonly)
    public static func expectedRegisterReads(for draft: Instruction) -> UInt64 {
        let ops = draft.operands
        switch draft.mnemonic {
        case .whilege, .whilegt, .whilelt, .whilele, .whilehs, .whilehi,
             .whilelo, .whilels, .whilerw, .whilewr:
            return operandRegisterMask(ops, 1) | operandRegisterMask(ops, 2)
        case .ctermeq, .ctermne:
            return operandRegisterMask(ops, 0) | operandRegisterMask(ops, 1)
        case .addvl, .addsvl, .addpl, .addspl:
            return operandRegisterMask(ops, 1)
        case .incp, .decp, .sqincp, .uqincp, .sqdecp, .uqdecp,
             .incb, .inch, .incw, .incd, .decb, .dech, .decw, .decd,
             .sqincb, .sqinch, .sqincw, .sqincd, .uqincb, .uqinch, .uqincw, .uqincd,
             .sqdecb, .sqdech, .sqdecw, .sqdecd, .uqdecb, .uqdech, .uqdecw, .uqdecd:
            return operandRegisterMask(ops, 0)
        case .index:
            return operandRegisterMask(ops, 1) | operandRegisterMask(ops, 2)
        case .movprfx:
            if ops.count == 2 { return operandRegisterMask(ops, 1) }
            var r = operandRegisterMask(ops, 2)
            if hasMergingGoverning(ops) { r |= operandRegisterMask(ops, 0) }
            return r
        default:
            return 0
        }
    }

    /// The canonical-index bitmask for the register/vector operand at `index`
    /// (XZR/WZR → 0; SP → bit 31; Z_n / V_n → bit 32+n), or 0 otherwise.
    @_effects(readonly)
    @inline(__always)
    public static func operandRegisterMask(_ ops: Instruction.Operands, _ index: Int) -> UInt64 {
        guard index >= 0, index < ops.count else { return 0 }
        switch ops[index] {
        case let .register(r):
            if r.isZeroRegister { return 0 }
            return UInt64(1) << UInt64(r.canonicalIndex)
        case let .scalableVector(v):
            return UInt64(1) << UInt64(v.canonicalIndex)
        default:
            return 0
        }
    }

    /// Whether any governing predicate operand is merging (`/M`).
    @_effects(readonly)
    public static func hasMergingGoverning(_ ops: Instruction.Operands) -> Bool {
        for op in ops {
            if case let .scalablePredicate(p) = op, p.qualifier == .merging {
                return true
            }
        }
        return false
    }
}
