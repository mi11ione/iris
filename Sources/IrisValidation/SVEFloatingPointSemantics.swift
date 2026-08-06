// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

public struct SVEFPSemanticIssue: Sendable, Equatable {
    /// Field that didn't match (e.g. "flagEffect", "scalableEffect",
    /// "registerReads").
    public let field: String
    /// Stringified actual value from the draft.
    public let actual: String
    /// Stringified expected value.
    public let expected: String
}

/// Per-record semantic-field verification for SVE / SVE2 floating-point.
public enum SVEFloatingPointSemanticChecker {
    @_effects(readonly)
    @_optimize(speed)
    public static func verify(draft: Instruction) -> SVEFPSemanticIssue? {
        if draft.mnemonic == .undefined { return nil }
        if draft.category != .sve {
            return SVEFPSemanticIssue(field: "category", actual: "\(draft.category)", expected: "sve")
        }
        if draft.branchClass != .none {
            return SVEFPSemanticIssue(field: "branchClass", actual: "\(draft.branchClass)", expected: "none")
        }
        if draft.memoryAccess != .none {
            return SVEFPSemanticIssue(field: "memoryAccess", actual: "\(draft.memoryAccess)", expected: "none")
        }
        if draft.memoryOrdering != [] {
            return SVEFPSemanticIssue(field: "memoryOrdering", actual: "\(draft.memoryOrdering)", expected: "[]")
        }
        if draft.flagEffect != .none {
            return SVEFPSemanticIssue(
                field: "flagEffect",
                actual: "\(draft.flagEffect.rawValue)", expected: "\(FlagEffect.none.rawValue)",
            )
        }
        let expEffect = SVEFloatingPointSemanticAttributes.expectedScalableEffect(for: draft)
        if draft.scalableEffect != expEffect {
            return SVEFPSemanticIssue(
                field: "scalableEffect",
                actual: "\(draft.scalableEffect.rawValue)", expected: "\(expEffect.rawValue)",
            )
        }
        let expPredW = SVEFloatingPointSemanticAttributes.expectedPredicateWrites(draft.operands)
        if draft.scalableWrites != ScalableRegisterSet(bits: UInt64(expPredW)) {
            return SVEFPSemanticIssue(
                field: "predicateWrites",
                actual: "0x\(String(draft.scalableWrites.bits, radix: 16))",
                expected: "0x\(String(expPredW, radix: 16))",
            )
        }
        let expPredR = SVEFloatingPointSemanticAttributes.expectedPredicateReads(draft.operands)
        if draft.scalableReads != ScalableRegisterSet(bits: UInt64(expPredR)) {
            return SVEFPSemanticIssue(
                field: "predicateReads",
                actual: "0x\(String(draft.scalableReads.bits, radix: 16))",
                expected: "0x\(String(expPredR, radix: 16))",
            )
        }
        let expRegW = SVEFloatingPointSemanticAttributes.expectedRegisterWrites(for: draft)
        if draft.semanticWrites.mask != expRegW {
            return SVEFPSemanticIssue(
                field: "registerWrites",
                actual: "0x\(String(draft.semanticWrites.mask, radix: 16))",
                expected: "0x\(String(expRegW, radix: 16))",
            )
        }
        let expRegR = SVEFloatingPointSemanticAttributes.expectedRegisterReads(for: draft)
        if draft.semanticReads.mask != expRegR {
            return SVEFPSemanticIssue(
                field: "registerReads",
                actual: "0x\(String(draft.semanticReads.mask, radix: 16))",
                expected: "0x\(String(expRegR, radix: 16))",
            )
        }
        return nil
    }
}

/// Per-mnemonic / per-operand SVE floating-point semantic-attribute lookups.
public enum SVEFloatingPointSemanticAttributes {
    /// `readsStreamingMode` on every SVE-FP form (all are vector operations
    /// whose element count comes from `CurrentVL()`); `partialWrite` on the
    /// merging-predicated forms plus the statically-preserving top-half
    /// converts (see the file header).
    @_effects(readonly)
    public static func expectedScalableEffect(for draft: Instruction) -> ScalableEffect {
        var effect: ScalableEffect = .readsStreamingMode
        if hasMergingGoverning(draft.operands) || preservesDestination(draft.mnemonic) {
            effect.insert(.partialWrite)
        }
        return effect
    }

    /// Whether the mnemonic leaves part of its destination's prior value
    /// intact at statically-known positions.
    @_effects(readonly)
    public static func preservesDestination(_ m: Mnemonic) -> Bool {
        switch m {
        case .fcvtnt, .fcvtxnt, .bfcvtnt:
            true
        default:
            false
        }
    }

    /// Whether the mnemonic reads its destination without the destination
    /// reappearing among its sources.
    @_effects(readonly)
    public static func readsDestination(_ m: Mnemonic) -> Bool {
        if preservesDestination(m) { return true }
        switch m {
        case .fmla, .fmls, .bfmla, .bfmls, .fcmla,
             .fdot, .bfdot, .fmmla, .bfmmla,
             .fmlalb, .fmlalt, .fmlslb, .fmlslt,
             .bfmlalb, .bfmlalt, .bfmlslb, .bfmlslt,
             .fmlallbb, .fmlallbt, .fmlalltb, .fmlalltt,
             .fclamp, .bfclamp:
            return true
        default:
            return false
        }
    }

    /// The result-role predicate operands.
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

    /// The governing predicates.
    @_effects(readonly)
    public static func expectedPredicateReads(_ ops: Instruction.Operands) -> UInt16 {
        var reads: UInt16 = 0
        var results: UInt16 = 0
        var merging = false
        for op in ops {
            guard case let .scalablePredicate(p) = op else { continue }
            let bit = UInt16(1) << UInt16(p.registerIndex & 0xF)
            if p.role == .result { results |= bit } else { reads |= bit }
            if p.qualifier == .merging { merging = true }
        }
        return merging ? reads | results : reads
    }

    /// The destination operand, when it is a register.
    @_effects(readonly)
    public static func expectedRegisterWrites(for draft: Instruction) -> UInt64 {
        guard let first = draft.operands.first else { return 0 }
        return registerMask(first)
    }

    /// Every source operand's register, plus the destination when the form
    /// reads it (merging predicate, accumulator, clamp, or preserving write).
    @_effects(readonly)
    public static func expectedRegisterReads(for draft: Instruction) -> UInt64 {
        let ops = draft.operands
        guard let first = ops.first else { return 0 }
        var mask: UInt64 = 0
        for index in 1 ..< ops.count {
            mask |= registerMask(ops[index])
        }
        if hasMergingGoverning(ops) || readsDestination(draft.mnemonic) {
            mask |= registerMask(first)
        }
        return mask
    }

    /// The canonical-index bitmask of an operand's register(s).
    @_effects(readonly)
    public static func registerMask(_ op: Operand) -> UInt64 {
        switch op {
        case let .scalableVector(v):
            return UInt64(1) << UInt64(v.canonicalIndex)
        case let .vectorRegister(v):
            return UInt64(1) << UInt64(32 &+ v.registerIndex)
        case let .scalableVectorGroup(g):
            var mask: UInt64 = 0
            for j in 0 ..< g.count {
                mask |= UInt64(1) << UInt64(32 &+ g.memberIndex(j))
            }
            return mask
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
