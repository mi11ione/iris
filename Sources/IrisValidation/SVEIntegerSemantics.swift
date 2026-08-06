// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

public struct SVEIntSemanticIssue: Sendable, Equatable {
    /// Field that didn't match (e.g. "flagEffect", "scalableEffect",
    /// "registerReads").
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

/// Per-record semantic-field verification for SVE / SVE2 integer.
public enum SVEIntegerSemanticChecker {
    @_effects(readonly)
    @_optimize(speed)
    public static func verify(draft: Instruction) -> SVEIntSemanticIssue? {
        if draft.mnemonic == .undefined { return nil }
        if draft.category != .sve {
            return SVEIntSemanticIssue(field: "category", actual: "\(draft.category)", expected: "sve")
        }
        if draft.branchClass != .none {
            return SVEIntSemanticIssue(field: "branchClass", actual: "\(draft.branchClass)", expected: "none")
        }
        if draft.memoryAccess != .none {
            return SVEIntSemanticIssue(field: "memoryAccess", actual: "\(draft.memoryAccess)", expected: "none")
        }
        if draft.memoryOrdering != [] {
            return SVEIntSemanticIssue(field: "memoryOrdering", actual: "\(draft.memoryOrdering)", expected: "[]")
        }
        let expFlag = SVEIntegerSemanticAttributes.expectedFlagEffect(for: draft.mnemonic)
        if draft.flagEffect != expFlag {
            return SVEIntSemanticIssue(
                field: "flagEffect",
                actual: "\(draft.flagEffect.rawValue)", expected: "\(expFlag.rawValue)",
            )
        }
        let expEffect = SVEIntegerSemanticAttributes.expectedScalableEffect(for: draft)
        if draft.scalableEffect != expEffect {
            return SVEIntSemanticIssue(
                field: "scalableEffect",
                actual: "\(draft.scalableEffect.rawValue)", expected: "\(expEffect.rawValue)",
            )
        }
        let expPredW = SVEIntegerSemanticAttributes.expectedPredicateWrites(draft.operands)
        if draft.scalableWrites != ScalableRegisterSet(bits: UInt64(expPredW)) {
            return SVEIntSemanticIssue(
                field: "predicateWrites",
                actual: "0x\(String(draft.scalableWrites.bits, radix: 16))",
                expected: "0x\(String(expPredW, radix: 16))",
            )
        }
        let expPredR = SVEIntegerSemanticAttributes.expectedPredicateReads(draft.operands)
        if draft.scalableReads != ScalableRegisterSet(bits: UInt64(expPredR)) {
            return SVEIntSemanticIssue(
                field: "predicateReads",
                actual: "0x\(String(draft.scalableReads.bits, radix: 16))",
                expected: "0x\(String(expPredR, radix: 16))",
            )
        }
        let expRegW = SVEIntegerSemanticAttributes.expectedRegisterWrites(for: draft)
        if draft.semanticWrites.mask != expRegW {
            return SVEIntSemanticIssue(
                field: "registerWrites",
                actual: "0x\(String(draft.semanticWrites.mask, radix: 16))",
                expected: "0x\(String(expRegW, radix: 16))",
            )
        }
        let expRegR = SVEIntegerSemanticAttributes.expectedRegisterReads(for: draft)
        if draft.semanticReads.mask != expRegR {
            return SVEIntSemanticIssue(
                field: "registerReads",
                actual: "0x\(String(draft.semanticReads.mask, radix: 16))",
                expected: "0x\(String(expRegR, radix: 16))",
            )
        }
        return nil
    }
}

/// Per-mnemonic / per-operand SVE-integer semantic-attribute lookups.
public enum SVEIntegerSemanticAttributes {
    /// `.nzcv` for exactly the integer compares and MATCH/NMATCH.
    @_effects(readonly)
    public static func expectedFlagEffect(for m: Mnemonic) -> FlagEffect {
        switch m {
        case .cmpeq, .cmpge, .cmpgt, .cmphi, .cmphs,
             .cmple, .cmplo, .cmpls, .cmplt, .cmpne,
             .match, .nmatch:
            .nzcv
        default:
            .none
        }
    }

    /// `readsStreamingMode` on every SVE-integer form (all of them are vector
    /// operations whose element count comes from `CurrentVL()`, which consults
    /// `PSTATE.SM`); `partialWrite` on the merging-predicated forms plus the
    /// statically-preserving ones (see the file header).
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
        case .addhnt, .raddhnt, .subhnt, .rsubhnt,
             .shrnt, .rshrnt, .sqshrnt, .sqrshrnt, .uqshrnt, .uqrshrnt,
             .sqshrunt, .sqrshrunt, .sqxtnt, .sqxtunt, .uqxtnt,
             .eorbt, .eortb, .sli, .sri:
            true
        default:
            false
        }
    }

    /// Whether the mnemonic reads its destination even though the destination
    /// does not reappear among its source operands.
    @_effects(readonly)
    public static func readsDestination(_ m: Mnemonic) -> Bool {
        if preservesDestination(m) { return true }
        switch m {
        case .sdot, .udot, .usdot, .sudot, .cdot, .smmla, .ummla, .usmmla:
            return true
        case .mla, .mls, .sqrdmlah, .sqrdmlsh, .cmla, .sqrdcmlah,
             .smlalb, .smlalt, .umlalb, .umlalt, .smlslb, .smlslt, .umlslb, .umlslt,
             .sqdmlalb, .sqdmlalt, .sqdmlslb, .sqdmlslt, .sqdmlalbt, .sqdmlslbt,
             .mlapt, .madpt:
            return true
        case .ssra, .usra, .srsra, .ursra,
             .saba, .uaba, .sabal, .uabal, .sabalb, .sabalt, .uabalb, .uabalt,
             .adclb, .adclt, .sbclb, .sbclt, .sadalp, .uadalp:
            return true
        case .sclamp, .uclamp:
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
        case let .register(r):
            return r.isZeroRegister ? 0 : UInt64(1) << UInt64(r.canonicalIndex)
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
        case let .scalableMemory(mem):
            var mask: UInt64 = 0
            if case let .vector(base) = mem.base {
                mask |= UInt64(1) << UInt64(base.canonicalIndex)
            }
            if let index = mem.index {
                mask |= UInt64(1) << UInt64(index.canonicalIndex)
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
