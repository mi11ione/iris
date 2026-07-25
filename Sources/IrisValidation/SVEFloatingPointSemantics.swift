// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Per-record semantic-attribute verification for SVE-FP — SVE / SVE2
// floating-point. The text-parity validator proves mnemonic + operands
// against llvm-mc, but disassembly text does NOT encode `flagEffect`,
// `scalableEffect` (partialWrite / readsStreamingMode), or the semantic
// read/write sets — so this checker proves those independently, deriving
// expectations from the (text-validated) operand list plus the mnemonic as
// a computation entirely separate from the decode sites.
//
// The two rules that carry the weight, both settled against ARM's A64 ISA
// XML pseudocode (2025-12) and cross-checked against LLVM's register model:
//
// * `flagEffect` is `.none` on every SVE-FP form INCLUDING the compares —
// FCMEQ…FCMUO and FACGE/FACGT write a destination predicate and never
// PSTATE.NZCV (zero PSTATE references in their ASL), the deliberate
// contrast with SVE-integer's integer compares. FP exception state (FPSR) and
// the ambient FPCR/FPMR mode registers are out-of-band, per the SIMD/FP
// deviation.
//
// * `partialWrite` is set exactly when part of the destination's prior
// value SURVIVES: every merging (`/M`) form, plus the top-half converts
// FCVTNT/FCVTXNT/BFCVTNT in ALL their forms — the ASL seeds `result`
// from Z(d) and writes only the odd halves even under the SVE2p2 `/Z`
// qualifier and in the FP8 pair form. FCVTLT selects INPUT halves and
// follows the plain `/M` rule. The unpredicated accumulators (indexed
// FMLA, the widening/dot/matrix families), FCLAMP, FTMAD, and FADDA all
// read their destination yet rewrite every lane.

// Concrete semantic-field discrepancy between a decoded record and the
// architectural expectation. Returned by ``SVEFloatingPointSemanticChecker``.

import Iris

public struct SVEFPSemanticIssue: Sendable, Equatable {
    /// Field that didn't match (e.g. "flagEffect", "scalableEffect", "registerReads").
    public let field: String
    /// Stringified actual value from the draft.
    public let actual: String
    /// Stringified expected value.
    public let expected: String
}

/// Per-record semantic-field verification for SVE / SVE2 floating-point.
/// Returns `nil` when the record matches every expected attribute; the first
/// mismatch otherwise.
public enum SVEFloatingPointSemanticChecker {
    @_effects(readonly)
    @_optimize(speed)
    public static func verify(draft: Instruction) -> SVEFPSemanticIssue? {
        if draft.mnemonic == .undefined { return nil }
        // Universal invariants: SVE-FP computes, it never branches, never
        // touches memory, never touches NZCV, and always classifies as SVE.
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
        // Predicate reads / writes: comparing the WHOLE scalable set keeps
        // "no SVE-FP form touches FFR, ZA or ZT0" a checked property.
        let expPredW = SVEFloatingPointSemanticAttributes.expectedPredicateWrites(Array(Array(draft.operands)))
        if draft.scalableWrites != ScalableRegisterSet(bits: UInt64(expPredW)) {
            return SVEFPSemanticIssue(
                field: "predicateWrites",
                actual: "0x\(String(draft.scalableWrites.bits, radix: 16))",
                expected: "0x\(String(expPredW, radix: 16))",
            )
        }
        let expPredR = SVEFloatingPointSemanticAttributes.expectedPredicateReads(Array(Array(draft.operands)))
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
/// Pure functions over the decoded mnemonic and operand list.
public enum SVEFloatingPointSemanticAttributes {
    /// `readsStreamingMode` on every SVE-FP form (all are vector operations
    /// whose element count comes from `CurrentVL()`); `partialWrite` on the
    /// merging-predicated forms plus the statically-preserving top-half
    /// converts (see the file header).
    @_effects(readonly)
    public static func expectedScalableEffect(for draft: Instruction) -> ScalableEffect {
        var effect: ScalableEffect = .readsStreamingMode
        if hasMergingGoverning(Array(Array(draft.operands))) || preservesDestination(draft.mnemonic) {
            effect.insert(.partialWrite)
        }
        return effect
    }

    /// Whether the mnemonic leaves part of its destination's prior value
    /// intact at statically-known positions: the top-half converts, in every
    /// qualifier and in the FP8 pair form — ARM's ASL seeds `result` from
    /// the destination and assigns only the odd halves.
    @_effects(readonly)
    public static func preservesDestination(_ m: Mnemonic) -> Bool {
        switch m {
        case .fcvtnt, .fcvtxnt, .bfcvtnt:
            true
        default:
            false
        }
    }

    /// Whether the mnemonic reads its destination even though the destination
    /// does not reappear among its source operands: the unpredicated
    /// accumulators (indexed FMA, widening/dot/matrix multiply-add) and the
    /// three-source clamps. The destructive two-address forms (FTMAD, FADDA,
    /// the predicated binary family) are deliberately absent — their
    /// destination is already one of the source operands, so the general
    /// walk picks it up; the predicated `/M` forms are covered by the
    /// merging rule.
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

    // MARK: predicate reads / writes

    /// The result-role predicate operands — only the compares write a
    /// predicate in SVE-FP.
    @_effects(readonly)
    public static func expectedPredicateWrites(_ ops: [Operand]) -> UInt16 {
        var mask: UInt16 = 0
        for op in ops {
            if case let .scalablePredicate(p) = op, p.role == .result {
                mask |= UInt16(1) << UInt16(p.registerIndex & 0xF)
            }
        }
        return mask
    }

    /// The governing predicates — the only predicates SVE-FP reads as such —
    /// plus the result predicate when a governing predicate is merging (the
    /// structural invariant; inert here since SVE-FP's compares are all `/Z`).
    @_effects(readonly)
    public static func expectedPredicateReads(_ ops: [Operand]) -> UInt16 {
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

    // MARK: register (Z/V) reads / writes

    /// The destination operand, when it is a register: operand 0 for
    /// everything except the compares, whose operand 0 is a predicate and
    /// which therefore write no register at all.
    @_effects(readonly)
    public static func expectedRegisterWrites(for draft: Instruction) -> UInt64 {
        guard let first = Array(draft.operands).first else { return 0 }
        return registerMask(first)
    }

    /// Every source operand's register, plus the destination when the form
    /// reads it (merging predicate, accumulator, clamp, or preserving write).
    @_effects(readonly)
    public static func expectedRegisterReads(for draft: Instruction) -> UInt64 {
        let ops = Array(draft.operands)
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

    // MARK: helpers

    /// The canonical-index bitmask of an operand's register(s): Z_n and V_n
    /// at 32+n (they are the same physical register), a vector-pair group at
    /// both members. SVE-FP has no GPR operands.
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
    public static func hasMergingGoverning(_ ops: [Operand]) -> Bool {
        for op in ops {
            if case let .scalablePredicate(p) = op, p.qualifier == .merging {
                return true
            }
        }
        return false
    }
}
