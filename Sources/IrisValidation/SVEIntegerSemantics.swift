// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Per-record semantic-attribute verification for SVE-integer — SVE / SVE2
// integer. The text-parity validator proves mnemonic + operands against
// llvm-mc, but disassembly text does NOT encode `flagEffect`, `scalableEffect`
// (partialWrite / readsStreamingMode), or the semantic read/write sets — so
// this checker proves those independently. Expectations are derived here from
// the (text-validated) operand list plus the mnemonic, by architectural rule,
// as a computation entirely separate from the ~30 decode sites that populate
// those fields — so a disagreement between the two surfaces a decoder bug.
//
// The two rules that carry the weight, both settled against ARM's A64 ISA XML
// pseudocode rather than inferred from the encoding:
//
// * A destination is READ whenever the operation consumes its prior value —
// either because a merging (`/M`) governing predicate preserves inactive
// lanes, or because the form is an accumulator / three-source clamp /
// insert whose destination does not reappear in the operand list.
// The destructive two-address forms (`add z0.s, p0/m, z0.s, z1.s`) need no
// special case: their destination already appears among the sources.
//
// * `partialWrite` is set only when part of the destination's prior value
// SURVIVES into the result. That is a strictly narrower property than
// "the destination is read": SCLAMP, SSRA, SMMLA and ADCLB all read their
// destination and still rewrite every bit of it. Across all of SVE exactly
// 22 instructions preserve destination bits at statically-known positions
// (ARM's ASL seeds `result` from the destination and then writes only one
// lane parity, or bit-merges through a mask); 19 of them are SVE-integer's — the
// narrowing "top" forms, EORBT/EORTB, and SLI/SRI. The `/M` forms preserve
// lanes too, at positions known only at execution time, and are also set:
// `partialWrite` over-approximates the kill, so Piece 4 never treats a
// preserving write as a strong update.

// Concrete semantic-field discrepancy between a decoded record and the
// architectural expectation. Returned by ``SVEIntegerSemanticChecker``.

import Iris

public struct SVEIntSemanticIssue: Sendable, Equatable {
    /// Field that didn't match (e.g. "flagEffect", "scalableEffect", "registerReads").
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

/// Per-record semantic-field verification for SVE / SVE2 integer. Returns `nil`
/// when the record matches every expected attribute; the first mismatch otherwise.
public enum SVEIntegerSemanticChecker {
    @_effects(readonly)
    @_optimize(speed)
    public static func verify(draft: Instruction) -> SVEIntSemanticIssue? {
        if draft.mnemonic == .undefined { return nil }
        // Universal invariants for the tier: SVE-integer computes, it never branches,
        // never touches memory, and always classifies as SVE.
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
        // Predicate reads / writes. Comparing the WHOLE scalable set — not just
        // its predicate bits — is what makes "no SVE-integer form touches FFR, ZA or
        // ZT0" a checked property rather than a claim: any other bit set
        // in either set makes the comparison fail.
        let expPredW = SVEIntegerSemanticAttributes.expectedPredicateWrites(Array(Array(draft.operands)))
        if draft.scalableWrites != ScalableRegisterSet(bits: UInt64(expPredW)) {
            return SVEIntSemanticIssue(
                field: "predicateWrites",
                actual: "0x\(String(draft.scalableWrites.bits, radix: 16))",
                expected: "0x\(String(expPredW, radix: 16))",
            )
        }
        let expPredR = SVEIntegerSemanticAttributes.expectedPredicateReads(Array(Array(draft.operands)))
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

/// Per-mnemonic / per-operand SVE-integer semantic-attribute lookups. Pure
/// functions over the decoded mnemonic and operand list.
public enum SVEIntegerSemanticAttributes {
    /// `.nzcv` for exactly the integer compares and MATCH/NMATCH — the forms
    /// whose ASL ends in `PSTATE.[N,Z,C,V] = PredTest(...)`. Everything else in
    /// SVE-integer is `.none`, including the deceptive cases: saturation is silent (no
    /// NZCV, no modelled QC), and ADCLB/ADCLT/SBCLB/SBCLT take their carry from
    /// an odd lane of `Zm`, never from `PSTATE.C`.
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
        if hasMergingGoverning(Array(Array(draft.operands))) || preservesDestination(draft.mnemonic) {
            effect.insert(.partialWrite)
        }
        return effect
    }

    /// Whether the mnemonic leaves part of its destination's prior value intact
    /// at statically-known positions: the narrowing "top" forms (which write the
    /// odd elements and leave the even ones), the interleaved EORBT/EORTB (one
    /// lane parity each), and the SLI/SRI bit-merges. Contrast the "bottom"
    /// forms, which zero the other half, and the accumulators, which rewrite
    /// every bit.
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
    /// does not reappear among its source operands: the accumulators (`Zda`),
    /// the three-source clamps, and the preserving forms above. The destructive
    /// two-address forms are deliberately absent — their destination is already
    /// one of the source operands, so the general walk picks it up.
    @_effects(readonly)
    public static func readsDestination(_ m: Mnemonic) -> Bool {
        if preservesDestination(m) { return true }
        switch m {
        // Dot products and matrix multiply-accumulate.
        case .sdot, .udot, .usdot, .sudot, .cdot, .smmla, .ummla, .usmmla:
            return true
        // Multiply-add (predicated, indexed, and the long/saturating forms).
        case .mla, .mls, .sqrdmlah, .sqrdmlsh, .cmla, .sqrdcmlah,
             .smlalb, .smlalt, .umlalb, .umlalt, .smlslb, .smlslt, .umlslb, .umlslt,
             .sqdmlalb, .sqdmlalt, .sqdmlslb, .sqdmlslt, .sqdmlalbt, .sqdmlslbt,
             .mlapt, .madpt:
            return true
        // Shift-and-accumulate, absolute-difference-accumulate, carry-propagating
        // accumulate, and the widening pairwise accumulate.
        case .ssra, .usra, .srsra, .ursra,
             .saba, .uaba, .sabal, .uabal, .sabalb, .sabalt, .uabalb, .uabalt,
             .adclb, .adclt, .sbclb, .sbclt, .sadalp, .uadalp:
            return true
        // Three-source clamp: the value being clamped lives in the destination.
        case .sclamp, .uclamp:
            return true
        default:
            return false
        }
    }

    // MARK: predicate reads / writes

    /// The result-role predicate operands — only the compares and MATCH/NMATCH
    /// write a predicate.
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

    /// The governing predicates — the only predicates SVE-integer reads as such (no
    /// form reads a predicate as data; that is SVE-predicate's predicate-logical) — plus
    /// the result predicate when a governing predicate is merging, since a `/M`
    /// destination is an RMW source. That last clause is SVE-predicate's structural walk
    /// and is inert here (SVE-integer's only predicate-writing forms — the compares and
    /// MATCH/NMATCH — are all `/Z`), but it is the invariant, not an accident of
    /// the current instruction set, so it is checked rather than assumed.
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

    // MARK: register (GPR + Z/V) reads / writes

    /// The destination operand, when it is a register: operand 0 for everything
    /// except the compares and MATCH/NMATCH, whose operand 0 is a predicate and
    /// which therefore write no register at all.
    @_effects(readonly)
    public static func expectedRegisterWrites(for draft: Instruction) -> UInt64 {
        guard let first = Array(draft.operands).first else { return 0 }
        return registerMask(first)
    }

    /// Every source operand's register, plus the destination when the form reads
    /// it (merging predicate, accumulator, clamp, or preserving write).
    @_effects(readonly)
    public static func expectedRegisterReads(for draft: Instruction) -> UInt64 {
        let ops = Array(draft.operands)
        // A decoder bug that emitted a named mnemonic with no operands must be
        // reported as the mismatch it is, not trap the sweep on an empty range.
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

    /// The canonical-index bitmask of an operand's register(s): GPR at its own
    /// index (SP = 31, XZR/WZR dropped), Z_n and V_n at 32+n (they are the same
    /// physical register), a vector group at every member, and ADR's vector
    /// memory operand at both its base and its index.
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
    public static func hasMergingGoverning(_ ops: [Operand]) -> Bool {
        for op in ops {
            if case let .scalablePredicate(p) = op, p.qualifier == .merging {
                return true
            }
        }
        return false
    }
}
