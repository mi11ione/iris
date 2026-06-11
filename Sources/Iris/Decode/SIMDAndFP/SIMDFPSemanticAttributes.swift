// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Per-mnemonic semantic-attribute tables + verification
// helpers for SIMD & FP. Mirrors `DPRSemanticAttributes.swift` shape
// exactly — same public types (`SIMDFPSemanticIssue`,
// `SIMDFPExpectedReads`, `SIMDFPSemanticChecker`,
// `SIMDFPSemanticAttributes`), same `verify(_:)` entry point.
//
// Every SIMD/FP record has `branchClass == .none`,
// `memoryOrdering == []`, `category == .simdAndFP` — universal
// invariants (UNDEFINED records skip checks). `flagEffect` is `.nzcv`
// only for FCMP/FCMPE/FCCMP/FCCMPE; `.none` otherwise (including FCSEL).
// `memoryAccess` is `.load` for LDx/LDxR, `.store` for STx, `.none`
// otherwise. `semanticReads` / `semanticWrites` are mnemonic-specific
// per ARM ARM § C7 (per-instruction reference); some mnemonics are
// destructive/accumulating with destination-as-source.

/// Concrete semantic-field discrepancy between a decoded SIMD/FP
/// record and the ARM ARM expectation. Returned by
/// ``SIMDFPSemanticChecker/verify(_:)``.
@frozen
@_spi(Validation)
public struct SIMDFPSemanticIssue: Sendable, Equatable {
    /// Name of the field that didn't match.
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

/// Expected semantic-reads constraint for a SIMD/FP record.
/// `required` is the minimum bitset; `allowed` is the maximum. Mirrors
/// ``DPRExpectedReads`` shape.
@frozen
@_spi(Validation)
public struct SIMDFPExpectedReads: Sendable, Equatable {
    public let required: UInt64
    public let allowed: UInt64

    @inlinable
    public init(required: UInt64, allowed: UInt64) {
        self.required = required
        self.allowed = allowed
    }
}

/// Per-record semantic-field verification against the ARM ARM
/// per-instruction pages. Returns `nil` when the record matches every
/// expected attribute; returns the first mismatch otherwise.
@_spi(Validation)
public enum SIMDFPSemanticChecker {
    /// Verify the record's classification fields match expectations.
    /// UNDEFINED records skip checks (already-empty by construction).
    @_effects(readonly)
    @_optimize(speed)
    public static func verify(_ instruction: Instruction) -> SIMDFPSemanticIssue? {
        if instruction.mnemonic == .undefined { return nil }
        // Crypto (AES/SHA/SM3/SM4) sits in the op0 {7,F} partition but is
        // crypto-owned: its decoder sets category .crypto and its text
        // routes to the crypto canonicalizer. Its semantic checks belong
        // to the crypto checker; SIMD/FP still validates its text parity
        // via the sweep.
        if instruction.category == .crypto { return nil }
        if instruction.branchClass != .none {
            return SIMDFPSemanticIssue(
                field: "branchClass",
                actual: "\(instruction.branchClass)",
                expected: "none",
            )
        }
        let expectedOrdering = SIMDFPSemanticAttributes.expectedMemoryOrdering(for: instruction.mnemonic)
        if instruction.memoryOrdering != expectedOrdering {
            return SIMDFPSemanticIssue(
                field: "memoryOrdering",
                actual: "\(instruction.memoryOrdering)",
                expected: "\(expectedOrdering)",
            )
        }
        if instruction.category != .simdAndFP {
            return SIMDFPSemanticIssue(
                field: "category",
                actual: "\(instruction.category)",
                expected: "simdAndFP",
            )
        }
        let expectedFlag = SIMDFPSemanticAttributes.expectedFlagEffect(for: instruction.mnemonic)
        if instruction.flagEffect != expectedFlag {
            return SIMDFPSemanticIssue(
                field: "flagEffect",
                actual: "\(instruction.flagEffect)",
                expected: "\(expectedFlag)",
            )
        }
        let expectedAccess = SIMDFPSemanticAttributes.expectedMemoryAccess(for: instruction.mnemonic)
        if instruction.memoryAccess != expectedAccess {
            return SIMDFPSemanticIssue(
                field: "memoryAccess",
                actual: "\(instruction.memoryAccess)",
                expected: "\(expectedAccess)",
            )
        }
        // Operand-context discipline: `.msl` is valid only inside
        // `.shiftAmount`, never `.shiftedRegister`. Validate operand shape
        // BEFORE deriving read/write masks from the operands — a
        // structurally-invalid operand is not a mask divergence.
        for op in Array(instruction.operands) {
            if case let .shiftedRegister(_, kind, _) = op, kind == .msl {
                return SIMDFPSemanticIssue(
                    field: "shift-kind-context",
                    actual: ".shiftedRegister with .msl",
                    expected: ".msl is valid only in .shiftAmount",
                )
            }
        }
        // semanticReads / semanticWrites, derived independently from the
        // (text-validated) operand list by architectural rule — a separate
        // computation from each decoder's own mask logic, so any divergence
        // surfaces a decoder bug.
        if let expectedReads = SIMDFPSemanticAttributes.expectedReadMask(for: instruction),
           instruction.semanticReads.mask != expectedReads
        {
            return SIMDFPSemanticIssue(
                field: "semanticReads",
                actual: "0x" + String(instruction.semanticReads.mask, radix: 16),
                expected: "0x" + String(expectedReads, radix: 16),
            )
        }
        if let expectedWrites = SIMDFPSemanticAttributes.expectedWriteMask(for: instruction),
           instruction.semanticWrites.mask != expectedWrites
        {
            return SIMDFPSemanticIssue(
                field: "semanticWrites",
                actual: "0x" + String(instruction.semanticWrites.mask, radix: 16),
                expected: "0x" + String(expectedWrites, radix: 16),
            )
        }

        return nil
    }
}

/// Per-mnemonic semantic-attribute lookups. Pure functions; constant-
/// folded at module load.
@_spi(Validation)
public enum SIMDFPSemanticAttributes {
    /// The architecturally-correct ``FlagEffect`` for a SIMD/FP mnemonic.
    @_effects(readonly)
    public static func expectedFlagEffect(for m: Mnemonic) -> FlagEffect {
        switch m {
        // Plain FP compares write all four flags, read none.
        case .fcmp, .fcmpe:
            .nzcv
        // FP conditional compares read the condition (NZCV) and write NZCV.
        case .fccmp, .fccmpe:
            [.nzcv, .readsNZCV]
        // FP conditional select reads the condition (NZCV), writes no flag.
        case .fcsel:
            .readsNZCV
        default:
            .none
        }
    }

    /// The architecturally-correct ``MemoryAccess`` for a SIMD/FP
    /// mnemonic.
    @_effects(readonly)
    public static func expectedMemoryAccess(for m: Mnemonic) -> MemoryAccess {
        switch m {
        case .ld1, .ld2, .ld3, .ld4, .ld1r, .ld2r, .ld3r, .ld4r,
             .ldr, .ldur, .ldp, .ldnp, .ldtp, .ldtnp, .ldapur, .ldap1:
            .load
        case .st1, .st2, .st3, .st4,
             .str, .stur, .stp, .stnp, .sttp, .sttnp, .stlur, .stl1:
            .store
        default:
            .none
        }
    }

    /// The architecturally-correct ``MemoryOrdering`` for a SIMD/FP
    /// mnemonic. Only the LRCPC2 SIMD forms (STLUR/LDAPUR) carry ordering.
    @_effects(readonly)
    public static func expectedMemoryOrdering(for m: Mnemonic) -> MemoryOrdering {
        switch m {
        case .ldapur, .ldap1: [.acquire]
        case .stlur, .stl1: [.release]
        default: []
        }
    }

    /// Whether the destination operand of a SIMD/FP mnemonic is also a
    /// source (destructive / accumulating semantics).
    /// NOTE: FMADD/FMSUB/FNMADD/FNMSUB are 4-operand instructions where
    /// Va (operand[3]) is the accumulator — Rd (operand[0]) is a pure
    /// write. They are NOT destination-reads-itself; their accumulator
    /// is the explicit Ra operand.
    @_effects(readonly)
    public static func destinationReadsItself(for m: Mnemonic) -> Bool {
        switch m {
        case .mla, .mls, .fmla, .fmls, .fmlal, .fmlal2, .fmlsl, .fmlsl2,
             .fcmla, .fdot, .fmlalb, .fmlalt, .fmlallbb, .fmlallbt, .fmlalltb, .fmlalltt,
             .sqdmlal, .sqdmlsl, .sqdmlal2, .sqdmlsl2,
             .sqrdmlah, .sqrdmlsh,
             .smlal, .smlal2, .smlsl, .smlsl2,
             .umlal, .umlal2, .umlsl, .umlsl2,
             .sdot, .udot, .usdot, .sudot, .bfdot,
             .bfmlalb, .bfmlalt, .bfmmla,
             .smmla, .ummla, .usmmla,
             .sadalp, .uadalp,
             .saba, .uaba, .sabal, .sabal2, .uabal, .uabal2,
             .bsl, .bit, .bif,
             .ins, .sli, .sri, .tbx:
            true
        default:
            false
        }
    }

    /// Whether the destination (operand[0]) is also read as a source —
    /// the mnemonic-fixed accumulate set plus the two shapes whose
    /// destructiveness depends on operand form: ORR/BIC vector-immediate
    /// (read-modify-write; the register forms are not), and MOV-as-INS
    /// (an element-view destination preserves the unwritten lanes).
    @_effects(readonly)
    private static func destinationIsAlsoSource(_ instruction: Instruction) -> Bool {
        let m = instruction.mnemonic
        if destinationReadsItself(for: m) { return true }
        let ops = Array(instruction.operands)
        if m == .orr || m == .bic, ops.count >= 2 {
            switch ops[1] {
            case .immediate, .unsignedImmediate: return true
            default: return false
            }
        }
        // A lane-write destination (element view) preserves the unwritten
        // lanes, so the register is read as well as written: INS, MOV-as-INS,
        // FMOV Vd.D[1], Xn.
        if case let .vectorRegister(v)? = ops.first, case .element = v.view {
            return true
        }
        return false
    }

    /// Expected `semanticWrites` mask, derived from the operand list.
    /// `nil` for shapes too complex to summarize (the checker then skips).
    @_effects(readonly)
    @_optimize(speed)
    public static func expectedWriteMask(for instruction: Instruction) -> UInt64? {
        let m = instruction.mnemonic
        let ops = Array(instruction.operands)
        switch expectedMemoryAccess(for: m) {
        case .load:
            // Loaded register(s) are operand[0 ..< memory]; writeback also
            // writes the base GPR.
            guard let found = lastMemoryOperand(ops) else { return nil }
            var mask = registerMaskOver(ops, 0 ..< found.index)
            mask |= writebackBaseMask(found.memory)
            return mask
        case .store:
            // A store writes no register except a writeback base.
            guard let found = lastMemoryOperand(ops) else { return nil }
            return writebackBaseMask(found.memory)
        default:
            // Data-processing. The FP scalar compares (flagEffect == .nzcv)
            // write no register — their result is NZCV. Everything else
            // writes its destination, operand[0].
            if expectedFlagEffect(for: m).writtenFlags == .nzcv { return 0 }
            guard let first = ops.first else { return 0 }
            return registerBit(of: first)
        }
    }

    /// Expected `semanticReads` mask, derived from the operand list.
    /// `nil` for shapes too complex to summarize (the checker then skips).
    @_effects(readonly)
    @_optimize(speed)
    public static func expectedReadMask(for instruction: Instruction) -> UInt64? {
        let m = instruction.mnemonic
        let ops = Array(instruction.operands)
        switch expectedMemoryAccess(for: m) {
        case .load:
            // A load reads its base + index. A single-structure element load
            // (LD1..LD4 / LDAP1 {Vt.<T>}[i]) writes one lane and preserves
            // the rest, so each element-view destination is also read.
            guard let found = lastMemoryOperand(ops) else { return nil }
            var mask = memoryBaseAndIndexMask(found.memory)
            for i in 0 ..< found.index {
                if case let .vectorRegister(v) = ops[i], case .element = v.view {
                    mask |= UInt64(1) << UInt64(32 &+ v.registerIndex)
                }
            }
            return mask
        case .store:
            // A store reads the stored data register(s) + base/index.
            guard let found = lastMemoryOperand(ops) else { return nil }
            var mask = memoryBaseAndIndexMask(found.memory)
            mask |= registerMaskOver(ops, 0 ..< found.index)
            return mask
        default:
            // Data-processing: the source operands are operand[1...]; the
            // destination (operand[0]) is also a source for destructive /
            // accumulating ops and for the compares (which read operand[0]).
            var mask = ops.count > 1 ? registerMaskOver(ops, 1 ..< ops.count) : 0
            if destinationIsAlsoSource(instruction) || expectedFlagEffect(for: m).writtenFlags == .nzcv,
               let first = ops.first
            {
                mask |= registerBit(of: first)
            }
            return mask
        }
    }

    /// Register-set bit a single operand contributes (GPR canonical index,
    /// or 32 + index for a SIMD/FP register). ZR/WZR contribute nothing;
    /// non-register operands (immediates, conditions, …) contribute nothing.
    @inline(__always)
    @_effects(readonly)
    private static func registerBit(of op: Operand) -> UInt64 {
        switch op {
        case let .register(r):
            r.isZeroRegister ? 0 : (UInt64(1) << UInt64(r.canonicalIndex))
        case let .vectorRegister(v):
            UInt64(1) << UInt64(32 &+ v.registerIndex)
        case let .shiftedRegister(r, _, _):
            r.isZeroRegister ? 0 : (UInt64(1) << UInt64(r.canonicalIndex))
        case let .extendedRegister(r, _, _):
            r.isZeroRegister ? 0 : (UInt64(1) << UInt64(r.canonicalIndex))
        default:
            0
        }
    }

    @inline(__always)
    @_effects(readonly)
    private static func registerMaskOver(_ ops: [Operand], _ range: Range<Int>) -> UInt64 {
        var mask: UInt64 = 0
        for i in range {
            mask |= registerBit(of: ops[i])
        }
        return mask
    }

    @inline(__always)
    @_effects(readonly)
    private static func lastMemoryOperand(_ ops: [Operand]) -> (index: Int, memory: MemoryOperand)? {
        for i in stride(from: ops.count - 1, through: 0, by: -1) {
            if case let .memory(mm) = ops[i] { return (i, mm) }
        }
        return nil
    }

    @inline(__always)
    @_effects(readonly)
    private static func memoryBaseAndIndexMask(_ mem: MemoryOperand) -> UInt64 {
        var mask: UInt64 = 0
        if case let .register(base) = mem.base, !base.isZeroRegister {
            mask |= UInt64(1) << UInt64(base.canonicalIndex)
        }
        if let idx = mem.index, !idx.isZeroRegister {
            mask |= UInt64(1) << UInt64(idx.canonicalIndex)
        }
        return mask
    }

    @inline(__always)
    @_effects(readonly)
    private static func writebackBaseMask(_ mem: MemoryOperand) -> UInt64 {
        guard mem.writeback != .none, case let .register(base) = mem.base, !base.isZeroRegister
        else { return 0 }
        return UInt64(1) << UInt64(base.canonicalIndex)
    }
}
