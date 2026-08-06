// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

@frozen
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
@frozen
public struct SIMDFPExpectedReads: Sendable, Equatable {
    public let required: UInt64
    public let allowed: UInt64

    @inlinable
    public init(required: UInt64, allowed: UInt64) {
        self.required = required
        self.allowed = allowed
    }
}

/// Per-record semantic-field verification against the ARM ARM per-instruction
/// pages.
public enum SIMDFPSemanticChecker {
    /// Verify the record's classification fields match expectations.
    @_effects(readonly)
    @_optimize(speed)
    public static func verify(_ instruction: Instruction) -> SIMDFPSemanticIssue? {
        if instruction.mnemonic == .undefined { return nil }
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
        for op in instruction.operands {
            if case let .shiftedRegister(_, kind, _) = op, kind == .msl {
                return SIMDFPSemanticIssue(
                    field: "shift-kind-context",
                    actual: ".shiftedRegister with .msl",
                    expected: ".msl is valid only in .shiftAmount",
                )
            }
        }
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

/// Per-mnemonic semantic-attribute lookups.
public enum SIMDFPSemanticAttributes {
    /// The architecturally-correct `FlagEffect` for a SIMD/FP mnemonic.
    @_effects(readonly)
    public static func expectedFlagEffect(for m: Mnemonic) -> FlagEffect {
        switch m {
        case .fcmp, .fcmpe:
            .nzcv
        case .fccmp, .fccmpe:
            [.nzcv, .readsNZCV]
        case .fcsel:
            .readsNZCV
        default:
            .none
        }
    }

    /// The architecturally-correct `MemoryAccess` for a SIMD/FP mnemonic.
    @_effects(readonly)
    public static func expectedMemoryAccess(for m: Mnemonic) -> MemoryAccess {
        switch m {
        case .ld1, .ld2, .ld3, .ld4, .ld1r, .ld2r, .ld3r, .ld4r,
             .ldr, .ldur, .ldp, .ldnp, .ldtp, .ldtnp, .ldapur, .ldap1:
            .load
        case .st1, .st2, .st3, .st4,
             .str, .stur, .stp, .stnp, .sttp, .sttnp, .stlur, .stl1:
            .store
        case .ldbfadd, .ldbfadda, .ldbfaddl, .ldbfaddal,
             .ldbfmax, .ldbfmaxa, .ldbfmaxl, .ldbfmaxal,
             .ldbfmin, .ldbfmina, .ldbfminl, .ldbfminal,
             .ldbfmaxnm, .ldbfmaxnma, .ldbfmaxnml, .ldbfmaxnmal,
             .ldbfminnm, .ldbfminnma, .ldbfminnml, .ldbfminnmal,
             .ldfadd, .ldfadda, .ldfaddl, .ldfaddal,
             .ldfmax, .ldfmaxa, .ldfmaxl, .ldfmaxal,
             .ldfmin, .ldfmina, .ldfminl, .ldfminal,
             .ldfmaxnm, .ldfmaxnma, .ldfmaxnml, .ldfmaxnmal,
             .ldfminnm, .ldfminnma, .ldfminnml, .ldfminnmal,
             .stbfadd, .stbfaddl, .stbfmax, .stbfmaxl, .stbfmin, .stbfminl,
             .stbfmaxnm, .stbfmaxnml, .stbfminnm, .stbfminnml,
             .stfadd, .stfaddl, .stfmax, .stfmaxl, .stfmin, .stfminl,
             .stfmaxnm, .stfmaxnml, .stfminnm, .stfminnml:
            .atomic
        default:
            .none
        }
    }

    /// The architecturally-correct `MemoryOrdering` for a SIMD/FP mnemonic.
    @_effects(readonly)
    public static func expectedMemoryOrdering(for m: Mnemonic) -> MemoryOrdering {
        switch m {
        case .ldapur, .ldap1: [.acquire]
        case .stlur, .stl1: [.release]
        case .ldbfadda, .ldbfmaxa, .ldbfmina, .ldbfmaxnma, .ldbfminnma,
             .ldfadda, .ldfmaxa, .ldfmina, .ldfmaxnma, .ldfminnma:
            [.acquire]
        case .ldbfaddl, .ldbfmaxl, .ldbfminl, .ldbfmaxnml, .ldbfminnml,
             .ldfaddl, .ldfmaxl, .ldfminl, .ldfmaxnml, .ldfminnml,
             .stbfaddl, .stbfmaxl, .stbfminl, .stbfmaxnml, .stbfminnml,
             .stfaddl, .stfmaxl, .stfminl, .stfmaxnml, .stfminnml:
            [.release]
        case .ldbfaddal, .ldbfmaxal, .ldbfminal, .ldbfmaxnmal, .ldbfminnmal,
             .ldfaddal, .ldfmaxal, .ldfminal, .ldfmaxnmal, .ldfminnmal:
            [.acquire, .release]
        default: []
        }
    }

    /// Whether a SIMD/FP mnemonic's destination is also a source (destructive
    /// or accumulating).
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
             .bfmlalb, .bfmlalt, .bfmmla, .fmmla,
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

    /// Whether the destination is also read as a source.
    @_effects(readonly)
    private static func destinationIsAlsoSource(_ instruction: Instruction) -> Bool {
        let m = instruction.mnemonic
        if destinationReadsItself(for: m) { return true }
        let ops = instruction.operands
        if m == .orr || m == .bic, ops.count >= 2 {
            switch ops[1] {
            case .immediate, .unsignedImmediate: return true
            default: return false
            }
        }
        if case let .vectorRegister(v)? = ops.first, case .element = v.view {
            return true
        }
        return false
    }

    /// Expected `semanticWrites` mask, derived from the operand list.
    @_effects(readonly)
    @_optimize(speed)
    public static func expectedWriteMask(for instruction: Instruction) -> UInt64? {
        let m = instruction.mnemonic
        let ops = instruction.operands
        switch expectedMemoryAccess(for: m) {
        case .load:
            guard let found = lastMemoryOperand(ops) else { return nil }
            var mask = registerMaskOver(ops, 0 ..< found.index)
            mask |= writebackBaseMask(found.memory)
            return mask
        case .store:
            guard let found = lastMemoryOperand(ops) else { return nil }
            return writebackBaseMask(found.memory)
        case .atomic:
            guard let found = lastMemoryOperand(ops) else { return nil }
            if found.index < 2 { return 0 }
            return registerBit(of: ops[1])
        default:
            if expectedFlagEffect(for: m).writtenFlags == .nzcv { return 0 }
            guard let first = ops.first else { return 0 }
            return registerBit(of: first)
        }
    }

    /// Expected `semanticReads` mask, derived from the operand list.
    @_effects(readonly)
    @_optimize(speed)
    public static func expectedReadMask(for instruction: Instruction) -> UInt64? {
        let m = instruction.mnemonic
        let ops = instruction.operands
        switch expectedMemoryAccess(for: m) {
        case .load:
            guard let found = lastMemoryOperand(ops) else { return nil }
            var mask = memoryBaseAndIndexMask(found.memory)
            for i in 0 ..< found.index {
                if case let .vectorRegister(v) = ops[i], case .element = v.view {
                    mask |= UInt64(1) << UInt64(32 &+ v.registerIndex)
                }
            }
            return mask
        case .store:
            guard let found = lastMemoryOperand(ops) else { return nil }
            var mask = memoryBaseAndIndexMask(found.memory)
            mask |= registerMaskOver(ops, 0 ..< found.index)
            return mask
        case .atomic:
            guard let found = lastMemoryOperand(ops) else { return nil }
            var mask = memoryBaseAndIndexMask(found.memory)
            mask |= registerMaskOver(ops, 0 ..< min(1, found.index))
            return mask
        default:
            var mask = ops.count > 1 ? registerMaskOver(ops, 1 ..< ops.count) : 0
            if destinationIsAlsoSource(instruction) || expectedFlagEffect(for: m).writtenFlags == .nzcv,
               let first = ops.first
            {
                mask |= registerBit(of: first)
            }
            return mask
        }
    }

    /// Register-set bit a single operand contributes (GPR canonical index, or
    /// 32 + index for a SIMD/FP register).
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
    private static func registerMaskOver(_ ops: Instruction.Operands, _ range: Range<Int>) -> UInt64 {
        var mask: UInt64 = 0
        for i in range {
            mask |= registerBit(of: ops[i])
        }
        return mask
    }

    @inline(__always)
    @_effects(readonly)
    private static func lastMemoryOperand(_ ops: Instruction.Operands) -> (index: Int, memory: MemoryOperand)? {
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
