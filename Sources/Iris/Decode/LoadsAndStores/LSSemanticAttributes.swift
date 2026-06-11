// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Per-mnemonic semantic attribute tables and verification
// for the Loads & Stores family, mirroring DPRSemanticAttributes. Every
// L/S record carries category == .loadsAndStores, branchClass == .none,
// flagEffect == .none; the per-mnemonic tables further pin memoryAccess,
// memoryOrdering, operand shape, and the semanticReads/writes masks.

/// Concrete semantic-field discrepancy between a decoded record and the
/// per-mnemonic expectation. Returned by ``LSSemanticChecker/verify(_:)``.
@frozen
@_spi(Validation)
public struct LSSemanticIssue: Sendable, Equatable {
    /// Name of the field that didn't match (e.g. "memoryAccess",
    /// "memoryOrdering", "operandShape", "branchClass").
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

/// Typed operand-kind summary for the operand-shape table.
@frozen
@_spi(Validation)
public enum LSOperandKind: Sendable, Equatable {
    /// `.register(_)` operand.
    case register
    /// `.memory(_)` operand.
    case memory
    /// `.prefetchOperation(_)` operand.
    case prefetchOperation
    /// `.immediate(_)` or `.unsignedImmediate(_)` operand.
    case immediate
}

/// Per-record semantic-field verification against the spec table.
/// Returns `nil` when the record matches every expected attribute;
/// returns the first mismatch otherwise.
@_spi(Validation)
public enum LSSemanticChecker {
    @_effects(readonly)
    @_optimize(speed)
    public static func verify(_ instruction: Instruction) -> LSSemanticIssue? {
        if instruction.mnemonic == .undefined { return nil }
        // MTE L/S records flow through the L/S family decoder via the
        // case 0b011001 bit-21 dispatch; their semantic attributes are
        // verified by the crypto/Apple-extensions checker, not this one.
        if CryptoAppleExtensionsCanonicalizer.owns(instruction.mnemonic) { return nil }
        if instruction.branchClass != .none {
            return LSSemanticIssue(
                field: "branchClass",
                actual: "\(instruction.branchClass)",
                expected: "none",
            )
        }
        if instruction.flagEffect != .none {
            return LSSemanticIssue(
                field: "flagEffect",
                actual: "\(instruction.flagEffect)",
                expected: "none",
            )
        }
        if instruction.category != .loadsAndStores {
            return LSSemanticIssue(
                field: "category",
                actual: "\(instruction.category)",
                expected: "loadsAndStores",
            )
        }
        if let expectedAccess = LSSemanticAttributes.expectedMemoryAccess(for: instruction.mnemonic) {
            if instruction.memoryAccess != expectedAccess {
                return LSSemanticIssue(
                    field: "memoryAccess",
                    actual: "\(instruction.memoryAccess)",
                    expected: "\(expectedAccess)",
                )
            }
        }
        if let expectedOrdering = LSSemanticAttributes.expectedMemoryOrdering(for: instruction.mnemonic) {
            if instruction.memoryOrdering != expectedOrdering {
                return LSSemanticIssue(
                    field: "memoryOrdering",
                    actual: "\(instruction.memoryOrdering.rawValue)",
                    expected: "\(expectedOrdering.rawValue)",
                )
            }
        }
        if let expectedShape = LSSemanticAttributes.expectedOperandShape(for: instruction.mnemonic) {
            if !operandsMatchShape(Array(instruction.operands), expected: expectedShape) {
                return LSSemanticIssue(
                    field: "operandShape",
                    actual: formatOperandShape(Array(instruction.operands)),
                    expected: "\(expectedShape)",
                )
            }
        }
        if let expectedReads = LSSemanticAttributes.expectedReadMask(for: instruction) {
            if instruction.semanticReads.mask != expectedReads {
                return LSSemanticIssue(
                    field: "semanticReads",
                    actual: String(instruction.semanticReads.mask, radix: 16),
                    expected: "0x\(String(expectedReads, radix: 16))",
                )
            }
        }
        if let expectedWrites = LSSemanticAttributes.expectedWriteMask(for: instruction) {
            if instruction.semanticWrites.mask != expectedWrites {
                return LSSemanticIssue(
                    field: "semanticWrites",
                    actual: String(instruction.semanticWrites.mask, radix: 16),
                    expected: "0x\(String(expectedWrites, radix: 16))",
                )
            }
        }
        return nil
    }

    @inline(__always)
    @_effects(readonly)
    private static func operandKind(of op: Operand) -> LSOperandKind? {
        switch op {
        case .register: .register
        case .memory: .memory
        case .prefetchOperation: .prefetchOperation
        case .immediate, .unsignedImmediate: .immediate
        default: nil
        }
    }

    @inline(__always)
    @_effects(readonly)
    private static func operandsMatchShape(
        _ ops: [Operand], expected: [LSOperandKind],
    ) -> Bool {
        guard ops.count == expected.count else { return false }
        for i in 0 ..< ops.count {
            guard let actual = operandKind(of: ops[i]) else { return false }
            if actual != expected[i] { return false }
        }
        return true
    }

    /// Cold path: only invoked when a shape mismatch is being reported.
    @_effects(readonly)
    private static func formatOperandShape(_ ops: [Operand]) -> String {
        var shape: [LSOperandKind] = []
        shape.reserveCapacity(ops.count)
        for op in ops {
            shape.append(operandKind(of: op) ?? .immediate)
        }
        return "\(shape)"
    }
}

/// Per-mnemonic semantic-attribute lookups.
@_spi(Validation)
public enum LSSemanticAttributes {
    // Precomputed operand-shape arrays — referenced from expectedOperandShape
    // so each call returns the cached value rather than constructing a new
    // array on the verification hot path.
    private static let shapeRegMem: [LSOperandKind] = [.register, .memory]
    private static let shapeRegRegMem: [LSOperandKind] = [.register, .register, .memory]
    private static let shapeRegRegRegMem: [LSOperandKind] = [
        .register, .register, .register, .memory,
    ]
    private static let shapeRegRegRegRegMem: [LSOperandKind] = [
        .register, .register, .register, .register, .memory,
    ]
    private static let shapePrfMem: [LSOperandKind] = [.prefetchOperation, .memory]
    // FEAT_MOPS: three working registers, no memory operand in the list.
    private static let shapeRegRegReg: [LSOperandKind] = [.register, .register, .register]
    /// FEAT_RPRES RPRFM: range-prefetch op (immediate) + range register + base.
    private static let shapeImmRegMem: [LSOperandKind] = [.immediate, .register, .memory]

    /// Architecturally-correct ``FlagEffect`` for an L/S mnemonic. Every
    /// L/S instruction is `.none` (no NZCV write); this method exists for
    /// API consistency with ``DPRSemanticAttributes/expectedFlagEffect(for:)``.
    @_effects(readonly)
    public static func expectedFlagEffect(for _: Mnemonic) -> FlagEffect {
        .none
    }

    @_effects(readonly)
    @_optimize(speed)
    public static func expectedMemoryAccess(for m: Mnemonic) -> MemoryAccess? {
        switch m {
        case .ldr, .ldrb, .ldrh, .ldrsb, .ldrsh, .ldrsw,
             .ldur, .ldurb, .ldurh, .ldursb, .ldursh, .ldursw,
             .ldp, .ldpsw, .ldnp, .ldtp, .ldtnp,
             .ldar, .ldarb, .ldarh,
             .ldapr, .ldaprb, .ldaprh,
             .ldlar, .ldlarb, .ldlarh,
             .ldapur, .ldapurb, .ldapurh, .ldapursb, .ldapursh, .ldapursw,
             .ldraa, .ldrab,
             .ldtr, .ldtrb, .ldtrh, .ldtrsb, .ldtrsh, .ldtrsw:
            return .load
        case .str, .strb, .strh,
             .stur, .sturb, .sturh,
             .stp, .stgp, .stnp, .sttp, .sttnp,
             .stlr, .stlrb, .stlrh,
             .stllr, .stllrb, .stllrh,
             .stlur, .stlurb, .stlurh,
             .sttr, .sttrb, .sttrh:
            return .store
        case .ldxr, .ldxrb, .ldxrh, .ldxp,
             .ldaxr, .ldaxrb, .ldaxrh, .ldaxp:
            return .exclusiveLoad
        case .stxr, .stxrb, .stxrh, .stxp,
             .stlxr, .stlxrb, .stlxrh, .stlxp:
            return .exclusiveStore
        case .prfm, .prfum:
            return .prefetch
        case .sttxr, .stltxr:
            return .exclusiveStore
        case .ldtxr, .ldatxr:
            return .exclusiveLoad
        case .cast, .casat, .caslt, .casalt,
             .caspt, .caspat, .casplt, .caspalt:
            return .atomic
        case .ld64b:
            return .load
        case .st64b, .st64bv, .st64bv0:
            return .store
        case .rprfm:
            return .prefetch
        case .ldiapp:
            return .load
        case .stilp, .gcsstr, .gcssttr:
            return .store
        default:
            // LSE RMW 2113..2220 + ST-aliases 2221..2268 + CAS 2269..2284
            // all return .atomic; the raw-value range covers the entire
            // LSE+CAS block allocated in Mnemonic+LoadsAndStores.swift.
            // LSE128 (2318..2329) + MOPS (2330..2449) + LSUI/RCW atomics
            // (2450..2529) are atomic too.
            let r = m.rawValue
            if (2113 ... 2284).contains(r) || (2318 ... 2449).contains(r)
                || (2450 ... 2529).contains(r) || (2534 ... 2539).contains(r)
            {
                return .atomic
            }
            return nil
        }
    }

    @_effects(readonly)
    @_optimize(speed)
    public static func expectedMemoryOrdering(for m: Mnemonic) -> MemoryOrdering? {
        // Gate on memory-access membership so out-of-family mnemonics fall
        // through to `nil` rather than the implicit `[]` default — the
        // checker can then skip the ordering check for non-L/S drafts.
        guard expectedMemoryAccess(for: m) != nil else { return nil }
        switch m {
        case .ldar, .ldarb, .ldarh,
             .ldaxr, .ldaxrb, .ldaxrh, .ldaxp,
             .ldapr, .ldaprb, .ldaprh,
             .ldlar, .ldlarb, .ldlarh,
             .ldapur, .ldapurb, .ldapurh, .ldapursb, .ldapursh, .ldapursw:
            return [.acquire]
        case .stlr, .stlrb, .stlrh,
             .stlxr, .stlxrb, .stlxrh, .stlxp,
             .stllr, .stllrb, .stllrh,
             .stlur, .stlurb, .stlurh:
            return [.release]
        case .ldatxr, .casat, .caspat:
            return [.acquire]
        case .stltxr, .caslt, .casplt:
            return [.release]
        case .casalt, .caspalt:
            return [.acquire, .release]
        case .sttxr, .ldtxr, .cast, .caspt:
            return []
        default:
            // LSE atomics: the (A,R) suffix is encoded in the within-block
            // mnemonic position. LSE RMW base forms (2113..2220) are 9 ops ×
            // 3 size-groups × 4 orderings = 12 entries per op; the ordering
            // index is ((offset % 12) % 4) → plain / A / L / AL. ST-alias
            // forms (2221..2268) collapse only the A=0 orderings into a
            // 6-entry-per-op block, so even within-block index is plain and
            // odd is release. CAS forms (2269..2284) use 4-ordering blocks.
            let r = m.rawValue
            if (2113 ... 2220).contains(r) {
                // ordIndex ∈ {0,1,2,3} all enumerated; 3 (AL) is `default`.
                switch ((r - 2113) % 12) % 4 {
                case 0: return []
                case 1: return [.acquire]
                case 2: return [.release]
                default: return [.acquire, .release]
                }
            }
            if (2221 ... 2268).contains(r) {
                return (r - 2221) % 2 == 0 ? [] : [.release]
            }
            if (2269 ... 2284).contains(r) {
                // ordIndex ∈ {0,1,2,3} all enumerated; 3 (AL) is `default`.
                switch (r - 2269) % 4 {
                case 0: return []
                case 1: return [.acquire]
                case 2: return [.release]
                default: return [.acquire, .release]
                }
            }
            if (2318 ... 2329).contains(r) {
                // LSE128: 3 ops × 4 orderings [plain, A, L, AL].
                switch (r - 2318) % 4 {
                case 0: return []
                case 1: return [.acquire]
                case 2: return [.release]
                default: return [.acquire, .release]
                }
            }
            if (2450 ... 2529).contains(r) {
                // LSUI / RCW atomics: 4-ordering blocks [plain, L, A, AL].
                switch (r - 2450) % 4 {
                case 0: return []
                case 1: return [.release]
                case 2: return [.acquire]
                default: return [.acquire, .release]
                }
            }
            if r == 2530 { return [.release] } // stilp
            if r == 2531 { return [.acquire] } // ldiapp
            if r == 2532 || r == 2533 { return [] } // gcsstr / gcssttr
            if (2534 ... 2539).contains(r) {
                // LSUI ST-aliases: [plain, L] pairs.
                return (r - 2534) % 2 == 0 ? [] : [.release]
            }
            // LS64 (2314..2317) and MOPS (2330..2449) carry no ordering.
            return [] as MemoryOrdering
        }
    }

    @_effects(readonly)
    @_optimize(speed)
    public static func expectedOperandShape(for m: Mnemonic) -> [LSOperandKind]? {
        switch m {
        case .ldr, .str, .ldrb, .strb, .ldrh, .strh, .ldrsb, .ldrsh, .ldrsw,
             .ldur, .stur, .ldurb, .sturb, .ldurh, .sturh,
             .ldursb, .ldursh, .ldursw,
             .ldar, .stlr, .ldarb, .stlrb, .ldarh, .stlrh,
             .ldapr, .ldaprb, .ldaprh,
             .ldlar, .ldlarb, .ldlarh, .stllr, .stllrb, .stllrh,
             .ldapur, .stlur, .ldapurb, .stlurb, .ldapurh, .stlurh,
             .ldapursb, .ldapursh, .ldapursw,
             .ldraa, .ldrab,
             .ldtr, .sttr, .ldtrb, .sttrb, .ldtrh, .sttrh,
             .ldtrsb, .ldtrsh, .ldtrsw,
             .ldxr, .ldxrb, .ldxrh, .ldaxr, .ldaxrb, .ldaxrh:
            return shapeRegMem
        case .ldp, .stp, .ldpsw, .stgp, .ldnp, .stnp,
             .ldtp, .sttp, .ldtnp, .sttnp,
             .ldxp, .ldaxp:
            return shapeRegRegMem
        case .stxr, .stxrb, .stxrh, .stlxr, .stlxrb, .stlxrh:
            return shapeRegRegMem
        case .stxp, .stlxp:
            return shapeRegRegRegMem
        case .prfm, .prfum:
            return shapePrfMem
        case .sttxr, .stltxr, .cast, .casat, .caslt, .casalt:
            return shapeRegRegMem
        case .ldtxr, .ldatxr:
            return shapeRegMem
        case .caspt, .caspat, .casplt, .caspalt:
            return shapeRegRegRegRegMem
        case .ld64b, .st64b:
            return shapeRegMem
        case .st64bv, .st64bv0:
            return shapeRegRegMem
        case .rprfm:
            return shapeImmRegMem
        case .stilp, .ldiapp:
            return shapeRegRegMem
        case .gcsstr, .gcssttr:
            return shapeRegMem
        default:
            // LSE RMW base and CAS non-pair: 3-operand. LSE ST-alias drops
            // Rt → 2-operand. CASP carries two pairs → 5-operand.
            let r = m.rawValue
            if (2113 ... 2220).contains(r) {
                return shapeRegRegMem
            }
            // LSE128 (2318..2329): Xt, Xs, [Xn].
            if (2318 ... 2329).contains(r) {
                return shapeRegRegMem
            }
            // MOPS (2330..2449): three working registers.
            if (2330 ... 2449).contains(r) {
                return shapeRegRegReg
            }
            // LSUI atomics + RCW non-pair/cas/pair (2450..2521): 3-operand.
            if (2450 ... 2521).contains(r) {
                return shapeRegRegMem
            }
            // RCW CASP (2522..2529): two pairs + base → 5-operand.
            if (2522 ... 2529).contains(r) {
                return shapeRegRegRegRegMem
            }
            // LSUI ST-aliases (2534..2539): Rt dropped → 2-operand.
            if (2534 ... 2539).contains(r) {
                return shapeRegMem
            }
            if (2221 ... 2268).contains(r) {
                return shapeRegMem
            }
            if (2269 ... 2280).contains(r) {
                return shapeRegRegMem
            }
            if (2281 ... 2284).contains(r) {
                return shapeRegRegRegRegMem
            }
            return nil
        }
    }

    /// Expected semantic-reads bitmask derived from the operand list.
    /// Returns nil for mnemonics whose operand layout is too complex to
    /// summarize. Skips ZR/WZR per the `insertingNonZero(reg:into:)`
    /// convention (only SP-role is included for the encoding-31 slot).
    @_effects(readonly)
    @_optimize(speed)
    public static func expectedReadMask(for instruction: Instruction) -> UInt64? {
        guard let access = expectedMemoryAccess(for: instruction.mnemonic) else {
            return nil
        }
        let ops = Array(instruction.operands)
        let r = instruction.mnemonic.rawValue
        // FEAT_RPRES RPRFM: reads the range register (op[1]) + base (op[2]).
        if r == 2313 {
            var mask: UInt64 = 0
            if ops.count >= 2, case let .register(rm) = ops[1], !rm.isZeroRegister {
                mask |= UInt64(1) << UInt64(rm.canonicalIndex)
            }
            if ops.count >= 3, case let .memory(mem) = ops[2] {
                mask |= memoryBaseAndIndexMask(mem)
            }
            return mask
        }
        // FEAT_LS64 st64bv/st64bv0: read Xt (op[1]) + base; op[0] (Xs) is the
        // status output, not a read.
        if r == 2316 || r == 2317 {
            guard let found = lastMemoryOperand(ops) else { return nil }
            var mask: UInt64 = memoryBaseAndIndexMask(found.memory)
            mask |= registerMaskBits(ops, over: 1 ..< found.index)
            return mask
        }
        // FEAT_LSE128: reads Xt + Xs + base.
        if (2318 ... 2329).contains(r) {
            guard let found = lastMemoryOperand(ops) else { return nil }
            var mask: UInt64 = memoryBaseAndIndexMask(found.memory)
            mask |= registerMaskBits(ops, over: 0 ..< found.index)
            return mask
        }
        // FEAT_MOPS: read-modify-write reads all three working registers.
        if (2330 ... 2449).contains(r) {
            return registerMaskBits(ops, over: 0 ..< ops.count)
        }
        // FEAT_LSUI atomics (2450..2465) + ST-aliases (2534..2539): read Rs
        // (op[0]) + base; the RMW base also writes Rt, the alias drops it.
        if (2450 ... 2465).contains(r) || (2534 ... 2539).contains(r) {
            guard let found = lastMemoryOperand(ops) else { return nil }
            var mask: UInt64 = memoryBaseAndIndexMask(found.memory)
            if case let .register(rs) = ops[0], !rs.isZeroRegister {
                mask |= UInt64(1) << UInt64(rs.canonicalIndex)
            }
            return mask
        }
        // FEAT_THE RCW (2466..2529): read-check-write reads every register
        // operand (the check value, the new value, and the pair partners) plus
        // the base.
        if (2466 ... 2529).contains(r) {
            guard let found = lastMemoryOperand(ops) else { return nil }
            var mask: UInt64 = memoryBaseAndIndexMask(found.memory)
            mask |= registerMaskBits(ops, over: 0 ..< found.index)
            return mask
        }
        switch access {
        case .load:
            guard let found = lastMemoryOperand(ops) else { return nil }
            return memoryBaseAndIndexMask(found.memory)
        case .store:
            // Plain stores read operand[0..memIdx-1] as data (Rt[, Rt2]) plus
            // memory base/index. Exclusive stores use the .exclusiveStore arm
            // which skips operand[0] (Rs).
            guard let found = lastMemoryOperand(ops) else { return nil }
            var mask: UInt64 = memoryBaseAndIndexMask(found.memory)
            mask |= registerMaskBits(ops, over: 0 ..< found.index)
            return mask
        case .exclusiveStore:
            // Reads Rt[+Rt2] + base; operand[0] (Rs) is the written status.
            guard let found = lastMemoryOperand(ops) else { return nil }
            var mask: UInt64 = memoryBaseAndIndexMask(found.memory)
            mask |= registerMaskBits(ops, over: 1 ..< found.index)
            return mask
        case .exclusiveLoad:
            guard let found = lastMemoryOperand(ops) else { return nil }
            return memoryBaseAndIndexMask(found.memory)
        case .atomic:
            guard let found = lastMemoryOperand(ops) else { return nil }
            var mask: UInt64 = memoryBaseAndIndexMask(found.memory)
            let r = instruction.mnemonic.rawValue
            let isCAS = (2269 ... 2284).contains(r) || (2305 ... 2312).contains(r)
            if isCAS {
                // CAS / CASP read every register operand (Rs + Rt and the
                // pair partners for CASP).
                mask |= registerMaskBits(ops, over: 0 ..< found.index)
            } else if found.index >= 1, case let .register(reg) = ops[0],
                      !reg.isZeroRegister
            {
                // LSE RMW base / ST alias read operand[0] (Rs) only; Rt for
                // RMW base is a write of the loaded original, not a read.
                mask |= UInt64(1) << UInt64(reg.canonicalIndex)
            }
            return mask
        // `.prefetch` is `default`; `expectedMemoryAccess` never yields
        // `.none`, so the six real access kinds are all enumerated.
        default:
            guard let found = lastMemoryOperand(ops) else { return nil }
            return memoryBaseAndIndexMask(found.memory)
        }
    }

    /// Expected semantic-writes bitmask derived from the operand list.
    /// Returns nil for mnemonics whose operand layout is too complex.
    @_effects(readonly)
    @_optimize(speed)
    public static func expectedWriteMask(for instruction: Instruction) -> UInt64? {
        guard let access = expectedMemoryAccess(for: instruction.mnemonic) else {
            return nil
        }
        let ops = Array(instruction.operands)
        let r = instruction.mnemonic.rawValue
        // FEAT_LS64 st64bv/st64bv0: write the status register op[0] (Xs).
        if r == 2316 || r == 2317 {
            if case let .register(rs) = ops.first {
                return rs.isZeroRegister ? 0 : (UInt64(1) << UInt64(rs.canonicalIndex))
            }
            return nil
        }
        // FEAT_LSE128: writes Xt (op[0], the loaded original pair).
        if (2318 ... 2329).contains(r) {
            if case let .register(rt) = ops.first {
                return rt.isZeroRegister ? 0 : (UInt64(1) << UInt64(rt.canonicalIndex))
            }
            return nil
        }
        // FEAT_MOPS: CPY/CPYF (2330..2425) write all three working registers;
        // SET/SETG (2426..2449) write Xd (op[0]) + Xn (op[1]); the data
        // register Xs (op[2]) is read-only.
        if (2330 ... 2425).contains(r) {
            return registerMaskBits(ops, over: 0 ..< ops.count)
        }
        if (2426 ... 2449).contains(r) {
            return registerMaskBits(ops, over: 0 ..< min(2, ops.count))
        }
        // FEAT_LSUI atomics (2450..2465) + RCW non-pair/cas (2466..2497):
        // RMW base, write Rt (op[1], the loaded original).
        if (2450 ... 2497).contains(r) {
            if ops.count >= 2, case let .register(rt) = ops[1] {
                return rt.isZeroRegister ? 0 : (UInt64(1) << UInt64(rt.canonicalIndex))
            }
            return nil
        }
        // RCW pairs (2498..2521): write Rt (op[0]).
        if (2498 ... 2521).contains(r) {
            if case let .register(rt) = ops.first {
                return rt.isZeroRegister ? 0 : (UInt64(1) << UInt64(rt.canonicalIndex))
            }
            return nil
        }
        // RCW CASP (2522..2529): write the Rs pair (op[0], op[1]).
        if (2522 ... 2529).contains(r) {
            return registerMaskBits(ops, over: 0 ..< min(2, ops.count))
        }
        // LSUI ST-aliases (2534..2539): the loaded value is discarded → no write.
        if (2534 ... 2539).contains(r) {
            return 0
        }
        switch access {
        case .load:
            guard let found = lastMemoryOperand(ops) else { return nil }
            var mask: UInt64 = registerMaskBits(ops, over: 0 ..< found.index)
            // Writeback (pre/post-index) also writes the base register.
            if found.memory.writeback != .none {
                if case let .register(baseReg) = found.memory.base, !baseReg.isZeroRegister {
                    mask |= UInt64(1) << UInt64(baseReg.canonicalIndex)
                }
            }
            return mask
        case .store:
            guard let found = lastMemoryOperand(ops) else { return nil }
            if found.memory.writeback != .none {
                if case let .register(baseReg) = found.memory.base, !baseReg.isZeroRegister {
                    return UInt64(1) << UInt64(baseReg.canonicalIndex)
                }
            }
            return 0
        case .exclusiveStore:
            if case let .register(rsReg) = ops.first {
                if rsReg.isZeroRegister { return 0 }
                return UInt64(1) << UInt64(rsReg.canonicalIndex)
            }
            return nil
        case .exclusiveLoad:
            guard let found = lastMemoryOperand(ops) else { return nil }
            return registerMaskBits(ops, over: 0 ..< found.index)
        case .atomic:
            let r = instruction.mnemonic.rawValue
            let isCASNonPair = (2269 ... 2280).contains(r) || (2305 ... 2308).contains(r)
            let isCASP = (2281 ... 2284).contains(r) || (2309 ... 2312).contains(r)
            let isLSEAlias = (2221 ... 2268).contains(r)
            if isCASNonPair {
                if case let .register(rsReg) = ops.first {
                    if rsReg.isZeroRegister { return 0 }
                    return UInt64(1) << UInt64(rsReg.canonicalIndex)
                }
                return nil
            }
            if isCASP {
                var mask: UInt64 = 0
                if ops.count >= 2,
                   case let .register(rs0) = ops[0],
                   case let .register(rs1) = ops[1]
                {
                    if !rs0.isZeroRegister {
                        mask |= UInt64(1) << UInt64(rs0.canonicalIndex)
                    }
                    if !rs1.isZeroRegister {
                        mask |= UInt64(1) << UInt64(rs1.canonicalIndex)
                    }
                }
                return mask
            }
            if isLSEAlias {
                return 0
            }
            // The four atomic sub-ranges (CAS non-pair, CASP, LSE alias, LSE
            // RMW base) partition rawValue 2113...2284 exactly, and
            // `expectedMemoryAccess` yields `.atomic` only for that range, so
            // the remaining case is LSE RMW base — it writes Rt (operand[1]).
            if ops.count >= 2, case let .register(rtReg) = ops[1] {
                if rtReg.isZeroRegister { return 0 }
                return UInt64(1) << UInt64(rtReg.canonicalIndex)
            }
            return nil
        // `.prefetch` is `default`; `expectedMemoryAccess` never yields `.none`.
        default:
            return 0
        }
    }

    /// Last `.memory(_)` operand and its index, or `nil` if none.
    @inline(__always)
    @_effects(readonly)
    private static func lastMemoryOperand(
        _ ops: [Operand],
    ) -> (index: Int, memory: MemoryOperand)? {
        for i in stride(from: ops.count - 1, through: 0, by: -1) {
            if case let .memory(m) = ops[i] { return (i, m) }
        }
        return nil
    }

    /// Base + index register bits (skipping ZR-role) for a memory operand.
    @inline(__always)
    @_effects(readonly)
    private static func memoryBaseAndIndexMask(_ mem: MemoryOperand) -> UInt64 {
        var mask: UInt64 = 0
        if case let .register(baseReg) = mem.base, !baseReg.isZeroRegister {
            mask |= UInt64(1) << UInt64(baseReg.canonicalIndex)
        }
        if let indexReg = mem.index, !indexReg.isZeroRegister {
            mask |= UInt64(1) << UInt64(indexReg.canonicalIndex)
        }
        return mask
    }

    /// Bits to OR into a read/write mask for every `.register` operand in
    /// `ops[range]` (skipping ZR/WZR per ``insertingNonZero(reg:into:)``).
    @inline(__always)
    @_effects(readonly)
    private static func registerMaskBits(
        _ ops: [Operand], over range: Range<Int>,
    ) -> UInt64 {
        var mask: UInt64 = 0
        for i in range {
            if case let .register(r) = ops[i], !r.isZeroRegister {
                mask |= UInt64(1) << UInt64(r.canonicalIndex)
            }
        }
        return mask
    }
}
