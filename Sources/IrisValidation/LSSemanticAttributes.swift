// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

@frozen
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

/// A whole operand shape packed into one word.
@frozen
public struct LSOperandShape: Sendable, Equatable {
    /// bits [2:0] operand count; bits [4+2k:3+2k] the kind of operand `k`.
    @usableFromInline let packed: UInt16

    /// Widest shape the table describes (`CASP`.
    @usableFromInline static let maxCount = 5

    init(_ kinds: LSOperandKind...) {
        var bits = UInt16(kinds.count)
        for (k, kind) in kinds.enumerated() {
            bits |= UInt16(kind.code) << UInt16(3 + 2 * k)
        }
        packed = bits
    }

    /// Number of operands in the shape.
    @inlinable public var count: Int {
        Int(packed & 0b111)
    }

    /// The kind at `index`, or `nil` when `index` is past the shape.
    @inlinable public func kind(at index: Int) -> LSOperandKind? {
        guard index >= 0, index < count else { return nil }
        return LSOperandKind(code: UInt8((packed >> UInt16(3 + 2 * index)) & 0b11))
    }

    /// The shape as a list.
    public var kinds: [LSOperandKind] {
        var out: [LSOperandKind] = []
        out.reserveCapacity(count)
        for i in 0 ..< count {
            out.append(LSOperandKind(code: UInt8((packed >> UInt16(3 + 2 * i)) & 0b11)))
        }
        return out
    }
}

/// Typed operand-kind summary for the operand-shape table.
@frozen
public enum LSOperandKind: Sendable, Equatable {
    /// `.register(_)` operand.
    case register
    /// `.memory(_)` operand.
    case memory
    /// `.prefetchOperation(_)` operand.
    case prefetchOperation
    /// `.immediate(_)` or `.unsignedImmediate(_)` operand.
    case immediate

    /// Two-bit encoding used by ``LSOperandShape``.
    @usableFromInline var code: UInt8 {
        switch self {
        case .register: 0
        case .memory: 1
        case .prefetchOperation: 2
        case .immediate: 3
        }
    }

    @usableFromInline init(code: UInt8) {
        switch code {
        case 0: self = .register
        case 1: self = .memory
        case 2: self = .prefetchOperation
        default: self = .immediate
        }
    }
}

/// Per-record semantic-field verification against the spec table.
public enum LSSemanticChecker {
    @_effects(readonly)
    @_optimize(speed)
    public static func verify(_ instruction: Instruction) -> LSSemanticIssue? {
        if instruction.mnemonic == .undefined { return nil }
        if cryptoAppleExtensionsOwns(instruction.mnemonic) { return nil }
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
        if let expectedShape = LSSemanticAttributes.packedOperandShape(for: instruction.mnemonic) {
            if !operandsMatchShape(instruction.operands, expected: expectedShape) {
                return LSSemanticIssue(
                    field: "operandShape",
                    actual: formatOperandShape(instruction.operands),
                    expected: "\(expectedShape.kinds)",
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
        _ ops: Instruction.Operands, expected: LSOperandShape,
    ) -> Bool {
        guard ops.count == expected.count else { return false }
        for i in 0 ..< ops.count {
            guard let actual = operandKind(of: ops[i]), actual == expected.kind(at: i)
            else { return false }
        }
        return true
    }

    /// Cold path: only invoked when a shape mismatch is being reported.
    @_effects(readonly)
    private static func formatOperandShape(_ ops: Instruction.Operands) -> String {
        var shape: [LSOperandKind] = []
        shape.reserveCapacity(ops.count)
        for op in ops {
            shape.append(operandKind(of: op) ?? .immediate)
        }
        return "\(shape)"
    }
}

/// Per-mnemonic semantic-attribute lookups.
public enum LSSemanticAttributes {
    private static let shapeRegMem = LSOperandShape(.register, .memory)
    private static let shapeRegRegMem = LSOperandShape(.register, .register, .memory)
    private static let shapeRegRegRegMem = LSOperandShape(
        .register, .register, .register, .memory,
    )
    private static let shapeRegRegRegRegMem = LSOperandShape(
        .register, .register, .register, .register, .memory,
    )
    private static let shapePrfMem = LSOperandShape(.prefetchOperation, .memory)
    private static let shapeRegReg = LSOperandShape(.register, .register)
    private static let shapeRegRegReg = LSOperandShape(.register, .register, .register)
    /// FEAT_RPRES RPRFM: range-prefetch op (immediate) + range register +
    /// base.
    private static let shapeImmRegMem = LSOperandShape(.immediate, .register, .memory)

    /// Architecturally-correct `FlagEffect` for an L/S mnemonic.
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
        case .stilp, .gcsstr, .gcssttr, .stlp:
            return .store
        case .ldap, .ldapp:
            return .load
        default:
            let r = m.rawValue
            if (2113 ... 2284).contains(r) || (2318 ... 2449).contains(r)
                || (2450 ... 2529).contains(r) || (2534 ... 2539).contains(r)
                || (2540 ... 2551).contains(r)
            {
                return .atomic
            }
            return nil
        }
    }

    @_effects(readonly)
    @_optimize(speed)
    public static func expectedMemoryOrdering(for m: Mnemonic) -> MemoryOrdering? {
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
        case .ldap, .ldapp:
            return [.acquire]
        case .stlp:
            return [.release]
        default:
            let r = m.rawValue
            if (2113 ... 2220).contains(r) {
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
                switch (r - 2269) % 4 {
                case 0: return []
                case 1: return [.acquire]
                case 2: return [.release]
                default: return [.acquire, .release]
                }
            }
            if (2318 ... 2329).contains(r) {
                switch (r - 2318) % 4 {
                case 0: return []
                case 1: return [.acquire]
                case 2: return [.release]
                default: return [.acquire, .release]
                }
            }
            if (2450 ... 2529).contains(r) {
                switch (r - 2450) % 4 {
                case 0: return []
                case 1: return [.release]
                case 2: return [.acquire]
                default: return [.acquire, .release]
                }
            }
            if r == 2530 { return [.release] }
            if r == 2531 { return [.acquire] }
            if r == 2532 || r == 2533 { return [] }
            if (2534 ... 2539).contains(r) {
                return (r - 2534) % 2 == 0 ? [] : [.release]
            }
            return [] as MemoryOrdering
        }
    }

    /// The per-mnemonic operand shape as a list.
    @_effects(readonly)
    public static func expectedOperandShape(for m: Mnemonic) -> [LSOperandKind]? {
        packedOperandShape(for: m)?.kinds
    }

    @_effects(readonly)
    @_optimize(speed)
    public static func packedOperandShape(for m: Mnemonic) -> LSOperandShape? {
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
        case .stilp, .ldiapp, .ldap, .ldapp, .stlp:
            return shapeRegRegMem
        case .gcsstr, .gcssttr:
            return shapeRegMem
        default:
            let r = m.rawValue
            if (2113 ... 2220).contains(r) {
                return shapeRegRegMem
            }
            if (2318 ... 2329).contains(r) {
                return shapeRegRegMem
            }
            if (2330 ... 2449).contains(r) {
                return shapeRegRegReg
            }
            if (2540 ... 2551).contains(r) {
                return shapeRegReg
            }
            if (2450 ... 2521).contains(r) {
                return shapeRegRegMem
            }
            if (2522 ... 2529).contains(r) {
                return shapeRegRegRegRegMem
            }
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
    @_effects(readonly)
    @_optimize(speed)
    public static func expectedReadMask(for instruction: Instruction) -> UInt64? {
        guard let access = expectedMemoryAccess(for: instruction.mnemonic) else {
            return nil
        }
        let ops = instruction.operands
        let r = instruction.mnemonic.rawValue
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
        if r == 2316 || r == 2317 {
            guard let found = lastMemoryOperand(ops) else { return nil }
            var mask: UInt64 = memoryBaseAndIndexMask(found.memory)
            mask |= registerMaskBits(ops, over: 1 ..< found.index)
            return mask
        }
        if (2318 ... 2329).contains(r) {
            guard let found = lastMemoryOperand(ops) else { return nil }
            var mask: UInt64 = memoryBaseAndIndexMask(found.memory)
            mask |= registerMaskBits(ops, over: 0 ..< found.index)
            return mask
        }
        if (2330 ... 2449).contains(r) || (2540 ... 2551).contains(r) {
            return registerMaskBits(ops, over: 0 ..< ops.count)
        }
        if (2450 ... 2465).contains(r) || (2534 ... 2539).contains(r) {
            guard let found = lastMemoryOperand(ops) else { return nil }
            var mask: UInt64 = memoryBaseAndIndexMask(found.memory)
            if case let .register(rs) = ops[0], !rs.isZeroRegister {
                mask |= UInt64(1) << UInt64(rs.canonicalIndex)
            }
            return mask
        }
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
            guard let found = lastMemoryOperand(ops) else { return nil }
            var mask: UInt64 = memoryBaseAndIndexMask(found.memory)
            mask |= registerMaskBits(ops, over: 0 ..< found.index)
            return mask
        case .exclusiveStore:
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
                mask |= registerMaskBits(ops, over: 0 ..< found.index)
            } else if found.index >= 1, case let .register(reg) = ops[0],
                      !reg.isZeroRegister
            {
                mask |= UInt64(1) << UInt64(reg.canonicalIndex)
            }
            return mask
        default:
            guard let found = lastMemoryOperand(ops) else { return nil }
            return memoryBaseAndIndexMask(found.memory)
        }
    }

    /// Expected semantic-writes bitmask derived from the operand list.
    @_effects(readonly)
    @_optimize(speed)
    public static func expectedWriteMask(for instruction: Instruction) -> UInt64? {
        guard let access = expectedMemoryAccess(for: instruction.mnemonic) else {
            return nil
        }
        let ops = instruction.operands
        let r = instruction.mnemonic.rawValue
        if r == 2316 || r == 2317 {
            if case let .register(rs) = ops.first {
                return rs.isZeroRegister ? 0 : (UInt64(1) << UInt64(rs.canonicalIndex))
            }
            return nil
        }
        if (2318 ... 2329).contains(r) {
            if case let .register(rt) = ops.first {
                return rt.isZeroRegister ? 0 : (UInt64(1) << UInt64(rt.canonicalIndex))
            }
            return nil
        }
        if (2330 ... 2425).contains(r) {
            return registerMaskBits(ops, over: 0 ..< ops.count)
        }
        if (2426 ... 2449).contains(r) || (2540 ... 2551).contains(r) {
            return registerMaskBits(ops, over: 0 ..< min(2, ops.count))
        }
        if (2450 ... 2497).contains(r) {
            if ops.count >= 2, case let .register(rt) = ops[1] {
                return rt.isZeroRegister ? 0 : (UInt64(1) << UInt64(rt.canonicalIndex))
            }
            return nil
        }
        if (2498 ... 2521).contains(r) {
            if case let .register(rt) = ops.first {
                return rt.isZeroRegister ? 0 : (UInt64(1) << UInt64(rt.canonicalIndex))
            }
            return nil
        }
        if (2522 ... 2529).contains(r) {
            return registerMaskBits(ops, over: 0 ..< min(2, ops.count))
        }
        if (2534 ... 2539).contains(r) {
            return 0
        }
        switch access {
        case .load:
            guard let found = lastMemoryOperand(ops) else { return nil }
            var mask: UInt64 = registerMaskBits(ops, over: 0 ..< found.index)
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
            if ops.count >= 2, case let .register(rtReg) = ops[1] {
                if rtReg.isZeroRegister { return 0 }
                return UInt64(1) << UInt64(rtReg.canonicalIndex)
            }
            return nil
        default:
            return 0
        }
    }

    /// Last `.memory(_)` operand and its index, or `nil` if none.
    @inline(__always)
    @_effects(readonly)
    private static func lastMemoryOperand(
        _ ops: Instruction.Operands,
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
        _ ops: Instruction.Operands, over range: Range<Int>,
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
