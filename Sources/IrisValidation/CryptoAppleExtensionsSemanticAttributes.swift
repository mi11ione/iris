// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

@frozen
public struct CryptoSemanticIssue: Sendable, Equatable {
    public let field: String
    public let actual: String
    public let expected: String

    @inlinable
    public init(field: String, actual: String, expected: String) {
        self.field = field
        self.actual = actual
        self.expected = expected
    }
}

/// Independent reads / writes / flags / memory-access verification for every
/// crypto/Apple-extensions record, across all the op0 partitions those
/// instructions live in.
public enum CryptoAppleExtensionsSemanticChecker {
    private static let pacSignReg: Set<Mnemonic> = [.pacia, .pacib, .pacda, .pacdb]
    private static let pacAuthReg: Set<Mnemonic> = [.autia, .autib, .autda, .autdb]
    private static let pacSignZero: Set<Mnemonic> = [.paciza, .pacizb, .pacdza, .pacdzb]
    private static let pacAuthZero: Set<Mnemonic> = [.autiza, .autizb, .autdza, .autdzb]
    private static let xpac: Set<Mnemonic> = [.xpaci, .xpacd]
    /// FEAT_PAuth_LR forms whose modifier is SP (the LR is both source and
    /// destination), plus the two that take it from an Rn operand and the
    /// four that use the X15/X16/X17 triple.
    private static let pacLRStackModifier: Set<Mnemonic> = [
        .paciasppc, .pacibsppc, .pacnbiasppc, .pacnbibsppc, .autiasppc, .autibsppc,
    ]
    private static let pacLRRegisterModifier: Set<Mnemonic> = [.autiasppcr, .autibsppcr]
    private static let pacLRTripleModifier: Set<Mnemonic> = [
        .pacia171615, .pacib171615, .autia171615, .autib171615,
    ]
    private static let mteDPR: Set<Mnemonic> = [.irg, .gmi, .subp, .subps]
    private static let mteLS: Set<Mnemonic> = [
        .ldg, .stg, .st2g, .stzg, .stz2g, .ldgm, .stgm, .stzgm,
    ]

    /// Crypto destination-also-source set (the accumulate / round forms whose
    /// Vd/Qd is both read and written), from the ARM ARM.
    private static let cryptoTiedDestination: Set<Mnemonic> = [
        .aese, .aesd, .sha1c, .sha1p, .sha1m, .sha1su0, .sha1su1,
        .sha256su0, .sha256su1, .sha256h, .sha256h2,
        .sm3tt1a, .sm3tt1b, .sm3tt2a, .sm3tt2b,
        .sha512h, .sha512h2, .sha512su1, .sm3partw1, .sm3partw2,
        .sha512su0, .sm4e,
    ]

    /// Verify a crypto/Apple-extensions record's semantic attributes.
    @_effects(readonly)
    public static func verify(_ instruction: Instruction) -> CryptoSemanticIssue? {
        let m = instruction.mnemonic
        let isPACLinkRegister = pacLRStackModifier.contains(m)
            || pacLRRegisterModifier.contains(m) || pacLRTripleModifier.contains(m)
        let isPAC = pacSignReg.contains(m) || pacAuthReg.contains(m)
            || pacSignZero.contains(m) || pacAuthZero.contains(m)
            || xpac.contains(m) || m == .pacga || isPACLinkRegister
        let isMTEDPR = mteDPR.contains(m)
        let isMTEDPI = m == .addg || m == .subg
        let isMTELS = mteLS.contains(m)
        let isCrypto = instruction.category == .crypto
        let isAMX = instruction.category == .amx
        guard isPAC || isMTEDPR || isMTEDPI || isMTELS || isCrypto || isAMX else { return nil }

        if instruction.branchClass != .none {
            return CryptoSemanticIssue(field: "branchClass", actual: "\(instruction.branchClass)", expected: "none")
        }
        if instruction.memoryOrdering != [] {
            return CryptoSemanticIssue(field: "memoryOrdering", actual: "\(instruction.memoryOrdering)", expected: "[]")
        }

        let expectedCategory: Category = if isCrypto {
            .crypto
        } else if isAMX {
            .amx
        } else if isPAC {
            .pointerAuthentication
        } else {
            .memoryTagging
        }
        if instruction.category != expectedCategory {
            return CryptoSemanticIssue(field: "category", actual: "\(instruction.category)", expected: "\(expectedCategory)")
        }

        let expectedFlag: FlagEffect = m == .subps ? .nzcv : .none
        if instruction.flagEffect != expectedFlag {
            return CryptoSemanticIssue(field: "flagEffect", actual: "\(instruction.flagEffect)", expected: "\(expectedFlag)")
        }

        let expectedAccess: MemoryAccess = if m == .ldg || m == .ldgm {
            .load
        } else if isMTELS {
            .store
        } else {
            .none
        }
        if instruction.memoryAccess != expectedAccess {
            return CryptoSemanticIssue(field: "memoryAccess", actual: "\(instruction.memoryAccess)", expected: "\(expectedAccess)")
        }

        let ops = instruction.operands
        let (expectedReads, expectedWrites): (UInt64, UInt64) = if isCrypto {
            cryptoReadsWrites(m: m, ops: ops)
        } else if isMTEDPI {
            (operandRegisterMask(ops, 1), operandRegisterMask(ops, 0))
        } else if isMTELS {
            mteLoadStoreReadsWrites(m: m, ops: ops)
        } else if isAMX {
            (amxReads(ops), 0)
        } else if isPACLinkRegister {
            pacLinkRegisterReadsWrites(m: m, ops: ops)
        } else {
            pacMTEDPRReadsWrites(m: m, ops: ops)
        }

        if instruction.semanticWrites.mask != expectedWrites {
            return CryptoSemanticIssue(
                field: "semanticWrites",
                actual: "0x\(String(instruction.semanticWrites.mask, radix: 16))",
                expected: "0x\(String(expectedWrites, radix: 16))",
            )
        }
        if instruction.semanticReads.mask != expectedReads {
            return CryptoSemanticIssue(
                field: "semanticReads",
                actual: "0x\(String(instruction.semanticReads.mask, radix: 16))",
                expected: "0x\(String(expectedReads, radix: 16))",
            )
        }
        return nil
    }

    /// FEAT_PAuth_LR: the stack-modifier and register-modifier forms sign or
    /// authenticate LR; the X15/X16/X17 triple forms target X17.
    @_effects(readonly)
    private static func pacLinkRegisterReadsWrites(
        m: Mnemonic, ops: Instruction.Operands,
    ) -> (UInt64, UInt64) {
        let lr = UInt64(1) << 30
        if pacLRTripleModifier.contains(m) {
            let triple = (UInt64(1) << 15) | (UInt64(1) << 16) | (UInt64(1) << 17)
            return (triple, UInt64(1) << 17)
        }
        if pacLRRegisterModifier.contains(m) {
            return (lr | operandRegisterMask(ops, 0), lr)
        }
        return (lr | (UInt64(1) << 31), lr)
    }

    /// PAC standalone + MTE-DPR (IRG / GMI / SUBP / SUBPS).
    @_effects(readonly)
    private static func pacMTEDPRReadsWrites(m: Mnemonic, ops: Instruction.Operands) -> (UInt64, UInt64) {
        let rd0 = operandRegisterMask(ops, 0)
        let rd1 = operandRegisterMask(ops, 1)
        let rd2 = operandRegisterMask(ops, 2)
        let reads: UInt64 = if pacSignReg.contains(m) || pacAuthReg.contains(m) {
            rd0 | rd1
        } else if pacSignZero.contains(m) || pacAuthZero.contains(m) || xpac.contains(m) {
            rd0
        } else {
            rd1 | rd2
        }
        return (reads, rd0)
    }

    /// Crypto: write the destination (operand 0); read every source operand
    /// (operands 1...) plus the destination when it is also a source (the
    /// accumulate/round forms). Immediate operands contribute no register.
    @_effects(readonly)
    private static func cryptoReadsWrites(m: Mnemonic, ops: Instruction.Operands) -> (UInt64, UInt64) {
        let writes = operandRegisterMask(ops, 0)
        var reads: UInt64 = 0
        var i = 1
        while i < ops.count {
            reads |= operandRegisterMask(ops, i)
            i &+= 1
        }
        if cryptoTiedDestination.contains(m) { reads |= writes }
        return (reads, writes)
    }

    /// MTE L/S, with Rt at operand 0 and the `[Xn]` memory operand at 1. LDG is
    /// a read-modify-write of Rt, LDGM writes it whole, and the stores read it;
    /// all read the base, and pre/post writeback updates it.
    @_effects(readonly)
    private static func mteLoadStoreReadsWrites(m: Mnemonic, ops: Instruction.Operands) -> (UInt64, UInt64) {
        let rt = operandRegisterMask(ops, 0)
        let base = memoryBaseMask(ops, 1)
        let wb = memoryWriteback(ops, 1) ? base : 0
        switch m {
        case .ldg:
            return (rt | base, rt | wb)
        case .ldgm:
            return (base, rt | wb)
        default:
            return (rt | base, wb)
        }
    }

    /// AMX documented data ops read the X-register named by the 5-bit operand
    /// subfield (X31 = XZR contributes nothing); set/clr (opcode 17) and
    /// undocumented opcodes name no register.
    @_effects(readonly)
    private static func amxReads(_ ops: Instruction.Operands) -> UInt64 {
        guard case let .amxField(field) = ops.first else { return 0 }
        guard field.opcode <= 22, field.opcode != 17 else { return 0 }
        let x = field.operandField
        return x == 31 ? 0 : (UInt64(1) << UInt64(x))
    }

    /// Register mask for a single-register operand (GPR or SIMD).
    @_effects(readonly)
    private static func operandRegisterMask(_ ops: Instruction.Operands, _ index: Int) -> UInt64 {
        guard index >= 0, index < ops.count else { return 0 }
        switch ops[index] {
        case let .register(r):
            return r.isZeroRegister ? 0 : (UInt64(1) << UInt64(r.canonicalIndex))
        case let .vectorRegister(v):
            return UInt64(1) << UInt64(32 &+ UInt32(v.registerIndex))
        default:
            return 0
        }
    }

    /// Base-register mask for a `.memory` operand.
    @_effects(readonly)
    private static func memoryBaseMask(_ ops: Instruction.Operands, _ index: Int) -> UInt64 {
        guard index >= 0, index < ops.count, case let .memory(mem) = ops[index] else { return 0 }
        guard case let .register(r) = mem.base, !r.isZeroRegister else { return 0 }
        return UInt64(1) << UInt64(r.canonicalIndex)
    }

    /// Whether a `.memory` operand carries pre/post-index writeback.
    @_effects(readonly)
    private static func memoryWriteback(_ ops: Instruction.Operands, _ index: Int) -> Bool {
        guard index >= 0, index < ops.count, case let .memory(mem) = ops[index] else { return false }
        return mem.writeback != .none
    }
}

/// Whether a mnemonic belongs to the crypto / Apple-extensions family, whose
/// records reach the DPI and DPR decoders by delegation; those checkers hand
/// such a record here rather than to their own expectations.
@_effects(readonly)
func cryptoAppleExtensionsOwns(_ mnemonic: Mnemonic) -> Bool {
    mnemonic.rawValue >= 12288 && mnemonic.rawValue <= 16383
}
