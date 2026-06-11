// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Independent semantic oracle for the Crypto + Apple-extensions
// records, scattered across op0 partitions: crypto (AES / SHA-1 / SHA-256 /
// SHA-3 / SHA-512 / SM3 / SM4, in the SIMD/FP partition), PAC standalone +
// MTE-DPR (the DPR partition), MTE-DPI ADDG/SUBG (the DPI partition),
// MTE L/S (the L/S partition), and AMX (its own op0-0). Each host
// partition's verification pass routes its crypto/Apple-extension records
// here; the AMX pass routes
// AMX here. Expected reads / writes / flags / memory-access are derived
// from the text-validated operand list by architectural rule (ARM ARM for
// crypto+PAC+MTE, corsix/amx for AMX) — a separate computation from the
// decoders' own attribute logic, so a divergence between the two surfaces a
// decoder bug (as it historically did for PAC-sign).

/// Semantic-field discrepancy for a crypto/Apple-extensions record. Same
/// shape as the other per-family checkers' issue types.
@frozen
@_spi(Validation)
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
@_spi(Validation)
public enum CryptoAppleExtensionsSemanticChecker {
    // PAC standalone, by how it touches Rd. Sign and auth are both in-place
    // transforms of the pointer in Rd — `X[d] = AddPAC/Auth(X[d], modifier)` —
    // so both READ Rd (the pointer) and write it: register-source PAC/AUT read
    // Rd + modifier Rn; zero-source PAC/AUT and XPAC read+write Rd. PACGA is
    // the exception — a 3-operand form where Rd is pure output (read Rn + Rm).
    private static let pacSignReg: Set<Mnemonic> = [.pacia, .pacib, .pacda, .pacdb]
    private static let pacAuthReg: Set<Mnemonic> = [.autia, .autib, .autda, .autdb]
    private static let pacSignZero: Set<Mnemonic> = [.paciza, .pacizb, .pacdza, .pacdzb]
    private static let pacAuthZero: Set<Mnemonic> = [.autiza, .autizb, .autdza, .autdzb]
    private static let xpac: Set<Mnemonic> = [.xpaci, .xpacd]
    private static let mteDPR: Set<Mnemonic> = [.irg, .gmi, .subp, .subps]
    private static let mteLS: Set<Mnemonic> = [
        .ldg, .stg, .st2g, .stzg, .stz2g, .ldgm, .stgm, .stzgm,
    ]

    /// Crypto destination-also-source set (the accumulate / round forms whose
    /// Vd/Qd is both read and written), from the ARM ARM. The complement —
    /// AESMC, AESIMC, SHA1H, EOR3, BCAX, SM3SS1, RAX1, XAR, SM4EKEY — has Vd as
    /// pure output.
    private static let cryptoTiedDestination: Set<Mnemonic> = [
        .aese, .aesd, .sha1c, .sha1p, .sha1m, .sha1su0, .sha1su1,
        .sha256su0, .sha256su1, .sha256h, .sha256h2,
        .sm3tt1a, .sm3tt1b, .sm3tt2a, .sm3tt2b,
        .sha512h, .sha512h2, .sha512su1, .sm3partw1, .sm3partw2,
        .sha512su0, .sm4e,
    ]

    /// Verify a crypto/Apple-extensions record's semantic attributes.
    /// Returns nil when it
    /// matches every expected attribute, or when the mnemonic is not such
    /// a record (defensive — callers gate on `owns()` / the AMX category).
    @_effects(readonly)
    public static func verify(_ instruction: Instruction) -> CryptoSemanticIssue? {
        let m = instruction.mnemonic
        let isPAC = pacSignReg.contains(m) || pacAuthReg.contains(m)
            || pacSignZero.contains(m) || pacAuthZero.contains(m)
            || xpac.contains(m) || m == .pacga
        let isMTEDPR = mteDPR.contains(m)
        let isMTEDPI = m == .addg || m == .subg
        let isMTELS = mteLS.contains(m)
        let isCrypto = instruction.category == .crypto
        let isAMX = instruction.category == .amx
        guard isPAC || isMTEDPR || isMTEDPI || isMTELS || isCrypto || isAMX else { return nil }

        // Universal: none of these records branch or carry memory ordering.
        if instruction.branchClass != .none {
            return CryptoSemanticIssue(field: "branchClass", actual: "\(instruction.branchClass)", expected: "none")
        }
        if instruction.memoryOrdering != [] {
            return CryptoSemanticIssue(field: "memoryOrdering", actual: "\(instruction.memoryOrdering)", expected: "[]")
        }

        // Category.
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

        // Flags: only SUBPS sets NZCV; every other record here leaves them.
        let expectedFlag: FlagEffect = m == .subps ? .nzcv : .none
        if instruction.flagEffect != expectedFlag {
            return CryptoSemanticIssue(field: "flagEffect", actual: "\(instruction.flagEffect)", expected: "\(expectedFlag)")
        }

        // Memory access: only the MTE L/S tier touches memory.
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

        // Reads / writes by architectural class.
        let ops = Array(instruction.operands)
        let (expectedReads, expectedWrites): (UInt64, UInt64) = if isCrypto {
            cryptoReadsWrites(m: m, ops: ops)
        } else if isMTEDPI {
            // ADDG / SUBG: Rd = Rn op tags. Write Rd, read Rn (operands 2,3
            // are immediates).
            (operandRegisterMask(ops, 1), operandRegisterMask(ops, 0))
        } else if isMTELS {
            mteLoadStoreReadsWrites(m: m, ops: ops)
        } else if isAMX {
            (amxReads(ops), 0)
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

    // MARK: - Per-tier reads/writes rules

    /// PAC standalone + MTE-DPR (IRG / GMI / SUBP / SUBPS). Every form writes
    /// Rd (operand 0). Reads by class: register-source PAC/AUT read Rd+Rn;
    /// zero-source PAC/AUT and XPAC read Rd; PACGA and MTE-DPR read Rn+Rm
    /// (Rd pure output).
    @_effects(readonly)
    private static func pacMTEDPRReadsWrites(m: Mnemonic, ops: [Operand]) -> (UInt64, UInt64) {
        let rd0 = operandRegisterMask(ops, 0)
        let rd1 = operandRegisterMask(ops, 1)
        let rd2 = operandRegisterMask(ops, 2)
        let reads: UInt64 = if pacSignReg.contains(m) || pacAuthReg.contains(m) {
            rd0 | rd1
        } else if pacSignZero.contains(m) || pacAuthZero.contains(m) || xpac.contains(m) {
            rd0
        } else {
            rd1 | rd2 // PACGA + MTE-DPR: Rd is pure output; read Rn + Rm.
        }
        return (reads, rd0)
    }

    /// Crypto: write the destination (operand 0); read every source operand
    /// (operands 1...) plus the destination when it is also a source (the
    /// accumulate/round forms). Immediate operands contribute no register.
    @_effects(readonly)
    private static func cryptoReadsWrites(m: Mnemonic, ops: [Operand]) -> (UInt64, UInt64) {
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

    /// MTE L/S. Operand 0 is Rt, operand 1 the `[Xn]` memory operand.
    ///   - LDG: read-modify-write of Rt (the loaded tag is inserted into Rt,
    ///     preserving Xt's other bits → Rt is read AND written) + read base.
    ///   - LDGM: bulk load, Rt fully written; read base.
    ///   - stores (STG/ST2G/STZG/STZ2G/STGM/STZGM): read Rt + base; pre/post
    ///     writeback updates the base register.
    @_effects(readonly)
    private static func mteLoadStoreReadsWrites(m: Mnemonic, ops: [Operand]) -> (UInt64, UInt64) {
        let rt = operandRegisterMask(ops, 0)
        let base = memoryBaseMask(ops, 1)
        let wb = memoryWriteback(ops, 1) ? base : 0
        switch m {
        case .ldg:
            return (rt | base, rt | wb)
        case .ldgm:
            return (base, rt | wb)
        default: // stores
            return (rt | base, wb)
        }
    }

    /// AMX documented data ops read the X-register named by the 5-bit operand
    /// subfield (X31 = XZR contributes nothing); set/clr (opcode 17) and
    /// undocumented opcodes name no register. No AMX op writes a GPR (the
    /// coprocessor state is not in the general register file).
    @_effects(readonly)
    private static func amxReads(_ ops: [Operand]) -> UInt64 {
        guard case let .amxField(field) = ops.first else { return 0 }
        guard field.opcode <= 22, field.opcode != 17 else { return 0 }
        let x = field.operandField
        return x == 31 ? 0 : (UInt64(1) << UInt64(x))
    }

    // MARK: - Operand → register-mask helpers

    /// Register mask for a single-register operand (GPR or SIMD). Zero
    /// register (XZR/WZR) contributes nothing; SIMD registers occupy
    /// canonical indices 32...63.
    @_effects(readonly)
    private static func operandRegisterMask(_ ops: [Operand], _ index: Int) -> UInt64 {
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
    private static func memoryBaseMask(_ ops: [Operand], _ index: Int) -> UInt64 {
        guard index >= 0, index < ops.count, case let .memory(mem) = ops[index] else { return 0 }
        guard case let .register(r) = mem.base, !r.isZeroRegister else { return 0 }
        return UInt64(1) << UInt64(r.canonicalIndex)
    }

    /// Whether a `.memory` operand carries pre/post-index writeback.
    @_effects(readonly)
    private static func memoryWriteback(_ ops: [Operand], _ index: Int) -> Bool {
        guard index >= 0, index < ops.count, case let .memory(mem) = ops[index] else { return false }
        return mem.writeback != .none
    }
}
