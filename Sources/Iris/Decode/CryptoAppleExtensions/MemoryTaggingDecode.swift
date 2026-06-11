// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// MTE decoder. Three entry points matching the three encoding tiers
// MTE lives in:
//   - decodeDPI:  ADDG / SUBG          (called by DataProcessingImmediateDecoder)
//   - decodeDPR:  IRG / GMI / SUBP / SUBPS  (called by DataProc2or1SourceDecode)
//   - decodeLS:   LDG / STG / ST2G / STZG / STZ2G / LDGM / STGM / STZGM
//                                         (called by LoadsAndStoresDecoder)
//
// STGP is NOT handled here — the L/S family owns STGP at LoadStorePairDecode.
// The L/S MTE dispatch covers an exhaustive (opc1, op2)
// table; reserved combinations return nil so the caller emits UNDEFINED.

enum MemoryTaggingDecode {
    // MARK: - DPI tier (ADDG / SUBG)

    /// ADDG / SUBG in the DPI add-with-tags row. Returns nil if the
    /// encoding's sf or row prefix doesn't match.
    @_optimize(speed)
    static func decodeDPI(
        encoding: UInt32, address: UInt64,
    ) -> DecodedDraft? {
        // Row: 1 op 0 10001 10 uimm6 (0)(0) uimm4 Rn Rd; bit 30 = op (0=ADDG, 1=SUBG).
        // Fixed opcode bits: bit[31]=1, bit[29]=0 (S), bits[28:24]=10001,
        // bits[23:22]=10. Bits[15:14] are SBZ "(0)(0)": the architectural
        // decode does not test them — a nonzero value is CONSTRAINED
        // UNPREDICTABLE but still decodes as ADDG/SUBG (matching llvm-mc) —
        // so they are NOT in the mask. The mask omits bit 30 (op = ADDG vs
        // SUBG) but checks every real opcode bit, so reserved encodings
        // (e.g. bit 29 = 1 or bit 22 = 1) are still rejected.
        if (encoding & 0xBFC0_0000) != 0x9180_0000 { return nil }
        let isSub = ((encoding >> 30) & 1) == 1
        let uimm6 = UInt8((encoding >> 16) & 0x3F)
        let uimm4 = UInt8((encoding >> 10) & 0xF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)
        // Rd / Rn are <Xd|SP> / <Xn|SP>.
        let rdRef = gprOperand(encoding: Rd, width: .x64, form: .spOrGeneral)
        let rnRef = gprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        let mnemonic: Mnemonic = isSub ? .subg : .addg
        let reads = insertingNonZero(reg: rnRef, into: .empty)
        let writes = insertingNonZero(reg: rdRef, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            flagEffect: .none, category: .memoryTagging,
            operands: [
                .register(rdRef), .register(rnRef),
                .unsignedImmediate(value: UInt64(uimm6) * 16, width: 10),
                .unsignedImmediate(value: UInt64(uimm4), width: 4),
            ],
        )
    }

    // MARK: - DPR tier (IRG / GMI / SUBP / SUBPS)

    /// IRG / GMI / SUBP / SUBPS in the DPR 2-source row. Returns nil if
    /// the opc6 is outside MTE's DPR subspace.
    @_optimize(speed)
    static func decodeDPR(
        encoding: UInt32, address: UInt64,
    ) -> DecodedDraft? {
        // Self-validate the DPR 2-source MTE row prefix:
        //   bit 31=1 (sf), bit 30=0, bits[28:21]=11010110.
        // bit 29 (S) is intentionally ignored — SUBPS has S=1, IRG/GMI/
        // SUBP have S=0; the opc6 dispatch downstream applies the S
        // requirement per mnemonic. bits[20:16] (opcode2/Rm) are not
        // pre-checked; opc6 alone identifies the MTE-DPR subspace.
        if (encoding & 0xDFE0_0000) != 0x9AC0_0000 { return nil }
        let S = (encoding >> 29) & 1
        let opc6 = UInt8((encoding >> 10) & 0x3F)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)
        switch opc6 {
        case 0b000000:
            // SUBP (S=0) / SUBPS (S=1). Rd: GPR. Rn / Rm: GPR-or-SP.
            let mnemonic: Mnemonic = (S == 1) ? .subps : .subp
            let rdRef = gprOperand(encoding: Rd, width: .x64, form: .zrOrGeneral)
            let rnRef = gprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
            let rmRef = gprOperand(encoding: Rm, width: .x64, form: .spOrGeneral)
            var reads = insertingNonZero(reg: rnRef, into: .empty)
            reads = insertingNonZero(reg: rmRef, into: reads)
            let writes = insertingNonZero(reg: rdRef, into: .empty)
            return DecodedDraft(
                address: address, encoding: encoding, mnemonic: mnemonic,
                semanticReads: reads, semanticWrites: writes,
                flagEffect: (S == 1) ? .nzcv : .none,
                category: .memoryTagging,
                operands: [.register(rdRef), .register(rnRef), .register(rmRef)],
            )

        case 0b000100:
            // IRG: Rd: GPR-or-SP. Rn: GPR-or-SP. Rm: GPR (Rm=XZR aliases to
            // the 2-operand form `irg Xd, Xn` — handled by the canonicalizer).
            if S != 0 { return nil }
            let rdRef = gprOperand(encoding: Rd, width: .x64, form: .spOrGeneral)
            let rnRef = gprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
            let rmRef = gprOperand(encoding: Rm, width: .x64, form: .zrOrGeneral)
            var reads = insertingNonZero(reg: rnRef, into: .empty)
            reads = insertingNonZero(reg: rmRef, into: reads)
            let writes = insertingNonZero(reg: rdRef, into: .empty)
            return DecodedDraft(
                address: address, encoding: encoding, mnemonic: .irg,
                semanticReads: reads, semanticWrites: writes,
                flagEffect: .none, category: .memoryTagging,
                operands: [.register(rdRef), .register(rnRef), .register(rmRef)],
            )

        case 0b000101:
            // GMI: Rd: GPR. Rn: GPR-or-SP. Rm: GPR.
            if S != 0 { return nil }
            let rdRef = gprOperand(encoding: Rd, width: .x64, form: .zrOrGeneral)
            let rnRef = gprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
            let rmRef = gprOperand(encoding: Rm, width: .x64, form: .zrOrGeneral)
            var reads = insertingNonZero(reg: rnRef, into: .empty)
            reads = insertingNonZero(reg: rmRef, into: reads)
            let writes = insertingNonZero(reg: rdRef, into: .empty)
            return DecodedDraft(
                address: address, encoding: encoding, mnemonic: .gmi,
                semanticReads: reads, semanticWrites: writes,
                flagEffect: .none, category: .memoryTagging,
                operands: [.register(rdRef), .register(rnRef), .register(rmRef)],
            )

        default:
            return nil
        }
    }

    // MARK: - L/S tier

    /// L/S MTE: LDG / STG / ST2G / STZG / STZ2G / LDGM / STGM / STZGM.
    /// Returns nil if (opc1, op2) is reserved.
    @_optimize(speed)
    static func decodeLS(
        encoding: UInt32, address: UInt64,
    ) -> DecodedDraft? {
        // Self-validate the L/S MTE row prefix: bits[31:24] = 0xD9
        // (bits[29:24] = 0b011001 with bits[31:30] = 11) AND bit 21 = 1.
        // The caller's bit-21 check is mirrored here so direct callers
        // can't slip non-MTE rows through.
        if (encoding & 0xFF20_0000) != 0xD920_0000 { return nil }
        // Dispatch table:
        //   opc1=00, op2=00 (imm9=0) → STZGM (bulk; no offset)
        //   opc1=00, op2 ∈ {01,10,11} → STG post / signed / pre
        //   opc1=01, op2=00 → LDG signed-offset (any simm9)
        //   opc1=01, op2 ∈ {01,10,11} → STZG post / signed / pre
        //   opc1=10, op2=00 (imm9=0) → STGM
        //   opc1=10, op2 ∈ {01,10,11} → ST2G post / signed / pre
        //   opc1=11, op2=00 (imm9=0) → LDGM
        //   opc1=11, op2 ∈ {01,10,11} → STZ2G post / signed / pre
        let opc1 = UInt8((encoding >> 22) & 0x3)
        let op2 = UInt8((encoding >> 10) & 0x3)
        let imm9 = (encoding >> 12) & 0x1FF
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        switch (opc1, op2) {
        case (0b00, 0b00):
            if imm9 != 0 { return nil }
            return bulkLSDraft(.stzgm, isLoad: false, Rn: Rn, Rt: Rt, encoding: encoding, address: address)
        case (0b10, 0b00):
            if imm9 != 0 { return nil }
            return bulkLSDraft(.stgm, isLoad: false, Rn: Rn, Rt: Rt, encoding: encoding, address: address)
        case (0b11, 0b00):
            if imm9 != 0 { return nil }
            return bulkLSDraft(.ldgm, isLoad: true, Rn: Rn, Rt: Rt, encoding: encoding, address: address)
        case (0b01, 0b00):
            // LDG signed-offset (any simm9).
            return addressFormDraft(
                mnemonic: .ldg, op2: op2, imm9: imm9, Rn: Rn, Rt: Rt,
                isLoad: true, rtIsSPAllowed: false,
                encoding: encoding, address: address,
            )
        case (0b00, 0b01), (0b00, 0b10), (0b00, 0b11):
            return addressFormDraft(
                mnemonic: .stg, op2: op2, imm9: imm9, Rn: Rn, Rt: Rt,
                isLoad: false, rtIsSPAllowed: true,
                encoding: encoding, address: address,
            )
        case (0b01, 0b01), (0b01, 0b10), (0b01, 0b11):
            return addressFormDraft(
                mnemonic: .stzg, op2: op2, imm9: imm9, Rn: Rn, Rt: Rt,
                isLoad: false, rtIsSPAllowed: true,
                encoding: encoding, address: address,
            )
        case (0b10, 0b01), (0b10, 0b10), (0b10, 0b11):
            return addressFormDraft(
                mnemonic: .st2g, op2: op2, imm9: imm9, Rn: Rn, Rt: Rt,
                isLoad: false, rtIsSPAllowed: true,
                encoding: encoding, address: address,
            )
        case (0b11, 0b01), (0b11, 0b10):
            return addressFormDraft(
                mnemonic: .stz2g, op2: op2, imm9: imm9, Rn: Rn, Rt: Rt,
                isLoad: false, rtIsSPAllowed: true,
                encoding: encoding, address: address,
            )
        default:
            // The 16 (opc1, op2) tuples are exhaustively enumerated by
            // the cases above. The only one folded into `default` is
            // (0b11, 0b11) — STZ2G pre-index — kept here so Swift's
            // tuple-of-UInt8 exhaustiveness checker doesn't require a
            // separate (unreachable) default arm.
            return addressFormDraft(
                mnemonic: .stz2g, op2: op2, imm9: imm9, Rn: Rn, Rt: Rt,
                isLoad: false, rtIsSPAllowed: true,
                encoding: encoding, address: address,
            )
        }
    }

    // MARK: - L/S draft builders

    @inline(__always)
    private static func bulkLSDraft(
        _ mnemonic: Mnemonic, isLoad: Bool, Rn: UInt8, Rt: UInt8,
        encoding: UInt32, address: UInt64,
    ) -> DecodedDraft {
        // LDGM/STGM/STZGM: Rt is GPR, Rn is GPR-or-SP. No offset, no
        // writeback. Memory operand is bare `[Xn|SP]`.
        let rtRef = gprOperand(encoding: Rt, width: .x64, form: .zrOrGeneral)
        let rnRef = gprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        let mem = MemoryOperand(base: .register(rnRef))
        var reads = insertingNonZero(reg: rnRef, into: .empty)
        var writes: RegisterSet = .empty
        if isLoad {
            writes = insertingNonZero(reg: rtRef, into: writes)
        } else {
            reads = insertingNonZero(reg: rtRef, into: reads)
        }
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            memoryAccess: isLoad ? .load : .store,
            flagEffect: .none, category: .memoryTagging,
            operands: [.register(rtRef), .memory(mem)],
        )
    }

    @inline(__always)
    private static func addressFormDraft(
        mnemonic: Mnemonic, op2: UInt8, imm9: UInt32, Rn: UInt8, Rt: UInt8,
        isLoad: Bool, rtIsSPAllowed: Bool,
        encoding: UInt32, address: UInt64,
    ) -> DecodedDraft {
        // op2 → addressing mode: 01=post, 10=signed-offset, 11=pre.
        let writebackKind: Writeback = switch op2 {
        case 0b01: .postIndex
        case 0b10: .none
        case 0b11: .preIndex
        default: .none
        }
        let displacementBytes = signExtend9(imm9) * 16
        let rtForm: RegisterEncodingForm = rtIsSPAllowed ? .spOrGeneral : .zrOrGeneral
        let rtRef = gprOperand(encoding: Rt, width: .x64, form: rtForm)
        let rnRef = gprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        let mem = MemoryOperand(
            base: .register(rnRef),
            displacement: displacementBytes,
            writeback: writebackKind,
        )
        var reads = insertingNonZero(reg: rnRef, into: .empty)
        var writes: RegisterSet = .empty
        if isLoad {
            writes = insertingNonZero(reg: rtRef, into: writes)
            if mnemonic == .ldg {
                // LDG is read-modify-write of Rt: the loaded tag is inserted
                // into Xt's tag field (ARM ARM `X[t]<59:56> = tag`), preserving
                // the other bits, so Rt is read as well as written. (LDGM
                // full-writes Rt and goes through bulkLSDraft, not here.)
                reads = insertingNonZero(reg: rtRef, into: reads)
            }
        } else {
            reads = insertingNonZero(reg: rtRef, into: reads)
        }
        // Pre/post-index writeback updates Rn.
        if writebackKind != .none {
            writes = insertingNonZero(reg: rnRef, into: writes)
        }
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            memoryAccess: isLoad ? .load : .store,
            flagEffect: .none, category: .memoryTagging,
            operands: [.register(rtRef), .memory(mem)],
        )
    }
}
