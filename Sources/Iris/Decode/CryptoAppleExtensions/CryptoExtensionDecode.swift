// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Crypto-extension decoder. Decodes AES / SHA-1 / SHA-256 / SHA-3
// (EOR3, RAX1, XAR, BCAX) / SHA-512 / SM3 (SS1, TT1A/B/2A/B, PARTW1/2) /
// SM4 (E, EKEY). Invoked by SIMDAndFPDecoder on the deferred-crypto
// branches: returns a fully-formed draft if the encoding matches a
// crypto row, nil otherwise (caller falls through to UNDEFINED).

/// Crypto extension (AES / SHA / SM3 / SM4) decoder. Public so
/// corpus tooling can route encodings via the same code path the
/// runtime decoder uses.
enum CryptoExtensionDecode {
    /// Decode the encoding if it matches any AES / SHA-1 / SHA-256 /
    /// SHA-3 / SHA-512 / SM3 / SM4 row. Returns nil for non-crypto
    /// encodings; callers fall through to UNDEFINED.
    @_optimize(speed)
    static func decode(
        encoding: UInt32, address: UInt64,
    ) -> DecodedDraft? {
        let prefix = UInt8((encoding >> 24) & 0xFF)
        switch prefix {
        case 0x4E: return decodeAES(encoding: encoding, address: address)
        case 0x5E: return decodeSHA1And256(encoding: encoding, address: address)
        case 0xCE: return decodeSHA3SHA512SM3SM4(encoding: encoding, address: address)
        default: return nil
        }
    }

    // MARK: - AES

    @inline(__always)
    @_optimize(speed)
    private static func decodeAES(encoding: UInt32, address: UInt64) -> DecodedDraft? {
        // 0100 1110 0010 1000 0 opcode4 10 Rn Rd; opcode in bits[15:12].
        // Fixed bits: [31:16] = 0100 1110 0010 1000 (= 0x4E28); [11:10] = 10.
        // (Bit 16 is part of the fixed prefix per LLVM AESBase, not part of
        // the opcode field — opcode lives in bits[15:12].)
        if (encoding & 0xFFFF_0C00) != 0x4E28_0800 { return nil }
        let opcode = UInt8((encoding >> 12) & 0xF)
        let mnemonic: Mnemonic
        let isTied: Bool
        switch opcode {
        case 0b0100: mnemonic = .aese; isTied = true
        case 0b0101: mnemonic = .aesd; isTied = true
        case 0b0110: mnemonic = .aesmc; isTied = false
        case 0b0111: mnemonic = .aesimc; isTied = false
        default: return nil
        }
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)
        let vd = simdfpVectorOperand(Rd, arrangement: .b16)
        let vn = simdfpVectorOperand(Rn, arrangement: .b16)
        var reads = simdfpInsertingVector(Rn, into: .empty)
        if isTied { reads = simdfpInsertingVector(Rd, into: reads) }
        let writes = simdfpInsertingVector(Rd, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            flagEffect: .none, category: .crypto, operands: [vd, vn],
        )
    }

    // MARK: - SHA-1 and SHA-256

    @inline(__always)
    @_optimize(speed)
    private static func decodeSHA1And256(encoding: UInt32, address: UInt64) -> DecodedDraft? {
        // Three-register form: 0101 1110 000 Rm 0 op3 00 Rn Rd  (op3 = bits[14:12]).
        //   op3 = 000 → SHA1C  (Qd r/w, Sn, Vm.4S)
        //   op3 = 001 → SHA1P
        //   op3 = 010 → SHA1M
        //   op3 = 011 → SHA1SU0 (Vd.4S r/w, Vn.4S, Vm.4S)
        //   op3 = 100 → SHA256H  (Qd r/w, Qn, Vm.4S)
        //   op3 = 101 → SHA256H2
        //   op3 = 110 → SHA256SU1 (Vd.4S r/w, Vn.4S, Vm.4S)
        // Fixed: [31:21] = 0101 1110 000; bit[15]=0; bits[11:10]=00.
        if (encoding & 0xFFE0_8C00) == 0x5E00_0000 {
            let op3 = UInt8((encoding >> 12) & 0x7)
            let Rm = UInt8((encoding >> 16) & 0x1F)
            let Rn = UInt8((encoding >> 5) & 0x1F)
            let Rd = UInt8(encoding & 0x1F)
            let vmVec = simdfpVectorOperand(Rm, arrangement: .s4)
            switch op3 {
            case 0b000, 0b001, 0b010:
                let mnemonic: Mnemonic = (op3 == 0) ? .sha1c : (op3 == 1 ? .sha1p : .sha1m)
                let qd = simdfpScalarOperand(Rd, size: .q)
                let sn = simdfpScalarOperand(Rn, size: .s)
                var reads = simdfpInsertingVector(Rd, into: .empty)
                reads = simdfpInsertingVector(Rn, into: reads)
                reads = simdfpInsertingVector(Rm, into: reads)
                let writes = simdfpInsertingVector(Rd, into: .empty)
                return DecodedDraft(
                    address: address, encoding: encoding, mnemonic: mnemonic,
                    semanticReads: reads, semanticWrites: writes,
                    flagEffect: .none, category: .crypto,
                    operands: [qd, sn, vmVec],
                )
            case 0b011:
                let vd = simdfpVectorOperand(Rd, arrangement: .s4)
                let vn = simdfpVectorOperand(Rn, arrangement: .s4)
                var reads = simdfpInsertingVector(Rd, into: .empty)
                reads = simdfpInsertingVector(Rn, into: reads)
                reads = simdfpInsertingVector(Rm, into: reads)
                let writes = simdfpInsertingVector(Rd, into: .empty)
                return DecodedDraft(
                    address: address, encoding: encoding, mnemonic: .sha1su0,
                    semanticReads: reads, semanticWrites: writes,
                    flagEffect: .none, category: .crypto,
                    operands: [vd, vn, vmVec],
                )
            case 0b100, 0b101:
                let mnemonic: Mnemonic = (op3 == 0b100) ? .sha256h : .sha256h2
                let qd = simdfpScalarOperand(Rd, size: .q)
                let qn = simdfpScalarOperand(Rn, size: .q)
                var reads = simdfpInsertingVector(Rd, into: .empty)
                reads = simdfpInsertingVector(Rn, into: reads)
                reads = simdfpInsertingVector(Rm, into: reads)
                let writes = simdfpInsertingVector(Rd, into: .empty)
                return DecodedDraft(
                    address: address, encoding: encoding, mnemonic: mnemonic,
                    semanticReads: reads, semanticWrites: writes,
                    flagEffect: .none, category: .crypto,
                    operands: [qd, qn, vmVec],
                )
            case 0b110:
                let vd = simdfpVectorOperand(Rd, arrangement: .s4)
                let vn = simdfpVectorOperand(Rn, arrangement: .s4)
                var reads = simdfpInsertingVector(Rd, into: .empty)
                reads = simdfpInsertingVector(Rn, into: reads)
                reads = simdfpInsertingVector(Rm, into: reads)
                let writes = simdfpInsertingVector(Rd, into: .empty)
                return DecodedDraft(
                    address: address, encoding: encoding, mnemonic: .sha256su1,
                    semanticReads: reads, semanticWrites: writes,
                    flagEffect: .none, category: .crypto,
                    operands: [vd, vn, vmVec],
                )
            default: return nil
            }
        }
        // Two-register form: 0101 1110 0010 1000 0 op4 10 Rn Rd  (op4 = bits[14:12]).
        //   op4 = 0000 → SHA1H    (Sd, Sn — scalar S)
        //   op4 = 0001 → SHA1SU1  (Vd.4S r/w, Vn.4S)
        //   op4 = 0010 → SHA256SU0 (Vd.4S r/w, Vn.4S)
        if (encoding & 0xFFFF_8C00) == 0x5E28_0800 {
            let op4 = UInt8((encoding >> 12) & 0xF)
            let Rn = UInt8((encoding >> 5) & 0x1F)
            let Rd = UInt8(encoding & 0x1F)
            switch op4 {
            case 0b0000:
                let sd = simdfpScalarOperand(Rd, size: .s)
                let sn = simdfpScalarOperand(Rn, size: .s)
                let reads = simdfpInsertingVector(Rn, into: .empty)
                let writes = simdfpInsertingVector(Rd, into: .empty)
                return DecodedDraft(
                    address: address, encoding: encoding, mnemonic: .sha1h,
                    semanticReads: reads, semanticWrites: writes,
                    flagEffect: .none, category: .crypto,
                    operands: [sd, sn],
                )
            case 0b0001, 0b0010:
                let mnemonic: Mnemonic = (op4 == 0b0001) ? .sha1su1 : .sha256su0
                let vd = simdfpVectorOperand(Rd, arrangement: .s4)
                let vn = simdfpVectorOperand(Rn, arrangement: .s4)
                var reads = simdfpInsertingVector(Rd, into: .empty)
                reads = simdfpInsertingVector(Rn, into: reads)
                let writes = simdfpInsertingVector(Rd, into: .empty)
                return DecodedDraft(
                    address: address, encoding: encoding, mnemonic: mnemonic,
                    semanticReads: reads, semanticWrites: writes,
                    flagEffect: .none, category: .crypto,
                    operands: [vd, vn],
                )
            default: return nil
            }
        }
        return nil
    }

    // MARK: - SHA-3 / SHA-512 / SM3 / SM4 (0xCE prefix)

    @inline(__always)
    @_optimize(speed)
    private static func decodeSHA3SHA512SM3SM4(encoding: UInt32, address: UInt64) -> DecodedDraft? {
        // Sub-discriminate by bits[24:21]:
        //   0000 / 0001 → 4-register SHA-3 (EOR3 / BCAX) at bits[15]=0
        //   0010        → SM3SS1 4-reg (bits[15]=0) OR SM3TT 3-reg+imm2 (bits[15]=1)
        //   0011        → 3-register SHA-512/SM3/SM4
        //   0100        → XAR (Vd.2D, Vn.2D, Vm.2D, #imm6)
        //   0110        → 2-register SHA512SU0 / SM4E
        let bits24_21 = UInt8((encoding >> 21) & 0xF)
        switch bits24_21 {
        case 0b0000, 0b0001:
            return decodeSHA3FourReg(encoding: encoding, address: address)
        case 0b0010:
            // SM3SS1 (bits[15]=0) vs SM3TT (bits[15]=1).
            let bit15 = (encoding >> 15) & 1
            if bit15 == 0 {
                return decodeSM3SS1(encoding: encoding, address: address)
            }
            // bit15 = 1 → SM3TT family below (3-reg + imm2 form).
            return decodeSM3TT(encoding: encoding, address: address)
        case 0b0011:
            return decodeThreeRegSHA512SM(encoding: encoding, address: address)
        case 0b0100:
            return decodeXAR(encoding: encoding, address: address)
        case 0b0110:
            return decodeTwoRegSHA512SM4E(encoding: encoding, address: address)
        default:
            return nil
        }
    }

    @inline(__always)
    private static func decodeSHA3FourReg(encoding: UInt32, address: UInt64) -> DecodedDraft? {
        // 1100 1110 00 op0_2 Rm 0 Va Rn Rd; op0_2 selects EOR3 (00) / BCAX (01).
        // Fixed: [31:23] = 1100 1110 0; bit[15] = 0.
        if (encoding & 0xFF80_8000) != 0xCE00_0000 { return nil }
        let op0_2 = UInt8((encoding >> 21) & 0x3)
        let mnemonic: Mnemonic = switch op0_2 {
        case 0b00: .eor3
        default:
            // Caller (decodeSHA3SHA512SM3SM4) only routes bits[24:21] ∈
            // {0b0000, 0b0001} here, so bits[22:21] = op0_2 ∈ {0b00, 0b01};
            // 0b10 and 0b11 are structurally unreachable, leaving only
            // 0b01 → BCAX in the default arm.
            .bcax
        }
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let Ra = UInt8((encoding >> 10) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)
        let vd = simdfpVectorOperand(Rd, arrangement: .b16)
        let vn = simdfpVectorOperand(Rn, arrangement: .b16)
        let vm = simdfpVectorOperand(Rm, arrangement: .b16)
        let va = simdfpVectorOperand(Ra, arrangement: .b16)
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(Rm, into: reads)
        reads = simdfpInsertingVector(Ra, into: reads)
        let writes = simdfpInsertingVector(Rd, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            flagEffect: .none, category: .crypto,
            operands: [vd, vn, vm, va],
        )
    }

    @inline(__always)
    private static func decodeSM3SS1(encoding: UInt32, address: UInt64) -> DecodedDraft {
        // 1100 1110 010 Rm 0 Ra Rn Rd; operands Vd.4S, Vn.4S, Vm.4S, Va.4S.
        // Caller (decodeSHA3SHA512SM3SM4) routes via bits[24:21]=0b0010 AND
        // bit 15 = 0, which together fully determine the row prefix —
        // no inner prefix check needed.
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let Ra = UInt8((encoding >> 10) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)
        let vd = simdfpVectorOperand(Rd, arrangement: .s4)
        let vn = simdfpVectorOperand(Rn, arrangement: .s4)
        let vm = simdfpVectorOperand(Rm, arrangement: .s4)
        let va = simdfpVectorOperand(Ra, arrangement: .s4)
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(Rm, into: reads)
        reads = simdfpInsertingVector(Ra, into: reads)
        let writes = simdfpInsertingVector(Rd, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: .sm3ss1,
            semanticReads: reads, semanticWrites: writes,
            flagEffect: .none, category: .crypto,
            operands: [vd, vn, vm, va],
        )
    }

    @inline(__always)
    private static func decodeSM3TT(encoding: UInt32, address: UInt64) -> DecodedDraft? {
        // 1100 1110 010 Rm 1 0 imm2 op1 Rn Rd; op1 selects 1A/1B/2A/2B.
        // Fixed: [31:21] = 1100 1110 010; bits[15:14] = 10.
        if (encoding & 0xFFE0_C000) != 0xCE40_8000 { return nil }
        let imm2 = UInt8((encoding >> 12) & 0x3)
        let op1 = UInt8((encoding >> 10) & 0x3)
        let mnemonic: Mnemonic = switch op1 {
        case 0b00: .sm3tt1a
        case 0b01: .sm3tt1b
        case 0b10: .sm3tt2a
        default:
            // op1 is a 2-bit value; the only remaining case is 0b11.
            .sm3tt2b
        }
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)
        let vd = simdfpVectorOperand(Rd, arrangement: .s4)
        let vn = simdfpVectorOperand(Rn, arrangement: .s4)
        let vmElement = simdfpElementOperand(Rm, elementSize: .s, index: imm2)
        var reads = simdfpInsertingVector(Rd, into: .empty)
        reads = simdfpInsertingVector(Rn, into: reads)
        reads = simdfpInsertingVector(Rm, into: reads)
        let writes = simdfpInsertingVector(Rd, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            flagEffect: .none, category: .crypto,
            operands: [vd, vn, vmElement],
        )
    }

    @inline(__always)
    private static func decodeThreeRegSHA512SM(encoding: UInt32, address: UInt64) -> DecodedDraft? {
        // 1100 1110 011 Rm 1 op0 00 op1 Rn Rd; bits[15:10] select.
        // Fixed: [31:21] = 1100 1110 011; bits[15] = 1; bits[13:12] = 00.
        if (encoding & 0xFFE0_B000) != 0xCE60_8000 { return nil }
        let op0 = UInt8((encoding >> 14) & 0x1)
        let op1 = UInt8((encoding >> 10) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)
        let mnemonic: Mnemonic
        let arrangement: VectorArrangement
        let isQTied: Bool // Qd-tied (true for SHA512H/H2)
        let isVTied: Bool // Vd-tied (true for SHA512SU1)
        switch (op0, op1) {
        case (0, 0b00): mnemonic = .sha512h; arrangement = .d2; isQTied = true; isVTied = false
        case (0, 0b01): mnemonic = .sha512h2; arrangement = .d2; isQTied = true; isVTied = false
        case (0, 0b10): mnemonic = .sha512su1; arrangement = .d2; isQTied = false; isVTied = true
        case (0, 0b11): mnemonic = .rax1; arrangement = .d2; isQTied = false; isVTied = false
        case (1, 0b00): mnemonic = .sm3partw1; arrangement = .s4; isQTied = false; isVTied = true
        case (1, 0b01): mnemonic = .sm3partw2; arrangement = .s4; isQTied = false; isVTied = true
        case (1, 0b10): mnemonic = .sm4ekey; arrangement = .s4; isQTied = false; isVTied = false
        default: return nil
        }
        let vmVec = simdfpVectorOperand(Rm, arrangement: arrangement)
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(Rm, into: reads)
        if isQTied || isVTied { reads = simdfpInsertingVector(Rd, into: reads) }
        let writes = simdfpInsertingVector(Rd, into: .empty)
        let vd: Operand
        let vn: Operand
        if isQTied {
            vd = simdfpScalarOperand(Rd, size: .q)
            vn = simdfpScalarOperand(Rn, size: .q)
        } else {
            vd = simdfpVectorOperand(Rd, arrangement: arrangement)
            vn = simdfpVectorOperand(Rn, arrangement: arrangement)
        }
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            flagEffect: .none, category: .crypto,
            operands: [vd, vn, vmVec],
        )
    }

    @inline(__always)
    private static func decodeXAR(encoding: UInt32, address: UInt64) -> DecodedDraft {
        // 1100 1110 100 Rm imm6 Rn Rd; operands Vd.2D, Vn.2D, Vm.2D, #imm6.
        // Caller (decodeSHA3SHA512SM3SM4) routes via bits[24:21]=0b0100,
        // which combined with the caller-guaranteed top byte 0xCE fully
        // determines the row prefix — no inner prefix check needed.
        let imm6 = UInt8((encoding >> 10) & 0x3F)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)
        let vd = simdfpVectorOperand(Rd, arrangement: .d2)
        let vn = simdfpVectorOperand(Rn, arrangement: .d2)
        let vm = simdfpVectorOperand(Rm, arrangement: .d2)
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(Rm, into: reads)
        let writes = simdfpInsertingVector(Rd, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: .xar,
            semanticReads: reads, semanticWrites: writes,
            flagEffect: .none, category: .crypto,
            operands: [vd, vn, vm, .unsignedImmediate(value: UInt64(imm6), width: 6)],
        )
    }

    @inline(__always)
    private static func decodeTwoRegSHA512SM4E(encoding: UInt32, address: UInt64) -> DecodedDraft? {
        // 1100 1110 110 00000 100 0 op1 Rn Rd; op1 selects SHA512SU0 (00) / SM4E (01).
        // Fixed: [31:21] = 1100 1110 110; [20:14] = 0000 010 0; [12] = 0.
        if (encoding & 0xFFFF_F000) != 0xCEC0_8000 { return nil }
        let op1 = UInt8((encoding >> 10) & 0x3)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)
        let mnemonic: Mnemonic
        let arrangement: VectorArrangement
        switch op1 {
        case 0b00: mnemonic = .sha512su0; arrangement = .d2
        case 0b01: mnemonic = .sm4e; arrangement = .s4
        default: return nil
        }
        let vd = simdfpVectorOperand(Rd, arrangement: arrangement)
        let vn = simdfpVectorOperand(Rn, arrangement: arrangement)
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(Rd, into: reads) // Vd-tied
        let writes = simdfpInsertingVector(Rd, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            flagEffect: .none, category: .crypto,
            operands: [vd, vn],
        )
    }
}
