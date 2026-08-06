// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Crypto extension (AES / SHA / SM3 / SM4) decoder.
enum CryptoExtensionDecode {
    /// Decode the encoding if it matches any AES / SHA-1 / SHA-256 / SHA-3 /
    /// SHA-512 / SM3 / SM4 row.
    @_optimize(speed)
    static func decode(
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft? {
        let prefix = UInt8((encoding >> 24) & 0xFF)
        switch prefix {
        case 0x4E: return decodeAES(encoding: encoding, address: address, &sink)
        case 0x5E: return decodeSHA1And256(encoding: encoding, address: address, &sink)
        case 0xCE: return decodeSHA3SHA512SM3SM4(encoding: encoding, address: address, &sink)
        default: return nil
        }
    }

    @inline(__always)
    @_optimize(speed)
    private static func decodeAES(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft? {
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
            flagEffect: .none, category: .crypto, operandCount: sink.emit(vd, vn),
        )
    }

    @inline(__always)
    @_optimize(speed)
    private static func decodeSHA1And256(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft? {
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
                    operandCount: sink.emit(qd, sn, vmVec),
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
                    operandCount: sink.emit(vd, vn, vmVec),
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
                    operandCount: sink.emit(qd, qn, vmVec),
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
                    operandCount: sink.emit(vd, vn, vmVec),
                )
            default: return nil
            }
        }
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
                    operandCount: sink.emit(sd, sn),
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
                    operandCount: sink.emit(vd, vn),
                )
            default: return nil
            }
        }
        return nil
    }

    @inline(__always)
    @_optimize(speed)
    private static func decodeSHA3SHA512SM3SM4(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft? {
        let bits24_21 = UInt8((encoding >> 21) & 0xF)
        switch bits24_21 {
        case 0b0000, 0b0001:
            return decodeSHA3FourReg(encoding: encoding, address: address, &sink)
        case 0b0010:
            let bit15 = (encoding >> 15) & 1
            if bit15 == 0 {
                return decodeSM3SS1(encoding: encoding, address: address, &sink)
            }
            return decodeSM3TT(encoding: encoding, address: address, &sink)
        case 0b0011:
            return decodeThreeRegSHA512SM(encoding: encoding, address: address, &sink)
        case 0b0100:
            return decodeXAR(encoding: encoding, address: address, &sink)
        case 0b0110:
            return decodeTwoRegSHA512SM4E(encoding: encoding, address: address, &sink)
        default:
            return nil
        }
    }

    @inline(__always)
    private static func decodeSHA3FourReg(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft? {
        if (encoding & 0xFF80_8000) != 0xCE00_0000 { return nil }
        let op0_2 = UInt8((encoding >> 21) & 0x3)
        let mnemonic: Mnemonic = switch op0_2 {
        case 0b00: .eor3
        default:
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
            operandCount: sink.emit(vd, vn, vm, va),
        )
    }

    @inline(__always)
    private static func decodeSM3SS1(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
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
            operandCount: sink.emit(vd, vn, vm, va),
        )
    }

    @inline(__always)
    private static func decodeSM3TT(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft? {
        if (encoding & 0xFFE0_C000) != 0xCE40_8000 { return nil }
        let imm2 = UInt8((encoding >> 12) & 0x3)
        let op1 = UInt8((encoding >> 10) & 0x3)
        let mnemonic: Mnemonic = switch op1 {
        case 0b00: .sm3tt1a
        case 0b01: .sm3tt1b
        case 0b10: .sm3tt2a
        default:
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
            operandCount: sink.emit(vd, vn, vmElement),
        )
    }

    @inline(__always)
    private static func decodeThreeRegSHA512SM(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft? {
        if (encoding & 0xFFE0_B000) != 0xCE60_8000 { return nil }
        let op0 = UInt8((encoding >> 14) & 0x1)
        let op1 = UInt8((encoding >> 10) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)
        let mnemonic: Mnemonic
        let arrangement: VectorArrangement
        let isQTied: Bool
        let isVTied: Bool
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
            operandCount: sink.emit(vd, vn, vmVec),
        )
    }

    @inline(__always)
    private static func decodeXAR(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
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
            operandCount: sink.emit(vd, vn, vm, .unsignedImmediate(value: UInt64(imm6), width: 6)),
        )
    }

    @inline(__always)
    private static func decodeTwoRegSHA512SM4E(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft? {
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
        reads = simdfpInsertingVector(Rd, into: reads)
        let writes = simdfpInsertingVector(Rd, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            flagEffect: .none, category: .crypto,
            operandCount: sink.emit(vd, vn),
        )
    }
}
