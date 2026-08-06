// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum FPDataProcessing1SourceDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let ftype = UInt8((encoding >> 22) & 0x3)
        let opcode = UInt8((encoding >> 15) & 0x3F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        if opcode == 0b000110 {
            if ftype != 0b01 {
                return .undefined(at: address, encoding: encoding)
            }
            let vd = simdfpScalarOperand(Rd, size: .h)
            let vn = simdfpScalarOperand(Rn, size: .s)
            return draft(
                address: address, encoding: encoding,
                mnemonic: .bfcvt, Rd: Rd, Rn: Rn, vd: vd, vn: vn, &sink,
            )
        }

        if (opcode & 0b111100) == 0b000100 {
            return decodeFCVTPrecision(
                encoding: encoding, address: address,
                ftype: ftype, opc: opcode & 0b11, Rn: Rn, Rd: Rd, &sink,
            )
        }

        let mnemonic: Mnemonic
        let dstSize: ScalarSize
        switch opcode {
        case 0b000000: mnemonic = .fmov
        case 0b000001: mnemonic = .fabs
        case 0b000010: mnemonic = .fneg
        case 0b000011: mnemonic = .fsqrt
        case 0b001000: mnemonic = .frintn
        case 0b001001: mnemonic = .frintp
        case 0b001010: mnemonic = .frintm
        case 0b001011: mnemonic = .frintz
        case 0b001100: mnemonic = .frinta
        case 0b001110: mnemonic = .frintx
        case 0b001111: mnemonic = .frinti
        case 0b010000: mnemonic = .frint32z
        case 0b010001: mnemonic = .frint32x
        case 0b010010: mnemonic = .frint64z
        case 0b010011: mnemonic = .frint64x
        default:
            return .undefined(at: address, encoding: encoding)
        }

        if ftype == 0b11,
           mnemonic == .frint32z || mnemonic == .frint32x
           || mnemonic == .frint64z || mnemonic == .frint64x
        {
            return .undefined(at: address, encoding: encoding)
        }

        guard let size = scalarSizeFromFtype(ftype) else {
            return .undefined(at: address, encoding: encoding)
        }
        dstSize = size
        let vd = simdfpScalarOperand(Rd, size: dstSize)
        let vn = simdfpScalarOperand(Rn, size: dstSize)
        return draft(
            address: address, encoding: encoding,
            mnemonic: mnemonic, Rd: Rd, Rn: Rn, vd: vd, vn: vn, &sink,
        )
    }

    @inline(__always)
    @_effects(readonly)
    private static func draft(
        address: UInt64, encoding: UInt32, mnemonic: Mnemonic,
        Rd: UInt8, Rn: UInt8, vd: Operand, vn: Operand, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: simdfpInsertingVector(Rn, into: .empty),
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none,
            memoryAccess: .none,
            memoryOrdering: [],
            flagEffect: .none,
            category: .simdAndFP,
            operandCount: sink.emit(vd, vn),
        )
    }

    /// FCVT precision sub-decoder, mapping (ftype source, opc destination).
    @inline(__always)
    @_optimize(speed)
    private static func decodeFCVTPrecision(
        encoding: UInt32, address: UInt64,
        ftype: UInt8, opc: UInt8, Rn: UInt8, Rd: UInt8, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        if ftype == opc { return .undefined(at: address, encoding: encoding) }
        if ftype == 0b10 || opc == 0b10 { return .undefined(at: address, encoding: encoding) }
        let srcSize = scalarSizeFromFtypeNonReserved(ftype)
        let dstSize = scalarSizeFromFtypeNonReserved(opc)
        let vd = simdfpScalarOperand(Rd, size: dstSize)
        let vn = simdfpScalarOperand(Rn, size: srcSize)
        return draft(
            address: address, encoding: encoding,
            mnemonic: .fcvt, Rd: Rd, Rn: Rn, vd: vd, vn: vn, &sink,
        )
    }
}
