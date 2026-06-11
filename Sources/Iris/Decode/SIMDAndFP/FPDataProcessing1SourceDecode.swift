// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// FP data-processing (1 source) per ARM ARM § C4.1.96.35.
// Encoding: `0 0 0 11110 ftype 1 00000 opcode 10000 Rn Rd`.
// Opcode at bits[20:15] selects FMOV/FABS/FNEG/FSQRT/FCVT precision /
// FRINT{N,P,M,Z,A,X,I} / FRINT32/64{X,Z} / BFCVT.
//
// FCVT precision (opcodes 0b000100..0b000111) sub-discriminates by
// (ftype, opc) where opc = bits[16:15] of the 6-bit opcode — the FCVT
// pages in ARM ARM list the (ftype source, opc destination) mapping.

enum FPDataProcessing1SourceDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let ftype = UInt8((encoding >> 22) & 0x3)
        // The 6-bit opcode is at bits[20:15]; bits[14:10] are fixed at 10000
        // by the caller's discriminator. bits[20:16] are 5 bits of opcode-
        // high; bit[15] is opcode-low.
        let opcode = UInt8((encoding >> 15) & 0x3F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        // BFCVT (S → BF16) sits at opcode 0b000110 which would otherwise
        // be matched by the FCVT-precision branch and rejected as
        // `opc == 10` reserved. Handle it explicitly first.
        if opcode == 0b000110 {
            // BFCVT's ftype field is fixed at 0b01 (the S→BF16 form); any
            // other ftype at this opcode is reserved.
            if ftype != 0b01 {
                return .undefined(at: address, encoding: encoding)
            }
            let vd = simdfpScalarOperand(Rd, size: .h)
            let vn = simdfpScalarOperand(Rn, size: .s)
            return draft(
                address: address, encoding: encoding,
                mnemonic: .bfcvt, Rd: Rd, Rn: Rn, vd: vd, vn: vn,
            )
        }

        // FCVT precision conversion: opcodes 0b000100..0b000111
        // (excluding 0b000110, handled as BFCVT above).
        if (opcode & 0b111100) == 0b000100 {
            return decodeFCVTPrecision(
                encoding: encoding, address: address,
                ftype: ftype, opc: opcode & 0b11, Rn: Rn, Rd: Rd,
            )
        }

        // The remaining opcodes pair (mnemonic, sameFtype-result):
        //   000000 FMOV      same precision
        //   000001 FABS      same
        //   000010 FNEG      same
        //   000011 FSQRT     same
        //   001000 FRINTN    same
        //   001001 FRINTP    same
        //   001010 FRINTM    same
        //   001011 FRINTZ    same
        //   001100 FRINTA    same
        //   001110 FRINTX    same
        //   001111 FRINTI    same
        //   010000 FRINT32Z  same (Armv8.5)
        //   010001 FRINT32X  same (Armv8.5)
        //   010010 FRINT64Z  same (Armv8.5)
        //   010011 FRINT64X  same (Armv8.5)
        //   000110 BFCVT     S→BF16 (ftype must be 00, dest implicit half)
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
        // 0b000110 (BFCVT) handled earlier; 0b000101, 0b000111, 0b001101
        // reserved; everything else reserved.
        default:
            return .undefined(at: address, encoding: encoding)
        }

        // FRINT32/64{Z,X} (FEAT_FRINTTS) operate on single/double only; the
        // half-precision (ftype=11) form is reserved.
        if ftype == 0b11,
           mnemonic == .frint32z || mnemonic == .frint32x
           || mnemonic == .frint64z || mnemonic == .frint64x
        {
            return .undefined(at: address, encoding: encoding)
        }

        // For FMOV/FABS/FNEG/FSQRT/FRINT*, source and destination share ftype.
        guard let size = scalarSizeFromFtype(ftype) else {
            return .undefined(at: address, encoding: encoding)
        }
        dstSize = size
        let vd = simdfpScalarOperand(Rd, size: dstSize)
        let vn = simdfpScalarOperand(Rn, size: dstSize)
        return draft(
            address: address, encoding: encoding,
            mnemonic: mnemonic, Rd: Rd, Rn: Rn, vd: vd, vn: vn,
        )
    }

    @inline(__always)
    @_effects(readonly)
    private static func draft(
        address: UInt64, encoding: UInt32, mnemonic: Mnemonic,
        Rd: UInt8, Rn: UInt8, vd: Operand, vn: Operand,
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
            operands: [vd, vn],
        )
    }

    /// FCVT precision sub-decoder. (ftype source, opc destination) mapping:
    ///   ftype=00 opc=01 S→D
    ///   ftype=00 opc=11 S→H
    ///   ftype=01 opc=00 D→S
    ///   ftype=01 opc=11 D→H
    ///   ftype=11 opc=00 H→S
    ///   ftype=11 opc=01 H→D
    /// Reserved: ftype==opc, ftype==10, opc==10.
    @inline(__always)
    @_optimize(speed)
    private static func decodeFCVTPrecision(
        encoding: UInt32, address: UInt64,
        ftype: UInt8, opc: UInt8, Rn: UInt8, Rd: UInt8,
    ) -> DecodedDraft {
        if ftype == opc { return .undefined(at: address, encoding: encoding) }
        if ftype == 0b10 || opc == 0b10 { return .undefined(at: address, encoding: encoding) }
        // After filtering, ftype and opc are both ∈ {0b00, 0b01, 0b11}.
        let srcSize = scalarSizeFromFtypeNonReserved(ftype)
        let dstSize = scalarSizeFromFtypeNonReserved(opc)
        let vd = simdfpScalarOperand(Rd, size: dstSize)
        let vn = simdfpScalarOperand(Rn, size: srcSize)
        return draft(
            address: address, encoding: encoding,
            mnemonic: .fcvt, Rd: Rd, Rn: Rn, vd: vd, vn: vn,
        )
    }
}
