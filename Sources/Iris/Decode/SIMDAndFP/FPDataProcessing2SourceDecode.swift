// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// FP data-processing (2 source) per ARM ARM § C4.1.96.39.
// Encoding: `0 0 0 11110 ftype 1 Rm opcode 10 Rn Rd`.
// Opcode (bits[15:12]) selects FMUL/FDIV/FADD/FSUB/FMAX/FMIN/FMAXNM/
// FMINNM/FNMUL. ftype selects S/D/H precision; H requires FEAT_FP16 at
// runtime but the decoder produces the H-form regardless (the decoder is
// feature-flag-agnostic).

enum FPDataProcessing2SourceDecode {
    /// Discriminator for this sub-class: bits[31:24] == 0b00011110 AND
    /// bits[21] == 1 AND bits[11:10] == 0b10. The caller (the top-level
    /// SIMD/FP dispatcher) routes here when those bits match.
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let ftype = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let opcode = UInt8((encoding >> 12) & 0xF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        // ftype=10 is reserved at this class (the X↔V.D[1] FMOV variants
        // use ftype=10 in the integer-conversion class, not here).
        guard let size = scalarSizeFromFtype(ftype) else {
            return .undefined(at: address, encoding: encoding)
        }

        // Opcode mapping per ARM ARM § C7.2 FxOp tables.
        let mnemonic: Mnemonic
        switch opcode {
        case 0b0000: mnemonic = .fmul
        case 0b0001: mnemonic = .fdiv
        case 0b0010: mnemonic = .fadd
        case 0b0011: mnemonic = .fsub
        case 0b0100: mnemonic = .fmax
        case 0b0101: mnemonic = .fmin
        case 0b0110: mnemonic = .fmaxnm
        case 0b0111: mnemonic = .fminnm
        case 0b1000: mnemonic = .fnmul
        // 0b1001..0b1111 reserved.
        default: return .undefined(at: address, encoding: encoding)
        }

        let vd = simdfpScalarOperand(Rd, size: size)
        let vn = simdfpScalarOperand(Rn, size: size)
        let vm = simdfpScalarOperand(Rm, size: size)

        let writes = simdfpInsertingVector(Rd, into: .empty)
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(Rm, into: reads)

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: writes,
            branchClass: .none,
            memoryAccess: .none,
            memoryOrdering: [],
            flagEffect: .none,
            category: .simdAndFP,
            operands: [vd, vn, vm],
        )
    }
}
