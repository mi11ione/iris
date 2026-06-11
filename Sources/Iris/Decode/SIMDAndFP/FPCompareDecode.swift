// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// FP compare per ARM ARM § C4.1.96.36.
// Encoding: `0 0 0 11110 ftype 1 Rm 001000 Rn opc 0 0 0 0 0`. opc bits
// [4:3] discriminate FCMP/FCMPE and reg-vs-zero form:
//   opc=00 FCMP  Vn, Vm        (Rm operand)
//   opc=01 FCMP  Vn, #0.0      (Rm must be 00000; operand is FP zero imm)
//   opc=10 FCMPE Vn, Vm
//   opc=11 FCMPE Vn, #0.0
// (bit[4] selects FCMPE; bit[3] selects the #0.0 zero form.)
//
// Flag-effect: .nzcv (writes all of NZCV).

enum FPCompareDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let ftype = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        // The opc field is bits[4:3]; bits[2:0] are fixed 000.
        if encoding & 0x07 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let opc = UInt8((encoding >> 3) & 0x3)

        guard let size = scalarSizeFromFtype(ftype) else {
            return .undefined(at: address, encoding: encoding)
        }

        // In the zero form, Rm is SBZ — a nonzero value is CONSTRAINED
        // UNPREDICTABLE, not UNDEFINED, and llvm-mc still decodes it as the
        // #0.0 form. So Rm is ignored here (not gated).
        let isZeroForm = (opc & 0b01) != 0
        let mnemonic: Mnemonic = (opc & 0b10) != 0 ? .fcmpe : .fcmp

        let vn = simdfpScalarOperand(Rn, size: size)
        let second: Operand
        var reads = simdfpInsertingVector(Rn, into: .empty)
        if isZeroForm {
            // size constrained to .h/.s/.d by scalarSizeFromFtype filter above.
            let kind: FloatImmediateKind = switch size {
            case .h: .half
            case .d: .double
            default: .single // size == .s (others impossible).
            }
            second = .floatImmediate(bits: 0, kind: kind)
        } else {
            second = simdfpScalarOperand(Rm, size: size)
            reads = simdfpInsertingVector(Rm, into: reads)
        }

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: .empty,
            branchClass: .none,
            memoryAccess: .none,
            memoryOrdering: [],
            flagEffect: .nzcv,
            category: .simdAndFP,
            operands: [vn, second],
        )
    }
}
