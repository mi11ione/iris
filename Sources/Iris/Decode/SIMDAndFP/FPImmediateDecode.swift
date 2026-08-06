// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum FPImmediateDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let ftype = UInt8((encoding >> 22) & 0x3)
        let imm8 = UInt8((encoding >> 13) & 0xFF)
        let imm5 = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        if imm5 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        guard let size = scalarSizeFromFtype(ftype) else {
            return .undefined(at: address, encoding: encoding)
        }

        let kind: FloatImmediateKind = switch size {
        case .h: .half
        case .d: .double
        default: .single
        }
        let bits = vfpExpandImm(imm8: imm8, kind: kind)

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .fmov,
            semanticReads: .empty,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none,
            memoryAccess: .none,
            memoryOrdering: [],
            flagEffect: .none,
            category: .simdAndFP,
            operandCount: sink.emit(simdfpScalarOperand(Rd, size: size), .floatImmediate(bits: bits, kind: kind)),
        )
    }
}

/// Implementation of the `VFPExpandImm` ARM pseudo-code for FMOV-imm and
/// vector FMOV-imm.
@_effects(readonly)
func vfpExpandImm(imm8: UInt8, kind: FloatImmediateKind) -> UInt64 {
    let sign = UInt64((imm8 >> 7) & 1)
    let abcdefgh = UInt64(imm8)
    let b = (abcdefgh >> 6) & 1
    let cde = (abcdefgh >> 4) & 0x7
    let efgh = abcdefgh & 0xF

    switch kind {
    case .half:
        let notB = (b ^ 1) & 1
        let exp = (notB << 4) | ((b == 0 ? 0 : 0b11) << 2) | UInt64(cde)
        let mantissa = efgh << 6
        return (sign << 15) | (exp << 10) | mantissa
    case .single:
        let notB = (b ^ 1) & 1
        let exp = (notB << 7) | ((b == 0 ? 0 : 0b11111) << 2) | UInt64(cde)
        let mantissa = efgh << 19
        return (sign << 31) | (exp << 23) | mantissa
    case .double:
        let notB = (b ^ 1) & 1
        let exp = (notB << 10) | ((b == 0 ? 0 : 0xFF) << 2) | UInt64(cde)
        let mantissa = efgh << 48
        return (sign << 63) | (exp << 52) | mantissa
    }
}
