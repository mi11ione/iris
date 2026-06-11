// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// FP immediate per ARM ARM § C4.1.96.37.
// Encoding: `0 0 0 11110 ftype 1 imm8 100 imm5 Rd`. `imm5` is
// architecturally fixed at 00000 (any other value is reserved). The
// 8-bit `imm8` field encodes an IEEE 754 immediate via a sign + 3-bit
// exponent + 4-bit mantissa packing (`VFPExpandImm`). The decoder
// expands to the full IEEE bit pattern at the destination precision
// and stores it as ``Operand/floatImmediate(bits:kind:)``.

enum FPImmediateDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let ftype = UInt8((encoding >> 22) & 0x3)
        let imm8 = UInt8((encoding >> 13) & 0xFF)
        let imm5 = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        // imm5 == 00000 is the only legal value at this class.
        if imm5 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        guard let size = scalarSizeFromFtype(ftype) else {
            return .undefined(at: address, encoding: encoding)
        }

        // size constrained to .h/.s/.d by scalarSizeFromFtype filter above.
        let kind: FloatImmediateKind = switch size {
        case .h: .half
        case .d: .double
        default: .single // size == .s (others impossible).
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
            operands: [
                simdfpScalarOperand(Rd, size: size),
                .floatImmediate(bits: bits, kind: kind),
            ],
        )
    }
}

/// Implementation of the `VFPExpandImm` ARM pseudo-code for FMOV-imm /
/// vector FMOV-imm immediate encoding. `imm8` packs:
///   - bit[7] = sign
///   - bits[6:4] = exponent (3 bits; biased by the destination format's
///     exponent bias minus 4)
///   - bits[3:0] = mantissa (4 bits, high-aligned into the destination's
///     mantissa width)
/// The expanded value is bias-adjusted, sign-extended into the
/// destination's bit pattern.
@_effects(readonly)
func vfpExpandImm(imm8: UInt8, kind: FloatImmediateKind) -> UInt64 {
    let sign = UInt64((imm8 >> 7) & 1)
    let abcdefgh = UInt64(imm8)
    // The packed bits: a=bit7 (sign), b=bit6, c=bit5, d=bit4 (exp top 3),
    // e=bit3, f=bit2, g=bit1, h=bit0 (mantissa).
    let b = (abcdefgh >> 6) & 1
    let cde = (abcdefgh >> 4) & 0x7
    let efgh = abcdefgh & 0xF

    switch kind {
    case .half:
        // Half: 1-bit sign, 5-bit exponent, 10-bit mantissa, exponent bias 15.
        // VFPExpandImm half: exp = NOT(b) : Replicate(b, 2) : cde; mant = efgh<<6.
        let notB = (b ^ 1) & 1
        let exp = (notB << 4) | ((b == 0 ? 0 : 0b11) << 2) | UInt64(cde)
        let mantissa = efgh << 6
        return (sign << 15) | (exp << 10) | mantissa
    case .single:
        // Single: 1-bit sign, 8-bit exponent, 23-bit mantissa, bias 127.
        // exp = NOT(b) : Replicate(b, 5) : cde; mant = efgh<<19.
        let notB = (b ^ 1) & 1
        let exp = (notB << 7) | ((b == 0 ? 0 : 0b11111) << 2) | UInt64(cde)
        let mantissa = efgh << 19
        return (sign << 31) | (exp << 23) | mantissa
    case .double:
        // Double: 1-bit sign, 11-bit exponent, 52-bit mantissa, bias 1023.
        // exp = NOT(b) : Replicate(b, 8) : cde; mant = efgh<<48.
        let notB = (b ^ 1) & 1
        let exp = (notB << 10) | ((b == 0 ? 0 : 0xFF) << 2) | UInt64(cde)
        let mantissa = efgh << 48
        return (sign << 63) | (exp << 52) | mantissa
    }
}
