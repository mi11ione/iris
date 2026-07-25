// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// predicated FP binary arithmetic: G1 register form
// (`sve_fp_2op_p_zds` — FADD…FDIV, FABD, FAMIN/FAMAX, FSCALE, FMULX, and the
// B16B16 bf16 twins occupying the sz=00 slots), G2 immediate form
// (`sve_fp_2op_i_p_zds` — the two-constant `#0.5/#1.0/#2.0/#0.0` family),
// and G16 pairwise (`sve2_fp_pairwise_pred`). All are destructive
// `<Zdn>, <Pg>/m, <Zdn>, <Zm|#const>` with the second source at bits[9:5]
// and the operation selector at bits[19:16] (register/pairwise) or
// bits[18:16] (immediate). Merging predication: destination read +
// `partialWrite`.

extension SVEFloatingPointDecode {
    // MARK: G1 — predicated binary register (0x65, bits[15:13]=100, bits[20:19]=0x)

    @inline(__always)
    static func decodePredicatedBinary(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let sz = (e >> 22) & 0b11
        let opc = (e >> 16) & 0xF
        let mnemonic: Mnemonic
        var size: ScalarSize = .h
        if sz == 0b00 {
            // The bf16 (B16B16 / BFSCALE) twins own these sz=00 slots; the
            // rest are architectural holes.
            switch opc {
            case 0b0000: mnemonic = .bfadd
            case 0b0001: mnemonic = .bfsub
            case 0b0010: mnemonic = .bfmul
            case 0b0100: mnemonic = .bfmaxnm
            case 0b0101: mnemonic = .bfminnm
            case 0b0110: mnemonic = .bfmax
            case 0b0111: mnemonic = .bfmin
            case 0b1001: mnemonic = .bfscale
            default: return undefined(e, a)
            }
        } else {
            size = elementSize(sz)
            switch opc {
            case 0b0000: mnemonic = .fadd
            case 0b0001: mnemonic = .fsub
            case 0b0010: mnemonic = .fmul
            case 0b0011: mnemonic = .fsubr
            case 0b0100: mnemonic = .fmaxnm
            case 0b0101: mnemonic = .fminnm
            case 0b0110: mnemonic = .fmax
            case 0b0111: mnemonic = .fmin
            case 0b1000: mnemonic = .fabd
            case 0b1001: mnemonic = .fscale
            case 0b1010: mnemonic = .fmulx
            case 0b1100: mnemonic = .fdivr
            case 0b1101: mnemonic = .fdiv
            case 0b1110: mnemonic = .famax
            case 0b1111: mnemonic = .famin
            default: return undefined(e, a) // opc 1011 — hole
            }
        }
        let dn = zd(e), m = zn(e), g = pg3(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(dn).union(vecMask(m)),
            semanticWrites: vecMask(dn), category: .sve,
            operands: [vec(dn, size), govern(g, .merging), vec(dn, size), vec(m, size)],
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    // MARK: G2 — arith immediate (0x65, bits[15:13]=100, bits[20:19]=11)

    @inline(__always)
    static func decodeArithImmediate(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // bits[9:6] are a fixed zero field in this class.
        if (e >> 6) & 0xF != 0 { return undefined(e, a) }
        guard let size = fpSize(e) else { return undefined(e, a) }
        let i1 = (e >> 5) & 1
        let mnemonic: Mnemonic
        let value: Double
        switch (e >> 16) & 0b111 {
        case 0b000: mnemonic = .fadd; value = i1 == 0 ? 0.5 : 1.0
        case 0b001: mnemonic = .fsub; value = i1 == 0 ? 0.5 : 1.0
        case 0b010: mnemonic = .fmul; value = i1 == 0 ? 0.5 : 2.0
        case 0b011: mnemonic = .fsubr; value = i1 == 0 ? 0.5 : 1.0
        case 0b100: mnemonic = .fmaxnm; value = i1 == 0 ? 0.0 : 1.0
        case 0b101: mnemonic = .fminnm; value = i1 == 0 ? 0.0 : 1.0
        case 0b110: mnemonic = .fmax; value = i1 == 0 ? 0.0 : 1.0
        default: mnemonic = .fmin; value = i1 == 0 ? 0.0 : 1.0
        }
        let dn = zd(e), g = pg3(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(dn),
            semanticWrites: vecMask(dn), category: .sve,
            operands: [
                vec(dn, size), govern(g, .merging), vec(dn, size),
                exactImmediate(value, size),
            ],
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    /// The exact-constant FP immediate of the arith-immediate family, carried
    /// as the IEEE bit pattern of the constant at the element precision.
    @inline(__always)
    static func exactImmediate(_ value: Double, _ size: ScalarSize) -> Operand {
        let kind = immediateKind(size)
        let bits: UInt64 = switch kind {
        case .half: UInt64(halfBits(of: value))
        case .single: UInt64(Float(value).bitPattern)
        case .double: value.bitPattern
        }
        return .floatImmediate(bits: bits, kind: kind)
    }

    /// IEEE 754 binary16 bit pattern of `value`, by re-biasing the double's
    /// own exponent — exact for every value this family carries (0.0, 0.5,
    /// 1.0, 2.0, all powers of two with an empty mantissa) and for any
    /// half-representable normal.
    ///
    /// Hand-rolled rather than `Float16(value).bitPattern` for the same
    /// reason ``SIMDFPCanonicalizer/halfBitsToDouble(_:)`` decodes halves by
    /// hand: `Float16` is macOS 11 / iOS 14 and up, so referencing it sets
    /// the package's deployment floors and drops Intel macOS.
    @inline(__always)
    static func halfBits(of value: Double) -> UInt16 {
        if value == 0 { return 0 }
        let doubleBits = value.bitPattern
        let sign = UInt16(truncatingIfNeeded: doubleBits >> 63) << 15
        let unbiasedExponent = Int((doubleBits >> 52) & 0x7FF) - 1023
        let mantissa = UInt16(truncatingIfNeeded: (doubleBits >> 42) & 0x3FF)
        return sign | UInt16(unbiasedExponent + 15) << 10 | mantissa
    }

    // MARK: G16 — pairwise (0x64, bits[15:13]=100, bits[20:19]=10)

    @inline(__always)
    static func decodePairwise(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        guard let size = fpSize(e) else { return undefined(e, a) }
        let mnemonic: Mnemonic
        switch (e >> 16) & 0b111 {
        case 0b000: mnemonic = .faddp
        case 0b100: mnemonic = .fmaxnmp
        case 0b101: mnemonic = .fminnmp
        case 0b110: mnemonic = .fmaxp
        case 0b111: mnemonic = .fminp
        default: return undefined(e, a)
        }
        let dn = zd(e), m = zn(e), g = pg3(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(dn).union(vecMask(m)),
            semanticWrites: vecMask(dn), category: .sve,
            operands: [vec(dn, size), govern(g, .merging), vec(dn, size), vec(m, size)],
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }
}
