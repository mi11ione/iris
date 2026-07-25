// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// 0x25 immediate region: G7 signed-immediate compare
// (`sve_int_scmp_vi`), G10 wide-immediate arithmetic (`sve_int_arith_imm0`
// add/sub/…, `sve_int_arith_imm` mul/smax/smin/umax/umin), and G8 DUP-
// immediate (`sve_int_dup_imm`, rendered `mov`). Field layout: Zdn/Zd [4:0],
// imm8 [12:5], sh (LSL #8) [13] for add-family and DUP; the arith_imm
// (smax/…) forms have no shift. Per the wide-immediate and DUP
// forms are unpredicated destructive full writes (Zdn read, partialWrite
// clear); DUP is a fresh full write.

extension SVEIntegerDecode {
    @inline(__always)
    static func decodeImmediate(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        if (e & 0xFF20_4000) == 0x2500_0000 { return decodeCompareSignedImmediate(e, a) } // G7
        if (e & 0xFF3F_C000) == 0x2538_C000 { return decodeDupImmediate(e, a) } // G8
        return decodeWideImmediate(e, a) // G10
    }

    // MARK: G10 wide immediate — `<mn> <Zdn>.<T>, <Zdn>.<T>, #<imm8>{, LSL #8}`

    /// The two wide-immediate classes (`sve_int_arith_imm0` add/sub/saturating,
    /// `sve_int_arith_imm` min/max/mul) interleave in the opcode space rather than
    /// splitting on any single bit — MUL sits at opc 10000, above the min/max
    /// block but sharing b19 with the add/sub block — so the whole 5-bit opc
    /// [20:16] selects the form, and with it the immediate's signedness and
    /// whether the `LSL #8` shift bit is available at all.
    @inline(__always)
    static func decodeWideImmediate(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // Both classes fix b15:14 = 11. The scope gate only pins b15 in the MUL
        // sub-region, so the b14=0 hole arrives here and must be rejected.
        guard (e >> 14) & 1 == 1 else { return undefined(e, a) }
        let mnemonic: Mnemonic
        let signed: Bool
        let hasShift: Bool
        switch (e >> 16) & 0b11111 {
        case 0b00000: (mnemonic, signed, hasShift) = (.add, false, true)
        case 0b00001: (mnemonic, signed, hasShift) = (.sub, false, true)
        case 0b00011: (mnemonic, signed, hasShift) = (.subr, false, true)
        case 0b00100: (mnemonic, signed, hasShift) = (.sqadd, false, true)
        case 0b00101: (mnemonic, signed, hasShift) = (.uqadd, false, true)
        case 0b00110: (mnemonic, signed, hasShift) = (.sqsub, false, true)
        case 0b00111: (mnemonic, signed, hasShift) = (.uqsub, false, true)
        case 0b01000: (mnemonic, signed, hasShift) = (.smax, true, false)
        case 0b01001: (mnemonic, signed, hasShift) = (.umax, false, false)
        case 0b01010: (mnemonic, signed, hasShift) = (.smin, true, false)
        case 0b01011: (mnemonic, signed, hasShift) = (.umin, false, false)
        case 0b10000: (mnemonic, signed, hasShift) = (.mul, true, false)
        default: return undefined(e, a)
        }
        // The shift-less forms have no b13 field; b13=1 there is reserved.
        if !hasShift, (e >> 13) & 1 != 0 { return undefined(e, a) }
        return wideImmediateDraft(e, a, mnemonic: mnemonic, signed: signed, hasShift: hasShift)
    }

    /// Shared wide-immediate destructive draft: `<mn> Zdn.T, Zdn.T, #imm{, lsl #8}`.
    @inline(__always)
    static func wideImmediateDraft(
        _ e: UInt32, _ a: UInt64, mnemonic: Mnemonic, signed: Bool, hasShift: Bool,
    ) -> DecodedDraft {
        let dn = zd(e), size = sz(e)
        let raw = (e >> 5) & 0xFF
        // LSL #8 requires an element ≥ 16 bits; sh=1 with sz=.b is UNDEFINED.
        if hasShift, (e >> 13) & 1 == 1, size == .b { return undefined(e, a) }
        let shift: UInt32 = hasShift && (e >> 13) & 1 == 1 ? 8 : 0
        var operands = [Operand]()
        operands.reserveCapacity(4)
        operands.append(vec(dn, size))
        operands.append(vec(dn, size))
        appendShiftedImmediate(raw: raw, shift: shift, signed: signed, to: &operands)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(dn), semanticWrites: vecMask(dn), category: .sve,
            operands: operands, scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: G8 DUP immediate (rendered `mov`; imm8 signed, optional LSL #8)

    @inline(__always)
    static func decodeDupImmediate(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let d = zd(e), size = sz(e)
        let raw = (e >> 5) & 0xFF
        if (e >> 13) & 1 == 1, size == .b { return undefined(e, a) } // LSL #8 illegal for .b
        let shift: UInt32 = (e >> 13) & 1 == 1 ? 8 : 0
        var operands = [Operand]()
        operands.reserveCapacity(3)
        operands.append(vec(d, size))
        appendShiftedImmediate(raw: raw, shift: shift, signed: true, to: &operands)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .mov,
            semanticWrites: vecMask(d), category: .sve,
            operands: operands,
            scalableEffect: .readsStreamingMode,
        )
    }
}
