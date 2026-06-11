// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// PC-relative addressing (ADR, ADRP) decode.
// Encoding bits 28:24 = 10000, op0=0x8, op1=0b00x (bit 23 is
// part of immhi, not a class discriminator). ADR target =
// record.address + byteOffset; ADRP target =
// (record.address & ~0xFFF) + byteOffset (page-aligned). Distinct
// operand cases (.label vs .pageLabel) reflect this contract for
// downstream consumers.

enum PCRelDecode {
    @inline(__always)
    @_optimize(speed)
    @_effects(readonly)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let op = UInt8((encoding >> 31) & 0x1) // 0 = ADR, 1 = ADRP
        let Rd = UInt8(encoding & 0x1F)

        // immhi = bits 23:5 (19 bits); immlo = bits 30:29 (2 bits).
        let immhi: UInt32 = (encoding >> 5) & 0x7FFFF
        let immlo: UInt32 = (encoding >> 29) & 0x3
        let raw21: UInt32 = (immhi << 2) | immlo

        // Sign-extend 21 bits to Int64. Pre-page-shift for ADR; post-page
        // shift (by 12) for ADRP.
        let signed21 = signExtend21(raw21)
        let byteOffset: Int64 = op == 1 ? signed21 << 12 : signed21

        // Rd is ZR-form (ADR/ADRP have no SP form — ARM ARM `<Xd>`
        // operand syntax); always 64-bit.
        let rdRef = gprOperand(encoding: Rd, width: .x64, form: .zrOrGeneral)

        let operand: Operand = op == 1
            ? .pageLabel(byteOffset: byteOffset)
            : .label(byteOffset: byteOffset)

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: op == 1 ? .adrp : .adr,
            semanticReads: .empty,
            semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
            flagEffect: .none,
            category: .dataProcessingImmediate,
            operands: [.register(rdRef), operand],
        )
    }

    /// Sign-extend a 21-bit value (in the low 21 bits of the input) to
    /// Int64. Arithmetic-shift-right preserves sign.
    @inline(__always)
    @_effects(readonly)
    static func signExtend21(_ raw: UInt32) -> Int64 {
        let unsigned = Int64(raw & 0x1FFFFF)
        // Shift left so bit 20 (raw's MSB) reaches bit 63, then arithmetic
        // shift right by the same amount to sign-extend.
        return (unsigned << 43) >> 43
    }
}
