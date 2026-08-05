// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// FEAT_CSSC "Minimum/maximum (immediate)" decode. Shares the DPI op1=0b011
// sub-dispatch with ADDG/SUBG (MTE), split by bit[22]: bit[22]=1 is min/max
// (here), bit[22]=0 is add/sub-with-tags (MTE-owned). Encoding:
//
// sf[31] 00[30:29] 1000[28:25] 11[24:23] 1[22] 00[21:20]
// opc[19:18] imm8[17:10] Rn[9:5] Rd[4:0]
//
// opc: 00=SMAX 01=UMAX 10=SMIN 11=UMIN. `imm8` is signed for the S* forms
// (rendered as signed decimal), unsigned for the U* forms. Rd and Rn are
// ZR-form general registers.

enum MinMaxImmDecode {
    @inline(__always)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // Fixed-bit guard: bits[30:29] and bits[21:20] are zero for this class
        // (the dispatcher already fixed op0=0x8, op1=0b011, bit[22]=1). Anything
        // else in this corner of the space is unallocated → UNDEFINED, matching
        // the oracle.
        if (encoding >> 29) & 0x3 != 0 || (encoding >> 20) & 0x3 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let sf = UInt8((encoding >> 31) & 0x1)
        let opc = UInt8((encoding >> 18) & 0x3)
        let imm8 = UInt8((encoding >> 10) & 0xFF)
        let rn = UInt8((encoding >> 5) & 0x1F)
        let rd = UInt8(encoding & 0x1F)

        let width: RegisterWidth = sf == 1 ? .x64 : .w32
        let rdRef = gprOperand(encoding: rd, width: width, form: .zrOrGeneral)
        let rnRef = gprOperand(encoding: rn, width: width, form: .zrOrGeneral)

        let mnemonic: Mnemonic
        let immOperand: Operand
        switch opc {
        case 0b00: // SMAX — signed immediate.
            mnemonic = .smax
            immOperand = .immediate(value: Int64(Int8(bitPattern: imm8)), width: 8)
        case 0b01: // UMAX — unsigned immediate.
            mnemonic = .umax
            immOperand = .unsignedImmediate(value: UInt64(imm8), width: 8)
        case 0b10: // SMIN — signed immediate.
            mnemonic = .smin
            immOperand = .immediate(value: Int64(Int8(bitPattern: imm8)), width: 8)
        default: // 0b11 UMIN — unsigned immediate.
            mnemonic = .umin
            immOperand = .unsignedImmediate(value: UInt64(imm8), width: 8)
        }

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: insertingNonZero(reg: rnRef, into: .empty),
            semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
            flagEffect: .none,
            category: .dataProcessingImmediate,
            operandCount: sink.emit(.register(rdRef), .register(rnRef), immOperand),
        )
    }
}
