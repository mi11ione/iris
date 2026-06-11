// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Extract (EXTR) decode. Encoding bits
// 28:23 = 100111, op0=0x9, op1=0b111. Reserved: N != sf; bit 21 != 0;
// 32-bit (sf=0) imms[5]=1. ROR alias when Rn == Rm.

enum ExtractDecode {
    @inline(__always)
    @_optimize(speed)
    @_effects(readonly)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        // Per ARM ARM C6.2.123 EXTR: opc bits 30:29 must be 00 and bit 21 (o0) must be 0.
        let opcHigh = UInt8((encoding >> 29) & 0x3)
        let n = UInt8((encoding >> 22) & 0x1)
        let o0 = UInt8((encoding >> 21) & 0x1)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let imms = UInt8((encoding >> 10) & 0x3F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        // Reserved encodings:
        if opcHigh != 0 { return .undefined(at: address, encoding: encoding) }
        if o0 != 0 { return .undefined(at: address, encoding: encoding) }
        if n != sf { return .undefined(at: address, encoding: encoding) }
        if sf == 0, (imms & 0x20) != 0 {
            return .undefined(at: address, encoding: encoding)
        }

        let width: RegisterWidth = sf == 1 ? .x64 : .w32
        // EXTR Rd/Rn/Rm are all ZR-form (ARM ARM `<Xd>` operand syntax).
        let rdRef = gprOperand(encoding: Rd, width: width, form: .zrOrGeneral)
        let rnRef = gprOperand(encoding: Rn, width: width, form: .zrOrGeneral)
        let rmRef = gprOperand(encoding: Rm, width: width, form: .zrOrGeneral)

        // ROR alias: EXTR with Rn == Rm. Operand list: 3 (Rd, Rn, #imms).
        if Rn == Rm {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .ror,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: .none,
                category: .dataProcessingImmediate,
                operands: [
                    .register(rdRef), .register(rnRef),
                    .unsignedImmediate(value: UInt64(imms), width: 6),
                ],
            )
        }

        // Base EXTR: 4 operands (Rd, Rn, Rm, #imms).
        var reads: RegisterSet = .empty
        if imms != 0 { reads = insertingNonZero(reg: rnRef, into: reads) }
        reads = insertingNonZero(reg: rmRef, into: reads)
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .extr,
            semanticReads: reads,
            semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
            flagEffect: .none,
            category: .dataProcessingImmediate,
            operands: [
                .register(rdRef), .register(rnRef), .register(rmRef),
                .unsignedImmediate(value: UInt64(imms), width: 6),
            ],
        )
    }
}
