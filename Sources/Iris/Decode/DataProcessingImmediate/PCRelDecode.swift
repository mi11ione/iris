// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum PCRelDecode {
    @inline(__always)
    @_optimize(speed)
    @_effects(readonly)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let op = UInt8((encoding >> 31) & 0x1)
        let Rd = UInt8(encoding & 0x1F)

        let immhi: UInt32 = (encoding >> 5) & 0x7FFFF
        let immlo: UInt32 = (encoding >> 29) & 0x3
        let raw21: UInt32 = (immhi << 2) | immlo

        let signed21 = signExtend21(raw21)
        let byteOffset: Int64 = op == 1 ? signed21 << 12 : signed21

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
            operandCount: sink.emit(.register(rdRef), operand),
        )
    }

    /// Sign-extend a 21-bit value (in the low 21 bits of the input) to Int64.
    @inline(__always)
    @_effects(readonly)
    static func signExtend21(_ raw: UInt32) -> Int64 {
        let unsigned = Int64(raw & 0x1FFFFF)
        return (unsigned << 43) >> 43
    }
}
