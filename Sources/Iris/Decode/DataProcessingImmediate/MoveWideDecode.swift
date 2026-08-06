// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum MoveWideDecode {
    @inline(__always)
    @_optimize(speed)
    @_effects(readonly)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let opc = UInt8((encoding >> 29) & 0x3)
        let hw = UInt8((encoding >> 21) & 0x3)
        let imm16 = UInt16((encoding >> 5) & 0xFFFF)
        let Rd = UInt8(encoding & 0x1F)

        if opc == 0b01 { return .undefined(at: address, encoding: encoding) }
        if sf == 0, (hw & 0b10) != 0 { return .undefined(at: address, encoding: encoding) }

        let regSize: UInt8 = sf == 1 ? 64 : 32
        let width: RegisterWidth = sf == 1 ? .x64 : .w32
        let rdRef = gprOperand(encoding: Rd, width: width, form: .zrOrGeneral)
        let shiftAmount: UInt8 = hw &* 16

        if opc == 0b10 {
            let value64 = UInt64(imm16) << shiftAmount
            if value64 != 0 || hw == 0 {
                let displayValue = signExtendForMovWide(value64, regSize: regSize)
                return DecodedDraft(
                    address: address,
                    encoding: encoding,
                    mnemonic: .mov,
                    semanticReads: .empty,
                    semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                    flagEffect: .none,
                    category: .dataProcessingImmediate,
                    operandCount: sink.emit(.register(rdRef), .immediate(value: displayValue, width: regSize)),
                )
            }
        }

        if opc == 0b00, imm16 != 0 || hw == 0 {
            let value64 = UInt64(imm16) << shiftAmount
            let widthMask: UInt64 = regSize == 64 ? UInt64.max : UInt64(UInt32.max)
            let inverted: UInt64 = ~value64 & widthMask
            if !AliasPredicates.isMOVZRepresentable(inverted, regSize: regSize) {
                let displayValue = signExtendForMovWide(inverted, regSize: regSize)
                return DecodedDraft(
                    address: address,
                    encoding: encoding,
                    mnemonic: .mov,
                    semanticReads: .empty,
                    semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                    flagEffect: .none,
                    category: .dataProcessingImmediate,
                    operandCount: sink.emit(.register(rdRef), .immediate(value: displayValue, width: regSize)),
                )
            }
        }

        let mnemonic: Mnemonic = if opc == 0b00 {
            .movn
        } else if opc == 0b10 {
            .movz
        } else {
            .movk
        }
        let operandMark = sink.mark
        sink.append(.register(rdRef))
        sink.append(.unsignedImmediate(value: UInt64(imm16), width: 16))
        if hw != 0 {
            sink.append(.shiftAmount(kind: .lsl, amount: shiftAmount))
        }
        let reads: RegisterSet = mnemonic == .movk
            ? insertingNonZero(reg: rdRef, into: .empty)
            : .empty
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
            flagEffect: .none,
            category: .dataProcessingImmediate,
            operandCount: sink.count(since: operandMark),
        )
    }

    /// Sign-extend the MOV-wide computed value to Int64 for display.
    @inline(__always)
    @_effects(readonly)
    static func signExtendForMovWide(_ value: UInt64, regSize: UInt8) -> Int64 {
        if regSize == 64 {
            return Int64(bitPattern: value)
        }
        let v32 = UInt32(truncatingIfNeeded: value)
        return Int64(Int32(bitPattern: v32))
    }
}
