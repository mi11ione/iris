// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum FPCompareDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let ftype = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        if encoding & 0x07 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let opc = UInt8((encoding >> 3) & 0x3)

        guard let size = scalarSizeFromFtype(ftype) else {
            return .undefined(at: address, encoding: encoding)
        }

        let isZeroForm = (opc & 0b01) != 0
        let mnemonic: Mnemonic = (opc & 0b10) != 0 ? .fcmpe : .fcmp

        let vn = simdfpScalarOperand(Rn, size: size)
        let second: Operand
        var reads = simdfpInsertingVector(Rn, into: .empty)
        if isZeroForm {
            let kind: FloatImmediateKind = switch size {
            case .h: .half
            case .d: .double
            default: .single
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
            operandCount: sink.emit(vn, second),
        )
    }
}
