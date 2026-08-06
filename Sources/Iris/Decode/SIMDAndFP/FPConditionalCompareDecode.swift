// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum FPConditionalCompareDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let ftype = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let cond = UInt8((encoding >> 12) & 0xF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let op = UInt8((encoding >> 4) & 0x1)
        let nzcv = UInt64(encoding & 0xF)

        guard let size = scalarSizeFromFtype(ftype) else {
            return .undefined(at: address, encoding: encoding)
        }
        let cc = conditionCodeTable[Int(cond & 0xF)]

        let mnemonic: Mnemonic = op == 1 ? .fccmpe : .fccmp

        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(Rm, into: reads)

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: .empty,
            branchClass: .none,
            memoryAccess: .none,
            memoryOrdering: [],
            flagEffect: [.nzcv, .readsNZCV],
            category: .simdAndFP,
            operandCount: sink.emit(simdfpScalarOperand(Rn, size: size), simdfpScalarOperand(Rm, size: size), .unsignedImmediate(value: nzcv, width: 4), .conditionCode(cc)),
        )
    }
}

/// Dense 16-entry table mapping a 4-bit `cond` field to the corresponding
/// ``ConditionCode``.
@usableFromInline
let conditionCodeTable: [ConditionCode] = [
    .eq, .ne, .cs, .cc, .mi, .pl, .vs, .vc,
    .hi, .ls, .ge, .lt, .gt, .le, .al, .nv,
]
