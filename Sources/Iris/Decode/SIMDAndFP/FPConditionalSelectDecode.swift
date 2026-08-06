// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum FPConditionalSelectDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let ftype = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let cond = UInt8((encoding >> 12) & 0xF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        guard let size = scalarSizeFromFtype(ftype) else {
            return .undefined(at: address, encoding: encoding)
        }
        let cc = conditionCodeTable[Int(cond & 0xF)]

        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(Rm, into: reads)

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .fcsel,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none,
            memoryAccess: .none,
            memoryOrdering: [],
            flagEffect: .readsNZCV,
            category: .simdAndFP,
            operandCount: sink.emit(simdfpScalarOperand(Rd, size: size), simdfpScalarOperand(Rn, size: size), simdfpScalarOperand(Rm, size: size), .conditionCode(cc)),
        )
    }
}
