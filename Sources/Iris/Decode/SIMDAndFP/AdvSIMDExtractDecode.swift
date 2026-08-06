// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum AdvSIMDExtractDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let op2 = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let imm4 = UInt8((encoding >> 11) & 0xF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        if op2 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        if Q == 0, (imm4 & 0x8) != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let arrangement: VectorArrangement = Q == 1 ? .b16 : .b8
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(Rm, into: reads)
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: .ext,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.emit(simdfpVectorOperand(Rd, arrangement: arrangement), simdfpVectorOperand(Rn, arrangement: arrangement), simdfpVectorOperand(Rm, arrangement: arrangement), .unsignedImmediate(value: UInt64(imm4), width: 4)),
        )
    }
}
