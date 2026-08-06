// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum AdvSIMDLUTDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard (encoding >> 30) & 1 == 1 else { return .undefined(at: address, encoding: encoding) }
        let size = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let bit14 = (encoding >> 14) & 1
        let bit13 = (encoding >> 13) & 1
        let bit12 = (encoding >> 12) & 1
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        let m: Mnemonic
        let arrangement: VectorArrangement
        let listCount: Int
        let index: UInt8
        switch size {
        case 0b10:
            guard bit12 == 1 else { return .undefined(at: address, encoding: encoding) }
            m = .luti2; arrangement = .b16; listCount = 1
            index = UInt8((encoding >> 13) & 0x3)
        case 0b11:
            m = .luti2; arrangement = .h8; listCount = 1
            index = UInt8((encoding >> 12) & 0x7)
        default:
            if bit12 == 1 {
                m = .luti4; arrangement = .h8; listCount = 2
                index = UInt8((encoding >> 13) & 0x3)
            } else if bit13 == 1 {
                m = .luti4; arrangement = .b16; listCount = 1
                index = UInt8(bit14)
            } else {
                return .undefined(at: address, encoding: encoding)
            }
        }

        let operandMark = sink.mark
        sink.append(simdfpVectorOperand(Rd, arrangement: arrangement))
        var reads: RegisterSet = .empty
        for i in 0 ..< listCount {
            let r = (Rn &+ UInt8(i)) & 0x1F
            sink.append(simdfpVectorOperand(r, arrangement: arrangement))
            reads = simdfpInsertingVector(r, into: reads)
        }
        sink.append(simdfpLaneOperand(Rm, index: index))
        reads = simdfpInsertingVector(Rm, into: reads)

        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: m,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.count(since: operandMark),
        )
    }
}
