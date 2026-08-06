// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum AdvSIMDTableLookupDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let len = UInt8((encoding >> 13) & 0x3)
        let op = UInt8((encoding >> 12) & 0x1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        let mnemonic: Mnemonic = op == 0 ? .tbl : .tbx
        let dstArrangement: VectorArrangement = Q == 1 ? .b16 : .b8

        let tableSize = Int(len) + 1
        let operandMark = sink.mark
        sink.append(simdfpVectorOperand(Rd, arrangement: dstArrangement))
        var reads: RegisterSet = .empty
        for i in 0 ..< tableSize {
            let r = (Rn &+ UInt8(i)) & 0x1F
            sink.append(simdfpVectorOperand(r, arrangement: .b16))
            reads = simdfpInsertingVector(r, into: reads)
        }
        sink.append(simdfpVectorOperand(Rm, arrangement: dstArrangement))
        reads = simdfpInsertingVector(Rm, into: reads)

        if mnemonic == .tbx {
            reads = simdfpInsertingVector(Rd, into: reads)
        }

        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.count(since: operandMark),
        )
    }
}
