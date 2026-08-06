// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum AdvSIMDPermuteDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let size = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let opcode = UInt8((encoding >> 12) & 0x7)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        let arrangement = arrangementFromSizeQ(size: size, Q: Q)
        if arrangement == .d1 {
            return .undefined(at: address, encoding: encoding)
        }

        let mnemonic: Mnemonic
        switch opcode {
        case 0b001: mnemonic = .uzp1
        case 0b010: mnemonic = .trn1
        case 0b011: mnemonic = .zip1
        case 0b101: mnemonic = .uzp2
        case 0b110: mnemonic = .trn2
        case 0b111: mnemonic = .zip2
        default: return .undefined(at: address, encoding: encoding)
        }

        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(Rm, into: reads)
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.emit(simdfpVectorOperand(Rd, arrangement: arrangement), simdfpVectorOperand(Rn, arrangement: arrangement), simdfpVectorOperand(Rm, arrangement: arrangement)),
        )
    }
}
