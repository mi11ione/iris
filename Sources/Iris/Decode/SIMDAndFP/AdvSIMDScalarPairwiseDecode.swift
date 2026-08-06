// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum AdvSIMDScalarPairwiseDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let U = UInt8((encoding >> 29) & 0x1)
        let size = UInt8((encoding >> 22) & 0x3)
        let opcode = UInt8((encoding >> 12) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        if U == 0, opcode == 0b11011 {
            if size != 0b11 {
                return .undefined(at: address, encoding: encoding)
            }
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: .addp,
                semanticReads: simdfpInsertingVector(Rn, into: .empty),
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operandCount: sink.emit(simdfpScalarOperand(Rd, size: .d), simdfpVectorOperand(Rn, arrangement: .d2)),
            )
        }
        if U == 0, size & 1 == 0 {
            let altBit = (size >> 1) & 1
            let m: Mnemonic? = switch (opcode, altBit) {
            case (0b01100, 0): .fmaxnmp
            case (0b01100, 1): .fminnmp
            case (0b01101, 0): .faddp
            case (0b01111, 0): .fmaxp
            case (0b01111, 1): .fminp
            default: nil
            }
            if let m {
                return DecodedDraft(
                    address: address, encoding: encoding, mnemonic: m,
                    semanticReads: simdfpInsertingVector(Rn, into: .empty),
                    semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                    branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                    flagEffect: .none, category: .simdAndFP,
                    operandCount: sink.emit(simdfpScalarOperand(Rd, size: .h), simdfpVectorOperand(Rn, arrangement: .h2)),
                )
            }
        }
        if U == 1 {
            let sz = size & 1
            let altBit = (size >> 1) & 1
            let elementSize: ScalarSize = sz == 0 ? .s : .d
            let m: Mnemonic
            switch (opcode, altBit) {
            case (0b01100, 0): m = .fmaxnmp
            case (0b01100, 1): m = .fminnmp
            case (0b01101, 0): m = .faddp
            case (0b01111, 0): m = .fmaxp
            case (0b01111, 1): m = .fminp
            default: return .undefined(at: address, encoding: encoding)
            }
            let arrangement: VectorArrangement = sz == 0 ? .s2 : .d2
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: m,
                semanticReads: simdfpInsertingVector(Rn, into: .empty),
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operandCount: sink.emit(simdfpScalarOperand(Rd, size: elementSize), simdfpVectorOperand(Rn, arrangement: arrangement)),
            )
        }
        return .undefined(at: address, encoding: encoding)
    }
}
