// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum AdvSIMDAcrossLanesDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let U = UInt8((encoding >> 29) & 0x1)
        let size = UInt8((encoding >> 22) & 0x3)
        let opcode = UInt8((encoding >> 12) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        if opcode == 0b01100 || opcode == 0b01111 {
            if size & 1 != 0 { return .undefined(at: address, encoding: encoding) }
            let isMin = (size >> 1) & 1 == 1
            let nm = opcode == 0b01100
            let m: Mnemonic = isMin
                ? (nm ? .fminnmv : .fminv)
                : (nm ? .fmaxnmv : .fmaxv)
            let resultSize: ScalarSize
            let srcArr: VectorArrangement
            if U == 1 {
                if Q != 1 { return .undefined(at: address, encoding: encoding) }
                resultSize = .s
                srcArr = .s4
            } else {
                resultSize = .h
                srcArr = Q == 1 ? .h8 : .h4
            }
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: m,
                semanticReads: simdfpInsertingVector(Rn, into: .empty),
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operandCount: sink.emit(simdfpScalarOperand(Rd, size: resultSize), simdfpVectorOperand(Rn, arrangement: srcArr)),
            )
        }

        let srcArrangement = arrangementFromSizeQ(size: size, Q: Q)
        if srcArrangement == .d1 || srcArrangement == .d2 || srcArrangement == .s2 {
            return .undefined(at: address, encoding: encoding)
        }

        let mnemonic: Mnemonic
        let resultSize: ScalarSize
        switch (U, opcode) {
        case (0, 0b00011):
            mnemonic = .saddlv
            resultSize = widenSize(elementSize(srcArrangement))
        case (1, 0b00011):
            mnemonic = .uaddlv
            resultSize = widenSize(elementSize(srcArrangement))
        case (0, 0b01010): mnemonic = .smaxv; resultSize = elementSize(srcArrangement)
        case (1, 0b01010): mnemonic = .umaxv; resultSize = elementSize(srcArrangement)
        case (0, 0b11010): mnemonic = .sminv; resultSize = elementSize(srcArrangement)
        case (1, 0b11010): mnemonic = .uminv; resultSize = elementSize(srcArrangement)
        case (0, 0b11011): mnemonic = .addv; resultSize = elementSize(srcArrangement)
        default:
            return .undefined(at: address, encoding: encoding)
        }

        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: simdfpInsertingVector(Rn, into: .empty),
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.emit(simdfpScalarOperand(Rd, size: resultSize), simdfpVectorOperand(Rn, arrangement: srcArrangement)),
        )
    }

    @inline(__always)
    @_effects(readonly)
    private static func elementSize(_ a: VectorArrangement) -> ScalarSize {
        a.elementSize
    }

    @inline(__always)
    @_effects(readonly)
    private static func widenSize(_ s: ScalarSize) -> ScalarSize {
        switch s {
        case .b: .h
        case .h: .s
        default: .d
        }
    }
}
