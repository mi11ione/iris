// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum AdvSIMDThreeSameFP16Decode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (encoding >> 14) & 1 == 1 { return .undefined(at: address, encoding: encoding) }
        let Q = UInt8((encoding >> 30) & 1)
        let U = UInt8((encoding >> 29) & 1)
        let a = UInt8((encoding >> 23) & 1)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let op3 = UInt8((encoding >> 11) & 0x7)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        let m: Mnemonic
        switch (U, a, op3) {
        case (0, 0, 0): m = .fmaxnm
        case (0, 0, 1): m = .fmla
        case (0, 0, 2): m = .fadd
        case (0, 0, 3): m = .fmulx
        case (0, 0, 4): m = .fcmeq
        case (0, 0, 6): m = .fmax
        case (0, 0, 7): m = .frecps
        case (0, 1, 0): m = .fminnm
        case (0, 1, 1): m = .fmls
        case (0, 1, 2): m = .fsub
        case (0, 1, 3): m = .famax
        case (0, 1, 6): m = .fmin
        case (0, 1, 7): m = .frsqrts
        case (1, 0, 0): m = .fmaxnmp
        case (1, 0, 2): m = .faddp
        case (1, 0, 3): m = .fmul
        case (1, 0, 4): m = .fcmge
        case (1, 0, 5): m = .facge
        case (1, 0, 6): m = .fmaxp
        case (1, 0, 7): m = .fdiv
        case (1, 1, 0): m = .fminnmp
        case (1, 1, 2): m = .fabd
        case (1, 1, 3): m = .famin
        case (1, 1, 4): m = .fcmgt
        case (1, 1, 5): m = .facgt
        case (1, 1, 6): m = .fminp
        case (1, 1, 7): m = .fscale
        default: return .undefined(at: address, encoding: encoding)
        }

        let arrangement: VectorArrangement = Q == 1 ? .h8 : .h4
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(Rm, into: reads)
        if simdFPDestinationReadsItself(m) {
            reads = simdfpInsertingVector(Rd, into: reads)
        }
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: m,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.emit(simdfpVectorOperand(Rd, arrangement: arrangement), simdfpVectorOperand(Rn, arrangement: arrangement), simdfpVectorOperand(Rm, arrangement: arrangement)),
        )
    }
}
