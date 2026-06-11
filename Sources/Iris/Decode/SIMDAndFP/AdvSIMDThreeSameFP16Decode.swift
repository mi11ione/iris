// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// AdvSIMD three-same (FP16) — half-precision three-register-same
// arithmetic. Encoding: `0 Q U 0 1110 a 1 0 Rm 0 0 op3 1 Rn Rd`
// (bits[28:24]=01110, bit23=a, bit22=1, bit21=0, bits[15:14]=00,
// bits[13:11]=op3, bit10=1). Element type is always FP16 (.4h/.8h);
// (U, a, op3) selects the operation. The .2s/.4s/.2d forms of these ops
// live in the regular three-same class (bit21=1); the bit15=1 region of
// this slot is the three-register-extension class (FCMA/dot/MMLA).
enum AdvSIMDThreeSameFP16Decode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        // bits[15:14] must be 00 for this class; bit14=1 is reserved.
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
        if SIMDFPSemanticAttributes.destinationReadsItself(for: m) {
            reads = simdfpInsertingVector(Rd, into: reads)
        }
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: m,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operands: [
                simdfpVectorOperand(Rd, arrangement: arrangement),
                simdfpVectorOperand(Rn, arrangement: arrangement),
                simdfpVectorOperand(Rm, arrangement: arrangement),
            ],
        )
    }
}
