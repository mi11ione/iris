// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// AdvSIMD vector extract (EXT) per
// ARM ARM § C4.1.96.21. Encoding:
// `0 Q 10 1110 00 0 Rm 0 imm4 0 Rn Rd`.
// Arrangement is .b8 (Q=0) or .b16 (Q=1) only; imm4 is the byte-index
// shift (0..7 for Q=0, 0..15 for Q=1). For Q=0, imm4[3] must be 0.

enum AdvSIMDExtractDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let op2 = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let imm4 = UInt8((encoding >> 11) & 0xF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        // op2 (bits[23:22]) must be 00 for EXT.
        if op2 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        // For Q=0, imm4[3] must be zero (only 8 bytes addressable).
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
            operands: [
                simdfpVectorOperand(Rd, arrangement: arrangement),
                simdfpVectorOperand(Rn, arrangement: arrangement),
                simdfpVectorOperand(Rm, arrangement: arrangement),
                .unsignedImmediate(value: UInt64(imm4), width: 4),
            ],
        )
    }
}
