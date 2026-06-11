// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// AdvSIMD vector permute (UZP1/UZP2/TRN1/TRN2/ZIP1/ZIP2)
// per ARM ARM § C4.1.96.20. Encoding:
// `0 Q 00 1110 size 0 Rm 0 opcode 1 0 Rn Rd`.
// opcode (bits[14:12]):
//   001 UZP1  010 TRN1  011 ZIP1  101 UZP2  110 TRN2  111 ZIP2

enum AdvSIMDPermuteDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let size = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let opcode = UInt8((encoding >> 12) & 0x7)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        // (size, Q) must encode a valid arrangement. size=11, Q=0 is
        // reserved here (only 1D is allowed in permute; 1D doesn't make
        // sense for permute either — per ARM ARM § C7.2.387 reserved).
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
            operands: [
                simdfpVectorOperand(Rd, arrangement: arrangement),
                simdfpVectorOperand(Rn, arrangement: arrangement),
                simdfpVectorOperand(Rm, arrangement: arrangement),
            ],
        )
    }
}
