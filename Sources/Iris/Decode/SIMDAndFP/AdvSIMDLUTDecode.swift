// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// AdvSIMD lookup table (FEAT_LUT) — LUTI2 / LUTI4. Encoding:
// `0 Q 0 0 1110 size 0 Rm <ctrl[15:10]> Rn Rd` (shares the TBL/TBX slot:
// bits[29:28]=00, bit15=0, bit11=0, bit10=0; size != 00 distinguishes LUT
// from TBL/TBX). Rm[20:16] is the table-index register (rendered as the
// bare lane `Vm[i]`), Rn[9:5] is the table-list base, Rd[4:0] the result.
//
//   size=10 → LUTI2 .16b, list {Vn.16b},  index = bits[14:13]   (bit12=1)
//   size=11 → LUTI2 .8h,  list {Vn.8h},   index = bits[14:12]
//   size=01, bit12=1 → LUTI4 .8h, list {Vn.8h, Vn+1.8h}, index = bits[14:13]
//   size=01, bit13=1 → LUTI4 .16b, list {Vn.16b},        index = bit14
enum AdvSIMDLUTDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        // LUT forms are 128-bit only (Q=1); Q=0 is unallocated.
        guard (encoding >> 30) & 1 == 1 else { return .undefined(at: address, encoding: encoding) }
        let size = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let bit14 = (encoding >> 14) & 1
        let bit13 = (encoding >> 13) & 1
        let bit12 = (encoding >> 12) & 1
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        // bits[11:10] are fixed 0 for every LUT form; the dispatcher
        // routes only bit11 == 0 && bit10 == 0 words here.
        let m: Mnemonic
        let arrangement: VectorArrangement
        let listCount: Int
        let index: UInt8
        switch size {
        case 0b10: // LUTI2 .16b
            guard bit12 == 1 else { return .undefined(at: address, encoding: encoding) }
            m = .luti2; arrangement = .b16; listCount = 1
            index = UInt8((encoding >> 13) & 0x3)
        case 0b11: // LUTI2 .8h
            m = .luti2; arrangement = .h8; listCount = 1
            index = UInt8((encoding >> 12) & 0x7)
        default: // size=01: LUTI4 — .8h{2} (bit12=1) or .16b{1} (bit13=1).
            // size=00 is TBL/TBX, routed upstream — 01 is the only
            // remaining value here.
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

        var operands: [Operand] = [simdfpVectorOperand(Rd, arrangement: arrangement)]
        operands.reserveCapacity(2 + listCount)
        var reads: RegisterSet = .empty
        for i in 0 ..< listCount {
            let r = (Rn &+ UInt8(i)) & 0x1F
            operands.append(simdfpVectorOperand(r, arrangement: arrangement))
            reads = simdfpInsertingVector(r, into: reads)
        }
        operands.append(simdfpLaneOperand(Rm, index: index))
        reads = simdfpInsertingVector(Rm, into: reads)

        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: m,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operands: operands,
        )
    }
}
