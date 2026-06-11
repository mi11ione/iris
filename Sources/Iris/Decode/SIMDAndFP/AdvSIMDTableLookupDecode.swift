// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// AdvSIMD table lookup (TBL/TBX) per
// ARM ARM § C4.1.96.19. Encoding:
// `0 Q 00 1110 00 0 Rm 0 len op 00 Rn Rd`.
// `len` = bits[14:13] selects table-list size 1..4; `op` = bit[12]
// (0 = TBL, 1 = TBX). Arrangement = `.b16` (Q=1) or `.b8` (Q=0).
// Table list is `len+1` consecutive vector registers starting at Vn
// (with modulo-32 wrap). Index is in Vm with the same arrangement as
// the destination.

enum AdvSIMDTableLookupDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let len = UInt8((encoding >> 13) & 0x3)
        let op = UInt8((encoding >> 12) & 0x1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        // The dispatcher routes only op2 (bits[23:22]) == 0 here; nonzero
        // values are FEAT_LUT and go to the LUT decoder.
        let mnemonic: Mnemonic = op == 0 ? .tbl : .tbx
        let dstArrangement: VectorArrangement = Q == 1 ? .b16 : .b8

        let tableSize = Int(len) + 1
        var operands: [Operand] = []
        operands.reserveCapacity(2 + tableSize)
        // Result (operand[0]).
        operands.append(simdfpVectorOperand(Rd, arrangement: dstArrangement))
        // Table list (operands[1..tableSize]); always .b16 arrangement
        // for table lanes regardless of Q (one whole vector each).
        var reads: RegisterSet = .empty
        for i in 0 ..< tableSize {
            let r = (Rn &+ UInt8(i)) & 0x1F
            operands.append(simdfpVectorOperand(r, arrangement: .b16))
            reads = simdfpInsertingVector(r, into: reads)
        }
        // Index (last operand).
        operands.append(simdfpVectorOperand(Rm, arrangement: dstArrangement))
        reads = simdfpInsertingVector(Rm, into: reads)

        // TBX is destructive on Rd (preserves Rd lanes for out-of-range
        // index entries) — destination reads itself.
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
            operands: operands,
        )
    }
}
