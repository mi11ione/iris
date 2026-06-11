// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// FP conditional compare per ARM ARM § C4.1.96.38.
// Encoding: `0 0 0 11110 ftype 1 Rm cond 01 Rn op nzcv`. `op` = bit[4]
// (0 = FCCMP, 1 = FCCMPE). `cond` = bits[15:12]. `nzcv` = bits[3:0].
//
// Operand layout: `[Vn, Vm, #nzcv, <cond>]`. Flag-effect = .nzcv.

enum FPConditionalCompareDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let ftype = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let cond = UInt8((encoding >> 12) & 0xF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let op = UInt8((encoding >> 4) & 0x1)
        let nzcv = UInt64(encoding & 0xF)

        guard let size = scalarSizeFromFtype(ftype) else {
            return .undefined(at: address, encoding: encoding)
        }
        // ConditionCode covers raw values 0..15 exhaustively; `cond & 0xF`
        // always indexes a valid case via the table lookup.
        let cc = conditionCodeTable[Int(cond & 0xF)]

        let mnemonic: Mnemonic = op == 1 ? .fccmpe : .fccmp

        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(Rm, into: reads)

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: .empty,
            branchClass: .none,
            memoryAccess: .none,
            memoryOrdering: [],
            flagEffect: [.nzcv, .readsNZCV],
            category: .simdAndFP,
            operands: [
                simdfpScalarOperand(Rn, size: size),
                simdfpScalarOperand(Rm, size: size),
                .unsignedImmediate(value: nzcv, width: 4),
                .conditionCode(cc),
            ],
        )
    }
}

/// Dense 16-entry table mapping a 4-bit `cond` field to the
/// corresponding ``ConditionCode``. Avoids the failable init?(rawValue:)
/// when the caller has already masked the input to 4 bits.
@usableFromInline
let conditionCodeTable: [ConditionCode] = [
    .eq, .ne, .cs, .cc, .mi, .pl, .vs, .vc,
    .hi, .ls, .ge, .lt, .gt, .le, .al, .nv,
]
