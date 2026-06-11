// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// FP conditional select per ARM ARM § C4.1.96.40.
// Encoding: `0 0 0 11110 ftype 1 Rm cond 11 Rn Rd`. Single mnemonic
// FCSEL — reads Vn or Vm depending on `cond` at runtime; flag-effect is
// `.readsNZCV` (FCSEL consumes NZCV, writes no flag).

enum FPConditionalSelectDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let ftype = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let cond = UInt8((encoding >> 12) & 0xF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        guard let size = scalarSizeFromFtype(ftype) else {
            return .undefined(at: address, encoding: encoding)
        }
        // ConditionCode raw values cover 0..15 exhaustively — index the
        // dense table from FPConditionalCompareDecode.swift.
        let cc = conditionCodeTable[Int(cond & 0xF)]

        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(Rm, into: reads)

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .fcsel,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none,
            memoryAccess: .none,
            memoryOrdering: [],
            flagEffect: .readsNZCV,
            category: .simdAndFP,
            operands: [
                simdfpScalarOperand(Rd, size: size),
                simdfpScalarOperand(Rn, size: size),
                simdfpScalarOperand(Rm, size: size),
                .conditionCode(cc),
            ],
        )
    }
}
