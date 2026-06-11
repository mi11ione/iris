// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// FP data-processing (3 source) per ARM ARM § C4.1.96.41.
// Encoding: `0 0 0 11111 ftype o1 Rm o0 Ra Rn Rd`.
// (o1, o0) selects FMADD/FMSUB/FNMADD/FNMSUB.

enum FPDataProcessing3SourceDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        // M (bit31) is a fixed 0 for FP DP 3-source; M=1 is reserved.
        if (encoding >> 31) & 1 == 1 {
            return .undefined(at: address, encoding: encoding)
        }
        let ftype = UInt8((encoding >> 22) & 0x3)
        let o1 = UInt8((encoding >> 21) & 0x1)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let o0 = UInt8((encoding >> 15) & 0x1)
        let Ra = UInt8((encoding >> 10) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        guard let size = scalarSizeFromFtype(ftype) else {
            return .undefined(at: address, encoding: encoding)
        }

        let mnemonic: Mnemonic = switch (o1, o0) {
        case (0, 0): .fmadd
        case (0, 1): .fmsub
        case (1, 0): .fnmadd
        default: .fnmsub // (o1, o0) = (1, 1) — only remaining 2-bit pair.
        }

        let vd = simdfpScalarOperand(Rd, size: size)
        let vn = simdfpScalarOperand(Rn, size: size)
        let vm = simdfpScalarOperand(Rm, size: size)
        let va = simdfpScalarOperand(Ra, size: size)

        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(Rm, into: reads)
        reads = simdfpInsertingVector(Ra, into: reads)

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none,
            memoryAccess: .none,
            memoryOrdering: [],
            flagEffect: .none,
            category: .simdAndFP,
            operands: [vd, vn, vm, va],
        )
    }
}
