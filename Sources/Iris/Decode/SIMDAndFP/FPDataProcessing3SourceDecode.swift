// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum FPDataProcessing3SourceDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
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
        default: .fnmsub
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
            operandCount: sink.emit(vd, vn, vm, va),
        )
    }
}
