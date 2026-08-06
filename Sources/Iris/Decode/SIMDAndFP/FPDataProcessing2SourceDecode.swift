// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum FPDataProcessing2SourceDecode {
    /// Discriminator for this sub-class.
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let ftype = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let opcode = UInt8((encoding >> 12) & 0xF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        guard let size = scalarSizeFromFtype(ftype) else {
            return .undefined(at: address, encoding: encoding)
        }

        let mnemonic: Mnemonic
        switch opcode {
        case 0b0000: mnemonic = .fmul
        case 0b0001: mnemonic = .fdiv
        case 0b0010: mnemonic = .fadd
        case 0b0011: mnemonic = .fsub
        case 0b0100: mnemonic = .fmax
        case 0b0101: mnemonic = .fmin
        case 0b0110: mnemonic = .fmaxnm
        case 0b0111: mnemonic = .fminnm
        case 0b1000: mnemonic = .fnmul
        default: return .undefined(at: address, encoding: encoding)
        }

        let vd = simdfpScalarOperand(Rd, size: size)
        let vn = simdfpScalarOperand(Rn, size: size)
        let vm = simdfpScalarOperand(Rm, size: size)

        let writes = simdfpInsertingVector(Rd, into: .empty)
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(Rm, into: reads)

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: writes,
            branchClass: .none,
            memoryAccess: .none,
            memoryOrdering: [],
            flagEffect: .none,
            category: .simdAndFP,
            operandCount: sink.emit(vd, vn, vm),
        )
    }
}
