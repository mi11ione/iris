// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum FPFixedPointConversionDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let ftype = UInt8((encoding >> 22) & 0x3)
        let rmode = UInt8((encoding >> 19) & 0x3)
        let opcode = UInt8((encoding >> 16) & 0x7)
        let scale = UInt8((encoding >> 10) & 0x3F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        guard let size = scalarSizeFromFtype(ftype) else {
            return .undefined(at: address, encoding: encoding)
        }

        if sf == 0, scale < 32 {
            return .undefined(at: address, encoding: encoding)
        }

        let fbits = UInt64(64 - Int(scale))
        let intWidth: RegisterWidth = sf == 1 ? .x64 : .w32
        let intReg = simdfpGprOperand(encoding: 0, width: intWidth, spOrGeneral: false)
        _ = intReg

        let mnemonic: Mnemonic
        let direction: ConversionDirection
        switch (rmode, opcode) {
        case (0b00, 0b010): mnemonic = .scvtf; direction = .gprToFP
        case (0b00, 0b011): mnemonic = .ucvtf; direction = .gprToFP
        case (0b11, 0b000): mnemonic = .fcvtzs; direction = .fpToGPR
        case (0b11, 0b001): mnemonic = .fcvtzu; direction = .fpToGPR
        default:
            return .undefined(at: address, encoding: encoding)
        }

        let scaleOp = Operand.unsignedImmediate(value: fbits, width: 6)
        switch direction {
        case .gprToFP:
            let gpr = simdfpGprOperand(encoding: Rn, width: intWidth, spOrGeneral: false)
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: simdfpInsertingNonZeroGPR(reg: gpr, into: .empty),
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operandCount: sink.emit(simdfpScalarOperand(Rd, size: size), .register(gpr), scaleOp),
            )
        case .fpToGPR:
            let gpr = simdfpGprOperand(encoding: Rd, width: intWidth, spOrGeneral: false)
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: simdfpInsertingVector(Rn, into: .empty),
                semanticWrites: simdfpInsertingNonZeroGPR(reg: gpr, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operandCount: sink.emit(.register(gpr), simdfpScalarOperand(Rn, size: size), scaleOp),
            )
        }
    }

    private enum ConversionDirection {
        case gprToFP
        case fpToGPR
    }
}
