// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum ScalarSIMDLRCPC2Decode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (encoding >> 10) & 0x3 != 0b10 { return .undefined(at: address, encoding: encoding) }
        if (encoding >> 21) & 1 != 0 { return .undefined(at: address, encoding: encoding) }

        let size = UInt8((encoding >> 30) & 0x3)
        let opc = UInt8((encoding >> 22) & 0x3)
        let imm9 = (encoding >> 12) & 0x1FF
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        let element: ScalarSize
        let isLoad: Bool
        switch (size, opc) {
        case (0b00, 0b00): element = .b; isLoad = false
        case (0b00, 0b01): element = .b; isLoad = true
        case (0b00, 0b10): element = .q; isLoad = false
        case (0b00, 0b11): element = .q; isLoad = true
        case (0b01, 0b00): element = .h; isLoad = false
        case (0b01, 0b01): element = .h; isLoad = true
        case (0b10, 0b00): element = .s; isLoad = false
        case (0b10, 0b01): element = .s; isLoad = true
        case (0b11, 0b00): element = .d; isLoad = false
        case (0b11, 0b01): element = .d; isLoad = true
        default: return .undefined(at: address, encoding: encoding)
        }

        let rnRef = simdfpGprOperand(encoding: Rn, width: .x64, spOrGeneral: true)
        let mem = MemoryOperand(
            base: .register(rnRef), index: nil,
            displacement: lsSignExtendImm9(imm9),
            extend: .none, shift: 0, writeback: .none,
        )
        var reads = simdfpInsertingNonZeroGPR(reg: rnRef, into: .empty)
        var writes: RegisterSet = .empty
        if isLoad {
            writes = simdfpInsertingVector(Rt, into: .empty)
        } else {
            reads = simdfpInsertingVector(Rt, into: reads)
        }

        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: isLoad ? .ldapur : .stlur,
            semanticReads: reads, semanticWrites: writes,
            branchClass: .none,
            memoryAccess: isLoad ? .load : .store,
            memoryOrdering: isLoad ? [.acquire] : [.release],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.emit(simdfpScalarOperand(Rt, size: element), .memory(mem)),
        )
    }
}
