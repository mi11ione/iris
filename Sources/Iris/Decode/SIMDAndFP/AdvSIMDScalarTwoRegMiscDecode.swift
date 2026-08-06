// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum AdvSIMDScalarTwoRegMiscDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let U = UInt8((encoding >> 29) & 0x1)
        let size = UInt8((encoding >> 22) & 0x3)
        let opcode = UInt8((encoding >> 12) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        let bit23 = (size >> 1) & 1
        if opcode >= 0b11000 || (opcode >= 0b01100 && opcode <= 0b01110 && bit23 == 1) {
            let sz = size & 1
            let altBit = (size >> 1) & 1
            let elementSize: ScalarSize = sz == 0 ? .s : .d
            let m: Mnemonic
            let zeroForm: Bool
            switch (U, opcode, altBit) {
            case (0, 0b11010, 0): m = .fcvtns; zeroForm = false
            case (0, 0b11010, 1): m = .fcvtps; zeroForm = false
            case (0, 0b11011, 0): m = .fcvtms; zeroForm = false
            case (0, 0b11011, 1): m = .fcvtzs; zeroForm = false
            case (0, 0b11100, 0): m = .fcvtas; zeroForm = false
            case (0, 0b11101, 0): m = .scvtf; zeroForm = false
            case (0, 0b11101, 1): m = .frecpe; zeroForm = false
            case (0, 0b11111, 1): m = .frecpx; zeroForm = false
            case (0, 0b01100, 1): m = .fcmgt; zeroForm = true
            case (0, 0b01101, 1): m = .fcmeq; zeroForm = true
            case (0, 0b01110, 1): m = .fcmlt; zeroForm = true
            case (1, 0b11010, 0): m = .fcvtnu; zeroForm = false
            case (1, 0b11010, 1): m = .fcvtpu; zeroForm = false
            case (1, 0b11011, 0): m = .fcvtmu; zeroForm = false
            case (1, 0b11011, 1): m = .fcvtzu; zeroForm = false
            case (1, 0b11100, 0): m = .fcvtau; zeroForm = false
            case (1, 0b11101, 0): m = .ucvtf; zeroForm = false
            case (1, 0b11101, 1): m = .frsqrte; zeroForm = false
            case (1, 0b01100, 1): m = .fcmge; zeroForm = true
            case (1, 0b01101, 1): m = .fcmle; zeroForm = true
            default: return .undefined(at: address, encoding: encoding)
            }
            let operandMark = sink.mark
            sink.append(simdfpScalarOperand(Rd, size: elementSize))
            sink.append(simdfpScalarOperand(Rn, size: elementSize))
            if zeroForm {
                let fpKind: FloatImmediateKind = sz == 0 ? .single : .double
                sink.append(.floatImmediate(bits: 0, kind: fpKind))
            }
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: m,
                semanticReads: simdfpInsertingVector(Rn, into: .empty),
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operandCount: sink.count(since: operandMark),
            )
        }
        if U == 1, opcode == 0b10110 {
            guard size == 0b01 else { return .undefined(at: address, encoding: encoding) }
            return DecodedDraft(
                address: address, encoding: encoding, mnemonic: .fcvtxn,
                semanticReads: simdfpInsertingVector(Rn, into: .empty),
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operandCount: sink.emit(simdfpScalarOperand(Rd, size: .s), simdfpScalarOperand(Rn, size: .d)),
            )
        }

        let m: Mnemonic
        let zeroForm: Bool
        switch (U, opcode) {
        case (0, 0b00011): m = .suqadd; zeroForm = false
        case (0, 0b00111): m = .sqabs; zeroForm = false
        case (0, 0b01000): m = .cmgt; zeroForm = true
        case (0, 0b01001): m = .cmeq; zeroForm = true
        case (0, 0b01010): m = .cmlt; zeroForm = true
        case (0, 0b01011): m = .abs; zeroForm = false
        case (0, 0b10100): m = .sqxtn; zeroForm = false
        case (1, 0b00011): m = .usqadd; zeroForm = false
        case (1, 0b00111): m = .sqneg; zeroForm = false
        case (1, 0b01000): m = .cmge; zeroForm = true
        case (1, 0b01001): m = .cmle; zeroForm = true
        case (1, 0b01011): m = .neg; zeroForm = false
        case (1, 0b10010): m = .sqxtun; zeroForm = false
        case (1, 0b10100): m = .uqxtn; zeroForm = false
        default: return .undefined(at: address, encoding: encoding)
        }
        let operandMark = sink.mark
        switch m {
        case .sqxtn, .sqxtun, .uqxtn:
            guard size != 0b11 else { return .undefined(at: address, encoding: encoding) }
            sink.append(simdfpScalarOperand(Rd, size: scalarElementFromSize(size)))
            sink.append(simdfpScalarOperand(Rn, size: scalarElementFromSize(size + 1)))
        case .cmgt, .cmeq, .cmlt, .cmge, .cmle, .abs, .neg:
            guard size == 0b11 else { return .undefined(at: address, encoding: encoding) }
            sink.append(simdfpScalarOperand(Rd, size: .d))
            sink.append(simdfpScalarOperand(Rn, size: .d))
        default:
            let elementSize = scalarElementFromSize(size)
            sink.append(simdfpScalarOperand(Rd, size: elementSize))
            sink.append(simdfpScalarOperand(Rn, size: elementSize))
        }
        if zeroForm {
            sink.append(.unsignedImmediate(value: 0, width: 1))
        }
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: m,
            semanticReads: simdfpInsertingVector(Rn, into: .empty),
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.count(since: operandMark),
        )
    }

    /// Scalar FP16 two-register miscellaneous (.h).
    static func decodeFP16(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (encoding >> 22) & 1 == 0 { return .undefined(at: address, encoding: encoding) }
        let U = UInt8((encoding >> 29) & 1)
        let altBit = UInt8((encoding >> 23) & 1)
        let opcode = UInt8((encoding >> 12) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)
        let m: Mnemonic
        switch (U, opcode, altBit) {
        case (0, 0b11010, 0): m = .fcvtns
        case (0, 0b11011, 0): m = .fcvtms
        case (0, 0b11100, 0): m = .fcvtas
        case (0, 0b11101, 0): m = .scvtf
        case (0, 0b01100, 1): m = .fcmgt
        case (0, 0b01101, 1): m = .fcmeq
        case (0, 0b01110, 1): m = .fcmlt
        case (0, 0b11010, 1): m = .fcvtps
        case (0, 0b11011, 1): m = .fcvtzs
        case (0, 0b11101, 1): m = .frecpe
        case (0, 0b11111, 1): m = .frecpx
        case (1, 0b11010, 0): m = .fcvtnu
        case (1, 0b11011, 0): m = .fcvtmu
        case (1, 0b11100, 0): m = .fcvtau
        case (1, 0b11101, 0): m = .ucvtf
        case (1, 0b01100, 1): m = .fcmge
        case (1, 0b01101, 1): m = .fcmle
        case (1, 0b11010, 1): m = .fcvtpu
        case (1, 0b11011, 1): m = .fcvtzu
        case (1, 0b11101, 1): m = .frsqrte
        default: return .undefined(at: address, encoding: encoding)
        }
        let zeroForm = switch m {
        case .fcmgt, .fcmeq, .fcmlt, .fcmge, .fcmle: true
        default: false
        }
        let operandMark = sink.mark
        _ = sink.emit(simdfpScalarOperand(Rd, size: .h), simdfpScalarOperand(Rn, size: .h))
        if zeroForm { sink.append(.floatImmediate(bits: 0, kind: .half)) }
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: m,
            semanticReads: simdfpInsertingVector(Rn, into: .empty),
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.count(since: operandMark),
        )
    }
}
