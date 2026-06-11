// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// AdvSIMD scalar two-reg-misc per
// ARM ARM § C4.1.96.13 + .11 FP16 merged. Encoding:
// `0 1 U 1 1110 size 10000 opcode 10 Rn Rd`. Covers SUQADD/SQABS/CMGT0/
// CMEQ0/CMLT0/ABS/SQXTN/USQADD/CMGE0/CMLE0/SQNEG/SQXTUN/UQXTN plus FP
// family (FRINT*/FCVT*/FCMxx0/FRECPE/FRSQRTE/FRECPX/FSQRT scalar).

enum AdvSIMDScalarTwoRegMiscDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let U = UInt8((encoding >> 29) & 0x1)
        let size = UInt8((encoding >> 22) & 0x3)
        let opcode = UInt8((encoding >> 12) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        // FP-family scalar two-reg-misc covers opcodes 11000..11111 always,
        // plus 01100..01110 (FCMxx-zero) when bit[23] = 1 (the FP-family
        // marker within size). The fpFamilyBit23 must be 1 for the
        // FCMxx-zero forms because their integer-tier opcode equivalents
        // would conflict (and the integer-tier has no scalar mapping at
        // those opcodes — see source FCMxx-zero is FP only).
        let bit23 = (size >> 1) & 1
        if opcode >= 0b11000 || (opcode >= 0b01100 && opcode <= 0b01110 && bit23 == 1) {
            // FP-family scalar two-reg-misc.
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
            // FRECPE (scalar) per ARM ARM is U=0, opcode=11101, altBit=1.
            case (0, 0b11101, 1): m = .frecpe; zeroForm = false
            // FRECPX (scalar) per ARM ARM is U=0, opcode=11111, altBit=1.
            case (0, 0b11111, 1): m = .frecpx; zeroForm = false
            // FCMxx-zero scalar — altBit = 1 (FP marker).
            case (0, 0b01100, 1): m = .fcmgt; zeroForm = true
            case (0, 0b01101, 1): m = .fcmeq; zeroForm = true
            case (0, 0b01110, 1): m = .fcmlt; zeroForm = true
            case (1, 0b11010, 0): m = .fcvtnu; zeroForm = false
            case (1, 0b11010, 1): m = .fcvtpu; zeroForm = false
            case (1, 0b11011, 0): m = .fcvtmu; zeroForm = false
            case (1, 0b11011, 1): m = .fcvtzu; zeroForm = false
            case (1, 0b11100, 0): m = .fcvtau; zeroForm = false
            case (1, 0b11101, 0): m = .ucvtf; zeroForm = false
            // FRSQRTE (scalar) per ARM ARM is U=1, opcode=11101, altBit=1.
            case (1, 0b11101, 1): m = .frsqrte; zeroForm = false
            case (1, 0b01100, 1): m = .fcmge; zeroForm = true
            case (1, 0b01101, 1): m = .fcmle; zeroForm = true
            default: return .undefined(at: address, encoding: encoding)
            }
            var operands: [Operand] = []
            operands.append(simdfpScalarOperand(Rd, size: elementSize))
            operands.append(simdfpScalarOperand(Rn, size: elementSize))
            if zeroForm {
                let fpKind: FloatImmediateKind = sz == 0 ? .single : .double
                operands.append(.floatImmediate(bits: 0, kind: fpKind))
            }
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: m,
                semanticReads: simdfpInsertingVector(Rn, into: .empty),
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operands: operands,
            )
        }
        // FCVTXN (scalar): U=1, opcode=0b10110 — narrowing D→S FP convert.
        // It sits in the integer-opcode range but is an FP op with distinct
        // operand widths, so handle it before the integer family.
        if U == 1, opcode == 0b10110 {
            guard size == 0b01 else { return .undefined(at: address, encoding: encoding) }
            return DecodedDraft(
                address: address, encoding: encoding, mnemonic: .fcvtxn,
                semanticReads: simdfpInsertingVector(Rn, into: .empty),
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operands: [simdfpScalarOperand(Rd, size: .s), simdfpScalarOperand(Rn, size: .d)],
            )
        }

        // Integer-family scalar two-reg-misc.
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
        // Element-size validity + operand shapes differ by family:
        //  - narrowing (sqxtn/sqxtun/uqxtn): dst = size element (b/h/s),
        //    src = the 2x-wider element (h/s/d); size==11 reserved.
        //  - compare-zero / abs / neg: 64-bit (D) only.
        //  - saturating (suqadd/sqabs/sqneg/usqadd): all element sizes.
        var operands: [Operand] = []
        switch m {
        case .sqxtn, .sqxtun, .uqxtn:
            guard size != 0b11 else { return .undefined(at: address, encoding: encoding) }
            operands.append(simdfpScalarOperand(Rd, size: scalarElementFromSize(size)))
            operands.append(simdfpScalarOperand(Rn, size: scalarElementFromSize(size + 1)))
        case .cmgt, .cmeq, .cmlt, .cmge, .cmle, .abs, .neg:
            guard size == 0b11 else { return .undefined(at: address, encoding: encoding) }
            operands.append(simdfpScalarOperand(Rd, size: .d))
            operands.append(simdfpScalarOperand(Rn, size: .d))
        default:
            let elementSize = scalarElementFromSize(size)
            operands.append(simdfpScalarOperand(Rd, size: elementSize))
            operands.append(simdfpScalarOperand(Rn, size: elementSize))
        }
        if zeroForm {
            operands.append(.unsignedImmediate(value: 0, width: 1))
        }
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: m,
            semanticReads: simdfpInsertingVector(Rn, into: .empty),
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operands: operands,
        )
    }

    /// Scalar FP16 two-register miscellaneous (.h). bits[21:17]=11100,
    /// bit22=1; bit23=altBit. Scalar Hd/Hn operands; fcmxx-zero adds #0.0.
    static func decodeFP16(encoding: UInt32, address: UInt64) -> DecodedDraft {
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
        var operands: [Operand] = [
            simdfpScalarOperand(Rd, size: .h),
            simdfpScalarOperand(Rn, size: .h),
        ]
        if zeroForm { operands.append(.floatImmediate(bits: 0, kind: .half)) }
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: m,
            semanticReads: simdfpInsertingVector(Rn, into: .empty),
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operands: operands,
        )
    }
}
