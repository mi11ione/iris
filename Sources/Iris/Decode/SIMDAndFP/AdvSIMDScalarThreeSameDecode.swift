// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// AdvSIMD scalar three-same per ARM ARM § C4.1.96.16
// (+ .12 extra + .10 FP16 merged). Encoding:
// `0 1 U 1 1110 size 1 Rm opcode 1 Rn Rd`. Bit[30] = 1 marks the scalar
// form (vs vector's bit[30] = Q). The operand triple is scalar registers
// at the size-determined width (B/H/S/D).

enum AdvSIMDScalarThreeSameDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let U = UInt8((encoding >> 29) & 0x1)
        let size = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let opcode = UInt8((encoding >> 11) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        if opcode >= 0b11000 {
            return decodeFPFamily(
                encoding: encoding, address: address,
                U: U, size: size, opcode: opcode, Rm: Rm, Rn: Rn, Rd: Rd,
            )
        }
        return decodeIntFamily(
            encoding: encoding, address: address,
            U: U, size: size, opcode: opcode, Rm: Rm, Rn: Rn, Rd: Rd,
        )
    }

    @inline(__always)
    @_optimize(speed)
    private static func decodeIntFamily(
        encoding: UInt32, address: UInt64,
        U: UInt8, size: UInt8, opcode: UInt8,
        Rm: UInt8, Rn: UInt8, Rd: UInt8,
    ) -> DecodedDraft {
        // Scalar three-same only operates on D-element typically (size=11);
        // some ops (SQADD/SQSUB/etc.) accept all element sizes B/H/S/D.
        let elementSize = scalarElementFromSize(size)
        let m: Mnemonic
        switch (U, opcode) {
        case (0, 0b00001): m = .sqadd
        case (0, 0b00101): m = .sqsub
        case (0, 0b00110): m = .cmgt
        case (0, 0b00111): m = .cmge
        case (0, 0b01000): m = .sshl
        case (0, 0b01001): m = .sqshl
        case (0, 0b01010): m = .srshl
        case (0, 0b01011): m = .sqrshl
        case (0, 0b10000): m = .add
        case (0, 0b10001): m = .cmtst
        case (0, 0b10110): m = .sqdmulh
        case (1, 0b00001): m = .uqadd
        case (1, 0b00101): m = .uqsub
        case (1, 0b00110): m = .cmhi
        case (1, 0b00111): m = .cmhs
        case (1, 0b01000): m = .ushl
        case (1, 0b01001): m = .uqshl
        case (1, 0b01010): m = .urshl
        case (1, 0b01011): m = .uqrshl
        case (1, 0b10000): m = .sub
        case (1, 0b10001): m = .cmeq
        case (1, 0b10110): m = .sqrdmulh
        default: return .undefined(at: address, encoding: encoding)
        }
        // Scalar three-same size validity: comparison/shift/add ops are
        // D-element only; SQDMULH/SQRDMULH are H/S only; the saturating
        // add/sub/shift ops accept all element sizes.
        let sizeOK: Bool = switch opcode {
        case 0b00110, 0b00111, 0b01000, 0b01010, 0b10000, 0b10001:
            size == 0b11
        case 0b10110:
            size == 0b01 || size == 0b10
        default:
            true
        }
        guard sizeOK else { return .undefined(at: address, encoding: encoding) }
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(Rm, into: reads)
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: m,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operands: [
                simdfpScalarOperand(Rd, size: elementSize),
                simdfpScalarOperand(Rn, size: elementSize),
                simdfpScalarOperand(Rm, size: elementSize),
            ],
        )
    }

    @inline(__always)
    @_optimize(speed)
    private static func decodeFPFamily(
        encoding: UInt32, address: UInt64,
        U: UInt8, size: UInt8, opcode: UInt8,
        Rm: UInt8, Rn: UInt8, Rd: UInt8,
    ) -> DecodedDraft {
        let sz = size & 1
        let altBit = (size >> 1) & 1
        let elementSize: ScalarSize = sz == 0 ? .s : .d
        let m: Mnemonic
        switch (U, opcode, altBit) {
        case (0, 0b11011, 0): m = .fmulx
        case (0, 0b11100, 0): m = .fcmeq
        case (0, 0b11111, 0): m = .frecps
        case (0, 0b11111, 1): m = .frsqrts
        case (1, 0b11100, 0): m = .fcmge
        case (1, 0b11100, 1): m = .fcmgt
        case (1, 0b11101, 0): m = .facge
        case (1, 0b11101, 1): m = .facgt
        case (1, 0b11010, 1): m = .fabd
        default: return .undefined(at: address, encoding: encoding)
        }
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(Rm, into: reads)
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: m,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operands: [
                simdfpScalarOperand(Rd, size: elementSize),
                simdfpScalarOperand(Rn, size: elementSize),
                simdfpScalarOperand(Rm, size: elementSize),
            ],
        )
    }
}

/// Map a 2-bit `size` field to the corresponding scalar element size
/// (B/H/S/D). Total over the 2-bit input space.
@inline(__always)
@_effects(readonly)
func scalarElementFromSize(_ size: UInt8) -> ScalarSize {
    scalarElementTable[Int(size & 0x3)]
}

private let scalarElementTable: [ScalarSize] = [.b, .h, .s, .d]
