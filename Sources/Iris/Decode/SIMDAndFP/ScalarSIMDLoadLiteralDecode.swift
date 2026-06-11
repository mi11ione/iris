// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Scalar SIMD LDR-literal (PC-relative, V=1).
// Encoding: `opc 0 11 1 V 00 imm19 Rt` with V=1. opc selects the
// destination element width (00=S, 01=D, 10=Q; 11 reserved).

enum ScalarSIMDLoadLiteralDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let opc = UInt8((encoding >> 30) & 0x3)
        let imm19 = UInt32((encoding >> 5) & 0x7FFFF)
        let Rt = UInt8(encoding & 0x1F)

        let elementSize: ScalarSize
        switch opc {
        case 0b00: elementSize = .s
        case 0b01: elementSize = .d
        case 0b10: elementSize = .q
        default: return .undefined(at: address, encoding: encoding)
        }
        let displacement = lsSignExtendImm19Local(imm19) * 4
        let memOperand = MemoryOperand(
            base: .pc, index: nil,
            displacement: displacement,
            extend: .none, shift: 0, writeback: .none,
        )
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: .ldr,
            semanticReads: .empty,
            semanticWrites: simdfpInsertingVector(Rt, into: .empty),
            branchClass: .none,
            memoryAccess: .load,
            memoryOrdering: [], flagEffect: .none, category: .simdAndFP,
            operands: [simdfpScalarOperand(Rt, size: elementSize), .memory(memOperand)],
        )
    }
}

/// Local imm19 sign-extender.
@inline(__always)
@_effects(readonly)
func lsSignExtendImm19Local(_ imm19: UInt32) -> Int64 {
    let mask: UInt32 = 0x7FFFF
    let value = imm19 & mask
    let signBit = (value >> 18) & 1
    if signBit == 1 {
        return Int64(bitPattern: UInt64(value) | ~UInt64(mask))
    }
    return Int64(value)
}
