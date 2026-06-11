// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Scalar SIMD LD/STR (unsigned-offset, V=1).
// Encoding: `size 11 1 1 0 1 V 01 opc 0 imm12 Rn Rt` with V=1. (size,
// opc) selects the destination element width B/H/S/D/Q. imm12 is the
// scaled unsigned 12-bit offset (× elementBytes).

enum ScalarSIMDLoadStoreUnsignedOffsetDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let size = UInt8((encoding >> 30) & 0x3)
        let opc = UInt8((encoding >> 22) & 0x3)
        let imm12 = UInt32((encoding >> 10) & 0xFFF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        // (size, opc) → (elementSize, mnemonic-is-load).
        guard let (elementSize, isLoad) = mapSizeOpc(size: size, opc: opc) else {
            return .undefined(at: address, encoding: encoding)
        }
        let scale = UInt64(elementSize.byteWidth)
        let displacement = Int64(UInt64(imm12) * scale)
        let rnRef = simdfpGprOperand(encoding: Rn, width: .x64, spOrGeneral: true)
        let memOperand = MemoryOperand(
            base: .register(rnRef), index: nil,
            displacement: displacement,
            extend: .none, shift: 0, writeback: .none,
        )

        let vt = simdfpScalarOperand(Rt, size: elementSize)
        let mnemonic: Mnemonic = isLoad ? .ldr : .str
        var reads = simdfpInsertingNonZeroGPR(reg: rnRef, into: .empty)
        var writes: RegisterSet = .empty
        if isLoad {
            writes = simdfpInsertingVector(Rt, into: writes)
        } else {
            reads = simdfpInsertingVector(Rt, into: reads)
        }
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            branchClass: .none,
            memoryAccess: isLoad ? .load : .store,
            memoryOrdering: [], flagEffect: .none, category: .simdAndFP,
            operands: [vt, .memory(memOperand)],
        )
    }

    @inline(__always)
    @_effects(readonly)
    private static func mapSizeOpc(size: UInt8, opc: UInt8) -> (ScalarSize, Bool)? {
        // (size, opc) → (element, isLoad). Q-form lives at size=00 opc=10/11.
        switch (size, opc) {
        case (0b00, 0b00): (.b, false)
        case (0b00, 0b01): (.b, true)
        case (0b00, 0b10): (.q, false) // STR Q
        case (0b00, 0b11): (.q, true) // LDR Q
        case (0b01, 0b00): (.h, false)
        case (0b01, 0b01): (.h, true)
        case (0b10, 0b00): (.s, false)
        case (0b10, 0b01): (.s, true)
        case (0b11, 0b00): (.d, false)
        case (0b11, 0b01): (.d, true)
        default: nil
        }
    }
}
