// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Scalar SIMD LDP/STP/LDNP/STNP (V=1).
// Encoding: `opc 10 1 V 0 indexing 1 ... Rt2 Rn Rt` with V=1. opc
// selects the scalar element width (00=S, 01=D, 10=Q); indexing
// (bits[24:23]) selects no-allocate (00), post-index (01), signed-
// offset (10), pre-index (11). The signed imm7 displacement is scaled
// by elementBytes.

enum ScalarSIMDLoadStorePairDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let opc = UInt8((encoding >> 30) & 0x3)
        let indexing = UInt8((encoding >> 23) & 0x3)
        let L = UInt8((encoding >> 22) & 0x1)
        let imm7 = UInt32((encoding >> 15) & 0x7F)
        let Rt2 = UInt8((encoding >> 10) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        // opc → (element, scale). opc=11 is the FEAT_LSUI unprivileged
        // T-pair (Q-register only); 10 is the regular Q pair — both Q/scale-16.
        let isUnpriv = opc == 0b11
        let elementSize: ScalarSize
        let scale: Int64
        switch opc {
        case 0b00: elementSize = .s; scale = 4
        case 0b01: elementSize = .d; scale = 8
        default: elementSize = .q; scale = 16
        }

        let mnemonic: Mnemonic
        let writeback: Writeback
        let isLoad = L == 1
        switch (indexing, isLoad) {
        case (0b00, true): mnemonic = isUnpriv ? .ldtnp : .ldnp; writeback = .none
        case (0b00, false): mnemonic = isUnpriv ? .sttnp : .stnp; writeback = .none
        case (0b01, true): mnemonic = isUnpriv ? .ldtp : .ldp; writeback = .postIndex
        case (0b01, false): mnemonic = isUnpriv ? .sttp : .stp; writeback = .postIndex
        case (0b10, true): mnemonic = isUnpriv ? .ldtp : .ldp; writeback = .none
        case (0b10, false): mnemonic = isUnpriv ? .sttp : .stp; writeback = .none
        case (0b11, true): mnemonic = isUnpriv ? .ldtp : .ldp; writeback = .preIndex
        default: // (indexing, isLoad) = (0b11, false) — only remaining combination.
            mnemonic = isUnpriv ? .sttp : .stp; writeback = .preIndex
        }

        let displacement = lsSignExtendImm7Local(imm7) * scale
        let rnRef = simdfpGprOperand(encoding: Rn, width: .x64, spOrGeneral: true)
        let memOperand = MemoryOperand(
            base: .register(rnRef), index: nil,
            displacement: displacement,
            extend: .none, shift: 0, writeback: writeback,
        )

        let vt = simdfpScalarOperand(Rt, size: elementSize)
        let vt2 = simdfpScalarOperand(Rt2, size: elementSize)

        var reads = simdfpInsertingNonZeroGPR(reg: rnRef, into: .empty)
        var writes: RegisterSet = .empty
        if isLoad {
            writes = simdfpInsertingVector(Rt, into: writes)
            writes = simdfpInsertingVector(Rt2, into: writes)
        } else {
            reads = simdfpInsertingVector(Rt, into: reads)
            reads = simdfpInsertingVector(Rt2, into: reads)
        }
        if writeback != .none {
            writes = simdfpInsertingNonZeroGPR(reg: rnRef, into: writes)
        }

        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            branchClass: .none,
            memoryAccess: isLoad ? .load : .store,
            memoryOrdering: [], flagEffect: .none, category: .simdAndFP,
            operands: [vt, vt2, .memory(memOperand)],
        )
    }
}

/// Local imm7 sign-extender.
@inline(__always)
@_effects(readonly)
func lsSignExtendImm7Local(_ imm7: UInt32) -> Int64 {
    let mask: UInt32 = 0x7F
    let value = imm7 & mask
    let signBit = (value >> 6) & 1
    if signBit == 1 {
        return Int64(bitPattern: UInt64(value) | ~UInt64(mask))
    }
    return Int64(value)
}
