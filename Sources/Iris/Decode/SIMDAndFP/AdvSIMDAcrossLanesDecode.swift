// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// AdvSIMD across-lanes per ARM ARM § C4.1.96.27.
// Encoding: `0 Q U 0 1110 size 11000 opcode 10 Rn Rd`. opcode (bits
// [16:12]) selects ADDV/SMAXV/SMINV/SADDLV/UADDLV/UMAXV/UMINV/
// FMAXNMV/FMAXV/FMINNMV/FMINV. Result is a single scalar (size-
// dependent: B/H/S/D); source is a vector.

enum AdvSIMDAcrossLanesDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let U = UInt8((encoding >> 29) & 0x1)
        let size = UInt8((encoding >> 22) & 0x3)
        let opcode = UInt8((encoding >> 12) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        // FP across-lanes reductions (FMAXNMV/FMAXV/FMINNMV/FMINV). opcode
        // 01100 (NM) / 01111; bit23 selects max(0)/min(1); U selects FP32
        // (.s ← .4s, Q=1 only) vs FP16 (.h ← .4h/.8h). bit22 is SBZ.
        if opcode == 0b01100 || opcode == 0b01111 {
            if size & 1 != 0 { return .undefined(at: address, encoding: encoding) }
            let isMin = (size >> 1) & 1 == 1
            let nm = opcode == 0b01100
            let m: Mnemonic = isMin
                ? (nm ? .fminnmv : .fminv)
                : (nm ? .fmaxnmv : .fmaxv)
            let resultSize: ScalarSize
            let srcArr: VectorArrangement
            if U == 1 {
                if Q != 1 { return .undefined(at: address, encoding: encoding) }
                resultSize = .s
                srcArr = .s4
            } else {
                resultSize = .h
                srcArr = Q == 1 ? .h8 : .h4
            }
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: m,
                semanticReads: simdfpInsertingVector(Rn, into: .empty),
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operands: [
                    simdfpScalarOperand(Rd, size: resultSize),
                    simdfpVectorOperand(Rn, arrangement: srcArr),
                ],
            )
        }

        let srcArrangement = arrangementFromSizeQ(size: size, Q: Q)
        // 1D and 2D and (B8) cannot be sensibly reduced across lanes:
        // 1D and (2S, Q=0) are excluded by ARM ARM table at this class.
        if srcArrangement == .d1 || srcArrangement == .d2 || srcArrangement == .s2 {
            return .undefined(at: address, encoding: encoding)
        }

        let mnemonic: Mnemonic
        let resultSize: ScalarSize
        // FP across-lanes: opcode=01100 (FMAXNM), 01111 (FMAX), 01100/11100 etc.
        // Integer: opcode=00011 (SADDLV/UADDLV), 01010 (SMAXV/UMAXV), 11010 (SMINV/UMINV), 11011 (ADDV).
        // FP family uses size=00/01 with bit selection — per ARM ARM the
        // FP across-lanes uses bit[23:22] as the precision selector.
        // Simplification: enumerate the integer opcodes; defer FP
        // across-lanes to a sibling check (returns UNDEFINED for unknowns).
        switch (U, opcode) {
        case (0, 0b00011):
            mnemonic = .saddlv
            // SADDLV result is one element wider than source.
            resultSize = widenSize(elementSize(srcArrangement))
        case (1, 0b00011):
            mnemonic = .uaddlv
            resultSize = widenSize(elementSize(srcArrangement))
        case (0, 0b01010): mnemonic = .smaxv; resultSize = elementSize(srcArrangement)
        case (1, 0b01010): mnemonic = .umaxv; resultSize = elementSize(srcArrangement)
        case (0, 0b11010): mnemonic = .sminv; resultSize = elementSize(srcArrangement)
        case (1, 0b11010): mnemonic = .uminv; resultSize = elementSize(srcArrangement)
        case (0, 0b11011): mnemonic = .addv; resultSize = elementSize(srcArrangement)
        default:
            return .undefined(at: address, encoding: encoding)
        }

        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: simdfpInsertingVector(Rn, into: .empty),
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operands: [
                simdfpScalarOperand(Rd, size: resultSize),
                simdfpVectorOperand(Rn, arrangement: srcArrangement),
            ],
        )
    }

    @inline(__always)
    @_effects(readonly)
    private static func elementSize(_ a: VectorArrangement) -> ScalarSize {
        a.elementSize
    }

    @inline(__always)
    @_effects(readonly)
    private static func widenSize(_ s: ScalarSize) -> ScalarSize {
        switch s {
        case .b: .h
        case .h: .s
        // .s widens to .d. .d and .q never reach here (across-lanes
        // gates D/Q source via the srcArrangement check upstream); the
        // default is therefore the .s case with sentinel fall-through.
        default: .d
        }
    }
}
