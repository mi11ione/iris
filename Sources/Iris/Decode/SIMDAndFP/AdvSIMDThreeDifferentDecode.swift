// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// AdvSIMD vector three-different: `0 Q U 0 1110 size 1 Rm opcode 00 Rn Rd`.
// opcode (bits[15:12]) + U select the variant; Q selects the upper-half
// "2" form. The class has three operand shapes, NOT one:
//   - lengthening: Rd is 2x-wide, Rn/Rm are narrow   (SADDL, SMULL, …)
//   - widening:    Rd & Rn are wide, Rm is narrow     (SADDW/SSUBW/U…)
//   - narrowing:   Rd is narrow, Rn/Rm are wide       (ADDHN/SUBHN/R…)
// Per-op size validity also differs: most allow size 8/16/32; SQDM* are
// 16/32 only; PMULL's generic table row is 8-bit only — its poly64 form
// (size=11, `.1q` ← `.1d`/`.2d`, FEAT_PMULL64) is decoded by a dedicated
// branch ahead of the table. size=11 is otherwise reserved.

enum AdvSIMDThreeDifferentDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let U = UInt8((encoding >> 29) & 0x1)
        let size = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let opcode = UInt8((encoding >> 12) & 0xF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        // FEAT_PMULL64: pmull/pmull2 .1q ← .1d (Q=0) / .2d (Q=1) (size=11).
        if U == 0, opcode == 0b1110, size == 0b11 {
            var reads = simdfpInsertingVector(Rn, into: .empty)
            reads = simdfpInsertingVector(Rm, into: reads)
            let src: VectorArrangement = Q == 1 ? .d2 : .d1
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: Q == 1 ? .pmull2 : .pmull,
                semanticReads: reads,
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operands: [
                    simdfpVectorOperand(Rd, arrangement: .q1),
                    simdfpVectorOperand(Rn, arrangement: src),
                    simdfpVectorOperand(Rm, arrangement: src),
                ],
            )
        }

        guard let op = diffOp(U: U, opcode: opcode) else {
            return .undefined(at: address, encoding: encoding)
        }
        // Per-op size validity (size==3 is never valid for these forms).
        guard size < 3, (op.sizeMask >> size) & 1 == 1 else {
            return .undefined(at: address, encoding: encoding)
        }

        let wide = wideArrangement(size: size)
        let narrow = narrowArrangement(size: size, Q: Q)
        let (dst, srcN, srcM): (VectorArrangement, VectorArrangement, VectorArrangement) = switch op.shape {
        case .lengthening: (wide, narrow, narrow)
        case .widening: (wide, wide, narrow)
        case .narrowing: (narrow, wide, wide)
        }
        let m = Q == 1 ? op.two : op.base

        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(Rm, into: reads)
        if SIMDFPSemanticAttributes.destinationReadsItself(for: m) {
            reads = simdfpInsertingVector(Rd, into: reads)
        }

        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: m,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operands: [
                simdfpVectorOperand(Rd, arrangement: dst),
                simdfpVectorOperand(Rn, arrangement: srcN),
                simdfpVectorOperand(Rm, arrangement: srcM),
            ],
        )
    }

    private enum DiffShape { case lengthening, widening, narrowing }
    private struct DiffOp {
        let base: Mnemonic
        let two: Mnemonic
        let shape: DiffShape
        /// Bit i set ⇒ size==i valid (i ∈ {0,1,2}).
        let sizeMask: UInt8
    }

    /// Map (U, opcode) → operation. Reserved combinations return nil.
    @inline(__always)
    @_effects(readonly)
    private static func diffOp(U: UInt8, opcode: UInt8) -> DiffOp? {
        let all: UInt8 = 0b111 // sizes 8/16/32
        let hs: UInt8 = 0b110 // sizes 16/32 (SQDM* doubling)
        switch (U, opcode) {
        case (0, 0b0000): return DiffOp(base: .saddl, two: .saddl2, shape: .lengthening, sizeMask: all)
        case (0, 0b0001): return DiffOp(base: .saddw, two: .saddw2, shape: .widening, sizeMask: all)
        case (0, 0b0010): return DiffOp(base: .ssubl, two: .ssubl2, shape: .lengthening, sizeMask: all)
        case (0, 0b0011): return DiffOp(base: .ssubw, two: .ssubw2, shape: .widening, sizeMask: all)
        case (0, 0b0100): return DiffOp(base: .addhn, two: .addhn2, shape: .narrowing, sizeMask: all)
        case (0, 0b0101): return DiffOp(base: .sabal, two: .sabal2, shape: .lengthening, sizeMask: all)
        case (0, 0b0110): return DiffOp(base: .subhn, two: .subhn2, shape: .narrowing, sizeMask: all)
        case (0, 0b0111): return DiffOp(base: .sabdl, two: .sabdl2, shape: .lengthening, sizeMask: all)
        case (0, 0b1000): return DiffOp(base: .smlal, two: .smlal2, shape: .lengthening, sizeMask: all)
        case (0, 0b1001): return DiffOp(base: .sqdmlal, two: .sqdmlal2, shape: .lengthening, sizeMask: hs)
        case (0, 0b1010): return DiffOp(base: .smlsl, two: .smlsl2, shape: .lengthening, sizeMask: all)
        case (0, 0b1011): return DiffOp(base: .sqdmlsl, two: .sqdmlsl2, shape: .lengthening, sizeMask: hs)
        case (0, 0b1100): return DiffOp(base: .smull, two: .smull2, shape: .lengthening, sizeMask: all)
        case (0, 0b1101): return DiffOp(base: .sqdmull, two: .sqdmull2, shape: .lengthening, sizeMask: hs)
        case (0, 0b1110): return DiffOp(base: .pmull, two: .pmull2, shape: .lengthening, sizeMask: 0b001)
        case (1, 0b0000): return DiffOp(base: .uaddl, two: .uaddl2, shape: .lengthening, sizeMask: all)
        case (1, 0b0001): return DiffOp(base: .uaddw, two: .uaddw2, shape: .widening, sizeMask: all)
        case (1, 0b0010): return DiffOp(base: .usubl, two: .usubl2, shape: .lengthening, sizeMask: all)
        case (1, 0b0011): return DiffOp(base: .usubw, two: .usubw2, shape: .widening, sizeMask: all)
        case (1, 0b0100): return DiffOp(base: .raddhn, two: .raddhn2, shape: .narrowing, sizeMask: all)
        case (1, 0b0101): return DiffOp(base: .uabal, two: .uabal2, shape: .lengthening, sizeMask: all)
        case (1, 0b0110): return DiffOp(base: .rsubhn, two: .rsubhn2, shape: .narrowing, sizeMask: all)
        case (1, 0b0111): return DiffOp(base: .uabdl, two: .uabdl2, shape: .lengthening, sizeMask: all)
        case (1, 0b1000): return DiffOp(base: .umlal, two: .umlal2, shape: .lengthening, sizeMask: all)
        case (1, 0b1010): return DiffOp(base: .umlsl, two: .umlsl2, shape: .lengthening, sizeMask: all)
        case (1, 0b1100): return DiffOp(base: .umull, two: .umull2, shape: .lengthening, sizeMask: all)
        default: return nil
        }
    }

    /// The wide (2x) arrangement: 128-bit, 2-byte/4-byte/8-byte elements.
    @inline(__always)
    @_effects(readonly)
    private static func wideArrangement(size: UInt8) -> VectorArrangement {
        switch size {
        case 0b00: .h8
        case 0b01: .s4
        default: .d2
        }
    }

    /// The narrow arrangement: 64-bit low half (Q=0) or 128-bit upper half
    /// (Q=1, the "2" form).
    @inline(__always)
    @_effects(readonly)
    private static func narrowArrangement(size: UInt8, Q: UInt8) -> VectorArrangement {
        switch (size, Q) {
        case (0b00, 0): .b8
        case (0b00, 1): .b16
        case (0b01, 0): .h4
        case (0b01, 1): .h8
        case (0b10, 0): .s2
        default: .s4
        }
    }
}
