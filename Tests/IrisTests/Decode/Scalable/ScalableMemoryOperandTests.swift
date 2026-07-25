// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates ScalableMemoryOperand — SVE addressing in both of its shapes:
/// contiguous (`[Xn, #imm, mul vl]`, `[Xn, Xm, lsl #k]`) and gather/scatter
/// (`[Xn, Zm.<T>, sxtw #scale]`, `[Zn.<T>, #imm]`). The operand records
/// structure only; computing the effective address is Piece 4's job, so every
/// field a consumer needs to do that must survive decode.
@Suite("ScalableMemoryOperand / contiguous and gather-scatter addressing")
struct ScalableMemoryOperandTests {
    @Test func contiguousGprBaseUsesTheDefaults() {
        let mem = ScalableMemoryOperand(base: .gpr(.x(1)))
        #expect(mem.base == .gpr(RegisterRef.x(1)))
        #expect(mem.index == nil)
        #expect(mem.scalarIndex == nil)
        #expect(mem.indexExtend == .none)
        #expect(mem.scaleShift == 0)
        #expect(mem.displacement == 0)
        #expect(!mem.mulVL)
    }

    @Test func aScalarIndexRecordsTheRegisterOffsetForm() {
        // `[Xn, Xm, lsl #k]` — the register-offset address carries `Xm` in
        // `scalarIndex`, distinct from the gather `Zm` vector index.
        let mem = ScalableMemoryOperand(base: .gpr(.x(3)), scalarIndex: .x(5), scaleShift: 2)
        #expect(mem.scalarIndex == RegisterRef.x(5))
        #expect(mem.index == nil)
        #expect(mem.scaleShift == 2)
    }

    @Test func aVectorBaseWithAScalarIndexIsTheQuadwordGatherForm() {
        // `[Zn.D, Xm]` — LD1Q / ST1Q and the vector-base non-temporal forms pair
        // a vector base with a scalar `Xm` index and no `Zm` vector index.
        let base = ScalableVectorRef(registerIndex: 2, element: .d)
        let mem = ScalableMemoryOperand(base: .vector(base), scalarIndex: .x(4))
        #expect(mem.base == .vector(base))
        #expect(mem.scalarIndex == RegisterRef.x(4))
        #expect(mem.index == nil)
    }

    @Test func anAddressCarriesAtMostOneOfScalarOrVectorIndex() {
        // The two index channels are disjoint by construction — a contiguous
        // register offset uses `scalarIndex`; a gather uses `index`.
        let contiguous = ScalableMemoryOperand(base: .gpr(.x(0)), scalarIndex: .x(1))
        #expect(contiguous.scalarIndex != nil)
        #expect(contiguous.index == nil)
        let gather = ScalableMemoryOperand(
            base: .gpr(.x(0)), index: ScalableVectorRef(registerIndex: 1, element: .s), indexExtend: .uxtw,
        )
        #expect(gather.index != nil)
        #expect(gather.scalarIndex == nil)
    }

    @Test func operandsDifferingOnlyInScalarIndexAreDistinct() {
        let withIndex = ScalableMemoryOperand(base: .gpr(.x(0)), scalarIndex: .x(2))
        let without = ScalableMemoryOperand(base: .gpr(.x(0)))
        #expect(withIndex != without)
    }

    @Test func mulVLAddressingMarksItsVectorLengthScaling() {
        // `[Xn, #imm, mul vl]` — the displacement is in vector-length units,
        // not bytes, so the flag is what tells a consumer how to scale it.
        let mem = ScalableMemoryOperand(base: .gpr(.x(3)), displacement: -8, mulVL: true)
        #expect(mem.mulVL)
        #expect(mem.displacement == -8)
    }

    @Test func displacementCarriesTheSignedMulVLRange() {
        // The mul-vl immediate range is -32...31; Int32 covers it with room.
        for displacement: Int32 in [-32, -1, 0, 1, 31] {
            let mem = ScalableMemoryOperand(base: .gpr(.x(0)), displacement: displacement, mulVL: true)
            #expect(mem.displacement == displacement)
        }
    }

    @Test func displacementCarriesWideByteOffsetsBothWays() {
        #expect(ScalableMemoryOperand(base: .gpr(.sp()), displacement: Int32.min).displacement == Int32.min)
        #expect(ScalableMemoryOperand(base: .gpr(.sp()), displacement: Int32.max).displacement == Int32.max)
    }

    @Test func stackPointerBaseIsRepresentable() {
        let mem = ScalableMemoryOperand(base: .gpr(.sp()))
        #expect(mem.base == .gpr(RegisterRef.sp()))
    }

    @Test func gatherWithGprBaseAndVectorIndexCarriesExtendAndScale() {
        // `[X1, Z2.S, sxtw #2]` — a 32-bit-index gather.
        let index = ScalableVectorRef(registerIndex: 2, element: .s)
        let mem = ScalableMemoryOperand(
            base: .gpr(.x(1)), index: index, indexExtend: .sxtw, scaleShift: 2,
        )
        #expect(mem.base == .gpr(RegisterRef.x(1)))
        #expect(mem.index == index)
        #expect(mem.indexExtend == .sxtw)
        #expect(mem.scaleShift == 2)
    }

    @Test func unscaledUnsignedGatherIsRepresentable() {
        let mem = ScalableMemoryOperand(
            base: .gpr(.x(4)), index: ScalableVectorRef(registerIndex: 5, element: .d),
            indexExtend: .uxtw, scaleShift: 0,
        )
        #expect(mem.indexExtend == .uxtw)
        #expect(mem.scaleShift == 0)
    }

    @Test func lslScaledSixtyFourBitGatherIsRepresentable() {
        let mem = ScalableMemoryOperand(
            base: .gpr(.x(6)), index: ScalableVectorRef(registerIndex: 7, element: .d),
            indexExtend: .lsl, scaleShift: 3,
        )
        #expect(mem.indexExtend == .lsl)
        #expect(mem.scaleShift == 3)
    }

    @Test func vectorBaseWithImmediateIsRepresentable() {
        // `[Z0.D, #16]` — the vector-plus-immediate gather form.
        let base = ScalableVectorRef(registerIndex: 0, element: .d)
        let mem = ScalableMemoryOperand(base: .vector(base), displacement: 16)
        #expect(mem.base == .vector(base))
        #expect(mem.index == nil)
        #expect(mem.displacement == 16)
    }

    @Test func gprAndVectorBasesAreDistinct() {
        let gprBased = ScalableMemoryOperand(base: .gpr(.x(0)))
        let vectorBased = ScalableMemoryOperand(base: .vector(ScalableVectorRef(registerIndex: 0)))
        #expect(gprBased != vectorBased)
    }

    @Test func baseAndIndexResolveToTheirSemanticReads() {
        // A gather reads the GPR base and the Z index: the base lands in the
        // GPR half of the mask, the index on the shared SIMD/Z bit.
        let index = ScalableVectorRef(registerIndex: 9, element: .d)
        let mem = ScalableMemoryOperand(base: .gpr(.x(2)), index: index, indexExtend: .lsl, scaleShift: 3)
        var reads = RegisterSet.empty
        if case let .gpr(register) = mem.base {
            reads = reads.inserting(register)
        }
        if let vectorIndex = mem.index {
            reads = reads.inserting(vectorIndex)
        }
        #expect(reads.contains(RegisterRef.x(2)))
        #expect(reads.contains(RegisterRef.simd(9)))
        #expect(reads.count == 2)
    }

    @Test func vectorBaseResolvesToASimdRead() {
        let mem = ScalableMemoryOperand(base: .vector(ScalableVectorRef(registerIndex: 4, element: .d)))
        var reads = RegisterSet.empty
        if case let .vector(vector) = mem.base {
            reads = reads.inserting(vector)
        }
        #expect(reads.contains(RegisterRef.simd(4)))
        #expect(reads.count == 1)
    }

    @Test func equalOperandsHashEqual() {
        let index = ScalableVectorRef(registerIndex: 1, element: .s)
        let a = ScalableMemoryOperand(base: .gpr(.x(0)), index: index, indexExtend: .sxtw, scaleShift: 1)
        let b = ScalableMemoryOperand(base: .gpr(.x(0)), index: index, indexExtend: .sxtw, scaleShift: 1)
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }

    @Test func equalBasesHashEqual() {
        let a = ScalableMemoryOperand.Base.gpr(.x(7))
        let b = ScalableMemoryOperand.Base.gpr(.x(7))
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }
}
