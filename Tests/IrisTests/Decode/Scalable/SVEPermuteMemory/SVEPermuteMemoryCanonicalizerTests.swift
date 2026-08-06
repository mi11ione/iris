// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func render(mnemonic: Mnemonic, operands: [Operand]) -> String {
    Instruction(address: 0, encoding: 0x8400_0000, mnemonic: mnemonic, category: .sve, operands: operands).text
}

/// Validates the 2s.5 canonicalizer's structural rendering rules that the
/// per-instruction decode tests touch only incidentally.
@Suite("SVE permute/memory/crypto / canonicalizer rendering rules")
struct SVEPermuteMemoryCanonicalizerRuleTests {
    @Test func aPairGroupRendersAsACommaList() {
        let group = ScalableVectorGroup(firstIndex: 0, count: 2, element: .b, layout: .consecutive)
        #expect(render(mnemonic: .ld2b, operands: [.scalableVectorGroup(group)]) == "ld2b { z0.b, z1.b }")
    }

    @Test func aContiguousRunOfThreeOrMoreRendersAsARange() {
        let group = ScalableVectorGroup(firstIndex: 0, count: 3, element: .b, layout: .consecutive)
        #expect(render(mnemonic: .ld3b, operands: [.scalableVectorGroup(group)]) == "ld3b { z0.b - z2.b }")
    }

    @Test func aGroupThatWrapsTheRegisterFileFallsBackToACommaList() {
        let group = ScalableVectorGroup(firstIndex: 30, count: 3, element: .b, layout: .consecutive)
        #expect(render(mnemonic: .ld3b, operands: [.scalableVectorGroup(group)]) == "ld3b { z30.b, z31.b, z0.b }")
    }

    @Test func aStridedGroupNeverUsesTheRangeForm() {
        let group = ScalableVectorGroup(firstIndex: 0, count: 4, element: .b, layout: .strided)
        #expect(render(mnemonic: .ld4b, operands: [.scalableVectorGroup(group)]) == "ld4b { z0.b, z4.b, z8.b, z12.b }")
    }

    @Test func aSizelessGroupRendersItsMembersWithoutSuffixes() {
        let group = ScalableVectorGroup(firstIndex: 0, count: 2, element: nil, layout: .consecutive)
        #expect(render(mnemonic: .ld2b, operands: [.scalableVectorGroup(group)]) == "ld2b { z0, z1 }")
    }

    @Test func everyPrefetchOperationNameRenders() {
        let expected: [UInt8: String] = [
            0: "pldl1keep", 1: "pldl1strm", 2: "pldl2keep", 3: "pldl2strm",
            4: "pldl3keep", 5: "pldl3strm", 6: "#6", 7: "#7",
            8: "pstl1keep", 9: "pstl1strm", 10: "pstl2keep", 11: "pstl2strm",
            12: "pstl3keep", 13: "pstl3strm", 14: "#14", 15: "#15",
        ]
        for raw: UInt8 in 0 ... 15 {
            let op = Operand.prefetchOperation(PrefetchOperation(rawValue: raw))
            #expect(render(mnemonic: .prfb, operands: [op]) == "prfb \(expected[raw]!)", "prfop \(raw)")
        }
    }

    @Test func aMulVLDisplacementDropsToBareBracketsAtZero() {
        let zero = ScalableMemoryOperand(base: .gpr(.x(0)), displacement: 0, mulVL: true)
        #expect(render(mnemonic: .ld1b, operands: [.scalableMemory(zero)]) == "ld1b [x0]")
        let nonzero = ScalableMemoryOperand(base: .gpr(.x(0)), displacement: -3, mulVL: true)
        #expect(render(mnemonic: .ld1b, operands: [.scalableMemory(nonzero)]) == "ld1b [x0, #-3, mul vl]")
    }

    @Test func aScalarIndexRendersItsLslOnlyWhenScaled() {
        let unscaled = ScalableMemoryOperand(base: .gpr(.x(1)), scalarIndex: .x(2), scaleShift: 0)
        #expect(render(mnemonic: .ld1b, operands: [.scalableMemory(unscaled)]) == "ld1b [x1, x2]")
        let scaled = ScalableMemoryOperand(base: .gpr(.x(1)), scalarIndex: .x(2), scaleShift: 3)
        #expect(render(mnemonic: .ld1d, operands: [.scalableMemory(scaled)]) == "ld1d [x1, x2, lsl #3]")
    }

    @Test func aStackPointerBaseRendersAsSP() {
        let mem = ScalableMemoryOperand(base: .gpr(.sp()))
        #expect(render(mnemonic: .ld1b, operands: [.scalableMemory(mem)]) == "ld1b [sp]")
    }

    @Test func aBareVectorRegisterRendersWithoutASuffix() {
        #expect(render(mnemonic: .ldr, operands: [.scalableVector(ScalableVectorRef(registerIndex: 5))]) == "ldr z5")
    }

    @Test func aZeroRegisterGprOperandRenders() {
        #expect(render(mnemonic: .lasta, operands: [.register(.wzr())]) == "lasta wzr")
        #expect(render(mnemonic: .lasta, operands: [.register(.xzr())]) == "lasta xzr")
    }
}

/// Validates the canonicalizer's defensive fallbacks.
@Suite("SVE permute/memory/crypto / canonicalizer defensive rendering")
struct SVEPermuteMemoryCanonicalizerDefensiveTests {
    @Test func anOperandlessRecordRendersJustItsMnemonic() {
        #expect(render(mnemonic: .aesmc, operands: []) == "aesmc")
    }

    @Test func anUnsupportedOperandRendersThePlaceholder() {
        #expect(render(mnemonic: .ld1b, operands: [.label(byteOffset: 0)]) == "ld1b ?")
    }

    @Test func anUnsupportedVectorViewRendersThePlaceholder() {
        let laneView = Operand.vectorRegister(VectorRegisterRef(registerIndex: 2, view: .lane(index: 0)))
        #expect(render(mnemonic: .insr, operands: [laneView]) == "insr ?v2")
    }

    @Test func aSimdRegisterInTheGprRendererFallsToTheMarker() {
        #expect(render(mnemonic: .lasta, operands: [.register(.simd(9))]) == "lasta ?s41")
    }

    @Test func stackPointerRolesRenderInTheGprRenderer() {
        #expect(render(mnemonic: .lasta, operands: [.register(.sp())]) == "lasta sp")
        #expect(render(mnemonic: .lasta, operands: [.register(.wsp())]) == "lasta wsp")
    }

    @Test func aPlainGprRendersAtBothWidths() {
        #expect(render(mnemonic: .insr, operands: [.register(.w(3))]) == "insr w3")
        #expect(render(mnemonic: .insr, operands: [.register(.x(3))]) == "insr x3")
    }

    @Test func anUnsignedImmediateRenders() {
        #expect(render(mnemonic: .ext, operands: [.unsignedImmediate(value: 7, width: 8)]) == "ext #7")
    }

    @Test func aPredicateWithAnElementIndexAndQualifierRenders() {
        let pred = Operand.scalablePredicate(ScalablePredicateRef(
            registerIndex: 3, element: .s, qualifier: .zeroing, role: .governing, elementIndex: 2,
        ))
        #expect(render(mnemonic: .ld1b, operands: [pred]) == "ld1b p3.s[2]/z")
    }

    @Test func aMnemonicOutsideThePermuteMemorySetRendersEmpty() {
        #expect(render(mnemonic: .add, operands: []) == "")
    }

    @Test func aVectorBaseAddressWithoutAnElementRenders() {
        let mem = ScalableMemoryOperand(base: .vector(ScalableVectorRef(registerIndex: 4)))
        #expect(render(mnemonic: .ld1q, operands: [.scalableMemory(mem)]) == "ld1q [z4]")
    }

    @Test func aVectorIndexWithoutAnElementRenders() {
        let mem = ScalableMemoryOperand(
            base: .gpr(.x(0)), index: ScalableVectorRef(registerIndex: 1), indexExtend: .uxtw,
        )
        #expect(render(mnemonic: .ld1b, operands: [.scalableMemory(mem)]) == "ld1b [x0, z1, uxtw]")
    }

    @Test func aGeneralRoleRegisterAtEncodingThirtyOneRenders() {
        #expect(render(mnemonic: .insr, operands: [.register(.x(31))]) == "insr x31")
        #expect(render(mnemonic: .insr, operands: [.register(.w(31))]) == "insr w31")
    }
}
