// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func render(mnemonic: Mnemonic, operands: [Operand]) -> String {
    Instruction(address: 0, encoding: 0x8400_0000, mnemonic: mnemonic, category: .sve, operands: operands).text
}

/// Validates the 2s.5 canonicalizer's structural rendering rules that the
/// per-instruction decode tests touch only incidentally: the multi-vector group
/// range-vs-comma choice (including the register-file-wrap fallback and the
/// strided layout), the full prefetch-operation name table, and the memory
/// bracket's optional pieces.
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
        // z30, z31, z0 — the range form would misrepresent the wrap, so the
        // renderer lists the members even though the count is ≥ 3.
        let group = ScalableVectorGroup(firstIndex: 30, count: 3, element: .b, layout: .consecutive)
        #expect(render(mnemonic: .ld3b, operands: [.scalableVectorGroup(group)]) == "ld3b { z30.b, z31.b, z0.b }")
    }

    @Test func aStridedGroupNeverUsesTheRangeForm() {
        // A strided group's members are not contiguous, so the range form (which
        // implies a `first - last` run) is wrong; the renderer lists them.
        let group = ScalableVectorGroup(firstIndex: 0, count: 4, element: .b, layout: .strided)
        #expect(render(mnemonic: .ld4b, operands: [.scalableVectorGroup(group)]) == "ld4b { z0.b, z4.b, z8.b, z12.b }")
    }

    @Test func aSizelessGroupRendersItsMembersWithoutSuffixes() {
        // ScalableVectorGroup's element is optional so the type is shared with
        // SME2's size-less lists; SVE permute/memory decode always supplies a
        // suffix, but the renderer stays total over a nil element.
        let group = ScalableVectorGroup(firstIndex: 0, count: 2, element: nil, layout: .consecutive)
        #expect(render(mnemonic: .ld2b, operands: [.scalableVectorGroup(group)]) == "ld2b { z0, z1 }")
    }

    @Test func everyPrefetchOperationNameRenders() {
        // The named policy set {0-5, 8-13} plus the raw fallback {6, 7, 14, 15}.
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
        // A zero displacement is dropped; a nonzero one carries `, mul vl`.
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
        // A base Xn with n=31 renders `sp` in the address bracket.
        let mem = ScalableMemoryOperand(base: .gpr(.sp()))
        #expect(render(mnemonic: .ld1b, operands: [.scalableMemory(mem)]) == "ld1b [sp]")
    }

    @Test func aBareVectorRegisterRendersWithoutASuffix() {
        // LDR/STR and PMOV render `z0` with no element suffix.
        #expect(render(mnemonic: .ldr, operands: [.scalableVector(ScalableVectorRef(registerIndex: 5))]) == "ldr z5")
    }

    @Test func aZeroRegisterGprOperandRenders() {
        // The LASTA/CLASTA GPR destination at index 31 is the zero register.
        #expect(render(mnemonic: .lasta, operands: [.register(.wzr())]) == "lasta wzr")
        #expect(render(mnemonic: .lasta, operands: [.register(.xzr())]) == "lasta xzr")
    }
}

/// Validates the canonicalizer's defensive rendering fallbacks — the paths a
/// well-formed 2s.5 decode never produces but which keep `format` total over
/// any `Instruction`: the placeholder for an unsupported operand or vector
/// view, the `?s` marker for a SIMD register that reached the GPR renderer, the
/// `sp`/`wsp` GPR roles, the predicate index/qualifier combinations, the
/// unsigned-immediate arm, and the empty string for a mnemonic outside the
/// permute/memory/crypto set.
@Suite("SVE permute/memory/crypto / canonicalizer defensive rendering")
struct SVEPermuteMemoryCanonicalizerDefensiveTests {
    @Test func anOperandlessRecordRendersJustItsMnemonic() {
        #expect(render(mnemonic: .aesmc, operands: []) == "aesmc")
    }

    @Test func anUnsupportedOperandRendersThePlaceholder() {
        #expect(render(mnemonic: .ld1b, operands: [.label(byteOffset: 0)]) == "ld1b ?")
    }

    @Test func anUnsupportedVectorViewRendersThePlaceholder() {
        // A non-scalar SIMD view is not a shape 2s.5 emits; it falls to `?v`.
        let laneView = Operand.vectorRegister(VectorRegisterRef(registerIndex: 2, view: .lane(index: 0)))
        #expect(render(mnemonic: .insr, operands: [laneView]) == "insr ?v2")
    }

    @Test func aSimdRegisterInTheGprRendererFallsToTheMarker() {
        // `.register` carrying a SIMD ref is not a 2s.5 shape; it renders `?s`.
        #expect(render(mnemonic: .lasta, operands: [.register(.simd(9))]) == "lasta ?s41")
    }

    @Test func stackPointerRolesRenderInTheGprRenderer() {
        // The plain-GPR renderer (not the address renderer) handles SP/WSP.
        #expect(render(mnemonic: .lasta, operands: [.register(.sp())]) == "lasta sp")
        #expect(render(mnemonic: .lasta, operands: [.register(.wsp())]) == "lasta wsp")
    }

    @Test func aPlainGprRendersAtBothWidths() {
        #expect(render(mnemonic: .insr, operands: [.register(.w(3))]) == "insr w3")
        #expect(render(mnemonic: .insr, operands: [.register(.x(3))]) == "insr x3")
    }

    @Test func anUnsignedImmediateRenders() {
        // 2s.5 emits only signed immediates; the unsigned arm stays total.
        #expect(render(mnemonic: .ext, operands: [.unsignedImmediate(value: 7, width: 8)]) == "ext #7")
    }

    @Test func aPredicateWithAnElementIndexAndQualifierRenders() {
        // 2s.5 predicates never carry a lane index, but the renderer supports it.
        let pred = Operand.scalablePredicate(ScalablePredicateRef(
            registerIndex: 3, element: .s, qualifier: .zeroing, role: .governing, elementIndex: 2,
        ))
        #expect(render(mnemonic: .ld1b, operands: [pred]) == "ld1b p3.s[2]/z")
    }

    @Test func aMnemonicOutsideThePermuteMemorySetRendersEmpty() {
        // `name` returns "" for a mnemonic 2s.5 does not own; an operand-less
        // record therefore renders the empty string.
        #expect(render(mnemonic: .add, operands: []) == "")
    }

    @Test func aVectorBaseAddressWithoutAnElementRenders() {
        // The vector-base bracket tolerates a plain `Zn` (no `.<T>` suffix).
        let mem = ScalableMemoryOperand(base: .vector(ScalableVectorRef(registerIndex: 4)))
        #expect(render(mnemonic: .ld1q, operands: [.scalableMemory(mem)]) == "ld1q [z4]")
    }

    @Test func aVectorIndexWithoutAnElementRenders() {
        // A gather index vector always carries an element suffix in practice, but
        // the bracket renderer tolerates a bare `Zn` index (the `?? ""` default).
        let mem = ScalableMemoryOperand(
            base: .gpr(.x(0)), index: ScalableVectorRef(registerIndex: 1), indexExtend: .uxtw,
        )
        #expect(render(mnemonic: .ld1b, operands: [.scalableMemory(mem)]) == "ld1b [x0, z1, uxtw]")
    }

    @Test func aGeneralRoleRegisterAtEncodingThirtyOneRenders() {
        // Encoding 31 with a general role (neither SP nor ZR) is not a shape 2s.5
        // emits — the GPR forms map index 31 to the zero register — but the
        // renderer falls through both role checks to the plain `x31`/`w31`.
        #expect(render(mnemonic: .insr, operands: [.register(.x(31))]) == "insr x31")
        #expect(render(mnemonic: .insr, operands: [.register(.w(31))]) == "insr w31")
    }
}
