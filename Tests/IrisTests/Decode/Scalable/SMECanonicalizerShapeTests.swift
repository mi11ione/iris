// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func smeText(_ mnemonic: Mnemonic, _ operands: [Operand]) -> String {
    Instruction(
        encoding: 0x8080_FC00, mnemonic: mnemonic, category: .sme, operands: operands,
    ).text
}

/// Validates that the SME-core canonicalizer is total over the operand
/// vocabulary, including shapes its own decoder never emits.
@Suite("SME-core canonicalizer — total over the operand vocabulary")
struct SMECanonicalizerShapeTests {
    @Test func mnemonicWithNoOperandsRendersBare() {
        #expect(smeText(.mov, []) == "mov")
    }

    @Test func tileWithoutAnElementRendersBare() {
        #expect(smeText(.mov, [.zaTile(index: 0, element: nil)]) == "mov za")
        #expect(smeText(.mov, [.zaTile(index: 3, element: .s)]) == "mov za3.s")
    }

    @Test func arrayVectorRendersWithAndWithoutAnElement() {
        let suffixed = ZAArrayVectorOperand(element: .s, selectRegister: .w(12), offset: 3)
        #expect(smeText(.mov, [.zaArrayVector(suffixed)]) == "mov za.s[w12, 3]")
        let bare = ZAArrayVectorOperand(selectRegister: .w(15), offset: 0)
        #expect(smeText(.mov, [.zaArrayVector(bare)]) == "mov za[w15, 0]")
    }

    @Test func scalableVectorWithoutAnElementRendersBare() {
        #expect(smeText(.mov, [.scalableVector(ScalableVectorRef(registerIndex: 5))]) == "mov z5")
    }

    @Test func vectorBaseAddressRenders() {
        let suffixed = ScalableMemoryOperand(base: .vector(ScalableVectorRef(registerIndex: 3, element: .s)))
        #expect(smeText(.ld1b, [.scalableMemory(suffixed)]) == "ld1b [z3.s]")
        let bare = ScalableMemoryOperand(base: .vector(ScalableVectorRef(registerIndex: 7)))
        #expect(smeText(.ld1b, [.scalableMemory(bare)]) == "ld1b [z7]")
    }

    @Test func foreignOperandKindRendersThePlaceholder() {
        #expect(smeText(.mov, [.register(.x(1))]) == "mov ?")
    }

    @Test func zeroSkipsNonTileOperands() {
        #expect(smeText(.zero, [.zaTile(index: 1, element: .d), .register(.x(0))]) == "zero {za1.d}")
    }

    @Test func mnemonicOutsideTheTableRendersEmpty() {
        #expect(smeText(.add, []).isEmpty)
    }
}
