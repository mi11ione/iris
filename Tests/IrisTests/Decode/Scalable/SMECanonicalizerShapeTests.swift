// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// A synthetic SME-core instruction: a real SME-core encoding (so the text
/// router hands it to the SME-core canonicalizer) carrying hand-built operands.
/// The canonicalizer is total over the operand vocabulary, not just over the
/// shapes its own decoder emits, so these cover the arms real encodings never
/// produce — an operand kind from outside SME's vocabulary, a tile with no
/// element suffix, a vector base in an address.
private func smeText(_ mnemonic: Mnemonic, _ operands: [Operand]) -> String {
    // 0x8080fc00 = FMOPA — an SME-core word, so `isSMECoreEncoding` holds and
    // the router picks the SME-core canonicalizer.
    Instruction(
        encoding: 0x8080_FC00, mnemonic: mnemonic, category: .sme, operands: operands,
    ).text
}

@Suite("SME-core canonicalizer — total over the operand vocabulary")
struct SMECanonicalizerShapeTests {
    @Test func mnemonicWithNoOperandsRendersBare() {
        #expect(smeText(.mov, []) == "mov")
    }

    /// A ZA tile with no element suffix renders bare `za` (the LDR/STR ZA and
    /// whole-array shapes), rather than inventing a suffix.
    @Test func tileWithoutAnElementRendersBare() {
        #expect(smeText(.mov, [.zaTile(index: 0, element: nil)]) == "mov za")
        #expect(smeText(.mov, [.zaTile(index: 3, element: .s)]) == "mov za3.s")
    }

    /// The ZA-array vector shape with and without an element suffix.
    @Test func arrayVectorRendersWithAndWithoutAnElement() {
        let suffixed = ZAArrayVectorOperand(element: .s, selectRegister: .w(12), offset: 3)
        #expect(smeText(.mov, [.zaArrayVector(suffixed)]) == "mov za.s[w12, 3]")
        let bare = ZAArrayVectorOperand(selectRegister: .w(15), offset: 0)
        #expect(smeText(.mov, [.zaArrayVector(bare)]) == "mov za[w15, 0]")
    }

    /// A scalable vector with no element suffix renders `z<n>` alone.
    @Test func scalableVectorWithoutAnElementRendersBare() {
        #expect(smeText(.mov, [.scalableVector(ScalableVectorRef(registerIndex: 5))]) == "mov z5")
    }

    /// A vector base in a scalable address (the gather form), with and without
    /// an element suffix on the base register.
    @Test func vectorBaseAddressRenders() {
        let suffixed = ScalableMemoryOperand(base: .vector(ScalableVectorRef(registerIndex: 3, element: .s)))
        #expect(smeText(.ld1b, [.scalableMemory(suffixed)]) == "ld1b [z3.s]")
        let bare = ScalableMemoryOperand(base: .vector(ScalableVectorRef(registerIndex: 7)))
        #expect(smeText(.ld1b, [.scalableMemory(bare)]) == "ld1b [z7]")
    }

    /// An operand kind outside SME's vocabulary renders the `?` placeholder
    /// instead of being silently dropped — the renderer stays total.
    @Test func foreignOperandKindRendersThePlaceholder() {
        #expect(smeText(.mov, [.register(.x(1))]) == "mov ?")
    }

    /// ZERO's tile list skips operands that are not tiles rather than
    /// mis-rendering them.
    @Test func zeroSkipsNonTileOperands() {
        #expect(smeText(.zero, [.zaTile(index: 1, element: .d), .register(.x(0))]) == "zero {za1.d}")
    }

    /// A mnemonic outside the SME-core naming table renders empty — the table
    /// stays total for ``Mnemonic/name`` without inventing a spelling.
    @Test func mnemonicOutsideTheTableRendersEmpty() {
        #expect(smeText(.add, []).isEmpty)
    }
}
