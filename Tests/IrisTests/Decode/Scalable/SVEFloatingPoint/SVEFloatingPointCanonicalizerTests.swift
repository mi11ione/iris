// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the canonicalizer's defensive fallbacks.
@Suite("SVE floating-point / canonicalizer defensive rendering")
struct SVEFloatingPointCanonicalizerTests {
    private func render(mnemonic: Mnemonic, operands: [Operand]) -> String {
        Instruction(address: 0, encoding: 0x6400_0000, mnemonic: mnemonic, category: .sve, operands: operands).text
    }

    @Test func anOperandlessRecordRendersJustItsMnemonic() {
        #expect(render(mnemonic: .fadd, operands: []) == "fadd")
    }

    @Test func aSizelessGroupRendersItsMembersWithoutSuffixes() {
        let group = ScalableVectorGroup(firstIndex: 4, count: 2, element: nil, layout: .consecutive)
        #expect(render(mnemonic: .fadd, operands: [.scalableVectorGroup(group)]) == "fadd { z4, z5 }")
    }

    @Test func aQuadwordElementSuffixRenders() {
        let op = Operand.scalableVector(ScalableVectorRef(registerIndex: 3, element: .q))
        #expect(render(mnemonic: .fadd, operands: [op]) == "fadd z3.q")
    }

    @Test func everyNeonArrangementSuffixRenders() {
        let rows: [(VectorArrangement, String)] = [
            (.b8, "8b"), (.b16, "16b"), (.h4, "4h"), (.h2, "2h"),
            (.s2, "2s"), (.d1, "1d"), (.q1, "1q"),
        ]
        for (arrangement, suffix) in rows {
            let op = Operand.vectorRegister(VectorRegisterRef(registerIndex: 5, view: .full(arrangement: arrangement)))
            #expect(render(mnemonic: .faddqv, operands: [op]) == "faddqv v5.\(suffix)")
        }
    }

    @Test func unsupportedVectorViewsAndOperandsRenderThePlaceholder() {
        let laneView = Operand.vectorRegister(VectorRegisterRef(registerIndex: 2, view: .lane(index: 0)))
        #expect(render(mnemonic: .fadd, operands: [laneView]) == "fadd ?v2")
        #expect(render(mnemonic: .fadd, operands: [.label(byteOffset: 0)]) == "fadd ?")
    }

    @Test func aNonFloatingPointMnemonicRendersItsRawValuePlaceholder() {
        let op = Operand.scalableVector(ScalableVectorRef(registerIndex: 0, element: .h))
        #expect(render(mnemonic: .add, operands: [op]) == "?\(Mnemonic.add.rawValue) z0.h")
    }

    @Test func aNonFmovImmediateOutsideTheShortConstantsRendersEightDecimals() {
        let op = Operand.floatImmediate(bits: UInt64(Float16(3.0).bitPattern), kind: .half)
        #expect(render(mnemonic: .fadd, operands: [op]) == "fadd #3.00000000")
    }
}
