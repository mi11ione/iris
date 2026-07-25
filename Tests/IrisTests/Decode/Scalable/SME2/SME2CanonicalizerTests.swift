// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func render(_ mnemonic: Mnemonic, _ operands: [Operand]) -> String {
    Instruction(address: 0, encoding: 0xC100_0000, mnemonic: mnemonic, category: .sme, operands: operands).text
}

private func group(_ first: UInt8, _ count: UInt8, _ element: ScalarSize?,
                   _ layout: ScalableVectorGroup.Layout = .consecutive, index: UInt8? = nil) -> Operand
{
    .scalableVectorGroup(ScalableVectorGroup(
        firstIndex: first, count: count, element: element, layout: layout, elementIndex: index,
    ))
}

/// Validates the 2s.7 canonicalizer's per-operand rendering rules — the pieces
/// the decode suites reach only through whole instructions. Each rule is a
/// character-level convention llvm-mc imposes that no encoding field announces,
/// so it is asserted directly on the operand shape: the multi-vector brace
/// forms, the ZA-array range and group suffixes, the tile-slice direction, the
/// predicate-as-counter and PSEL bracket forms, the ZT0 spellings, and the
/// address-bracket pieces.
@Suite("SME2 / canonicalizer rendering rules")
struct SME2CanonicalizerRuleTests {
    @Test func aVectorGroupRendersCommaPairDashRunAndStridedList() {
        #expect(render(.fadd, [group(0, 2, .s)]) == "fadd { z0.s, z1.s }")
        #expect(render(.fadd, [group(4, 4, .s)]) == "fadd { z4.s - z7.s }")
        #expect(render(.fadd, [group(1, 2, .d, .strided)]) == "fadd { z1.d, z9.d }")
        // A size-less group (LUTI table pair) and a group-level lane index.
        #expect(render(.luti6, [group(0, 2, nil)]) == "luti6 { z0, z1 }")
        #expect(render(.luti6, [group(0, 2, nil, index: 3)]) == "luti6 { z0, z1 }[3]")
    }

    @Test func aConsecutiveRunThatWrapsFallsBackToACommaList() {
        // The dash form needs `first + count - 1 <= 31`; a wrapping run lists
        // every member instead.
        #expect(render(.fadd, [group(30, 4, .s)]) == "fadd { z30.s, z31.s, z0.s, z1.s }")
    }

    @Test func aPredicateGroupListsItsSizedMembers() {
        #expect(render(.whilege, [.predicateGroup(firstIndex: 0, count: 2, element: .b)]) == "whilege { p0.b, p1.b }")
        #expect(render(.whilege, [.predicateGroup(firstIndex: 15, count: 2, element: .b)]) == "whilege { p15.b, p0.b }")
    }

    @Test func aZAArrayVectorRendersItsRangeGroupAndSuffix() {
        let base = ZAArrayVectorOperand(element: .s, selectRegister: .w(8), offset: 0, group: .vgx2)
        #expect(render(.fadd, [.zaArrayVector(base)]) == "fadd za.s[w8, 0, vgx2]")
        let range = ZAArrayVectorOperand(element: .d, selectRegister: .w(8), offset: 0, offsetHigh: 3, group: .none)
        #expect(render(.fadd, [.zaArrayVector(range)]) == "fadd za.d[w8, 0:3]")
        let quad = ZAArrayVectorOperand(element: .d, selectRegister: .w(11), offset: 2, group: .vgx4)
        #expect(render(.fadd, [.zaArrayVector(quad)]) == "fadd za.d[w11, 2, vgx4]")
        // The suffix-less array form (no element).
        let sizeless = ZAArrayVectorOperand(selectRegister: .w(8), offset: 4)
        #expect(render(.fadd, [.zaArrayVector(sizeless)]) == "fadd za[w8, 4]")
    }

    @Test func aZATileRendersWithAndWithoutItsSuffix() {
        #expect(render(.fmop4a, [.zaTile(index: 3, element: .s)]) == "fmop4a za3.s")
        #expect(render(.fmop4a, [.zaTile(index: 0, element: nil)]) == "fmop4a za")
    }

    @Test func aTileSliceRendersItsDirectionAndOptionalRange() {
        let horizontal = ZATileSliceOperand(
            tileIndex: 0, element: .b, direction: .horizontal, selectRegister: .w(12), offset: 0,
        )
        #expect(render(.mov, [.zaTileSlice(horizontal)]) == "mov za0h.b[w12, 0]")
        let vertical = ZATileSliceOperand(
            tileIndex: 3, element: .s, direction: .vertical, selectRegister: .w(13), offset: 2, offsetHigh: 5,
        )
        #expect(render(.mov, [.zaTileSlice(vertical)]) == "mov za3v.s[w13, 2:5]")
    }

    @Test func aZT0OperandRendersBareOrIndexed() {
        #expect(render(.ldr, [.zt0(elementIndex: nil)]) == "ldr zt0")
        #expect(render(.movt, [.zt0(elementIndex: 5)]) == "movt zt0[5]")
    }

    @Test func aVectorLengthMultiplierRendersVlx() {
        #expect(render(.whilege, [.vectorLengthMultiplier(2)]) == "whilege vlx2")
        #expect(render(.cntp, [.vectorLengthMultiplier(4)]) == "cntp vlx4")
    }

    @Test func aPredicateRendersEveryDressing() {
        // Counter (`pn`) vs mask (`p`), the size suffix, the PSEL select-register
        // bracket, the PEXT lane index, and the /z /m qualifiers.
        #expect(render(.sel, [.scalablePredicate(ScalablePredicateRef(registerIndex: 8, isCounter: true))]) == "sel pn8")
        #expect(render(.firstp, [.scalablePredicate(ScalablePredicateRef(registerIndex: 0, element: .b))]) == "firstp p0.b")
        let psel = ScalablePredicateRef(registerIndex: 5, element: .h, elementIndex: 3, selectRegister: .w(14))
        #expect(render(.psel, [.scalablePredicate(psel)]) == "psel p5.h[w14, 3]")
        // A select register with no explicit index renders the `, 0` default.
        let pselNoIndex = ScalablePredicateRef(registerIndex: 6, element: .d, selectRegister: .w(15))
        #expect(render(.psel, [.scalablePredicate(pselNoIndex)]) == "psel p6.d[w15, 0]")
        let pext = ScalablePredicateRef(registerIndex: 5, isCounter: true, elementIndex: 2)
        #expect(render(.pext, [.scalablePredicate(pext)]) == "pext pn5[2]")
        #expect(render(.ld1b, [.scalablePredicate(ScalablePredicateRef(registerIndex: 3, qualifier: .zeroing))]) == "ld1b p3/z")
        #expect(render(.smopa, [.scalablePredicate(ScalablePredicateRef(registerIndex: 3, qualifier: .merging))]) == "smopa p3/m")
    }

    @Test func aScalableVectorRendersWithAndWithoutSuffixAndIndex() {
        #expect(render(.mov, [.scalableVector(ScalableVectorRef(registerIndex: 5, element: .h))]) == "mov z5.h")
        #expect(render(.mov, [.scalableVector(ScalableVectorRef(registerIndex: 5))]) == "mov z5")
        #expect(render(.mov, [.scalableVector(ScalableVectorRef(registerIndex: 5, element: .d, elementIndex: 1))]) == "mov z5.d[1]")
    }

    @Test func theAddressBracketRendersEachPiece() {
        #expect(render(.ld1b, [.scalableMemory(ScalableMemoryOperand(base: .gpr(.x(3))))]) == "ld1b [x3]")
        let unscaled = ScalableMemoryOperand(base: .gpr(.x(3)), scalarIndex: .x(4), scaleShift: 0)
        #expect(render(.ld1b, [.scalableMemory(unscaled)]) == "ld1b [x3, x4]")
        let scaled = ScalableMemoryOperand(base: .gpr(.x(3)), scalarIndex: .x(4), scaleShift: 3)
        #expect(render(.ld1d, [.scalableMemory(scaled)]) == "ld1d [x3, x4, lsl #3]")
        let mulVL = ScalableMemoryOperand(base: .gpr(.x(0)), displacement: 10, mulVL: true)
        #expect(render(.ld1b, [.scalableMemory(mulVL)]) == "ld1b [x0, #10, mul vl]")
        let byteDisp = ScalableMemoryOperand(base: .gpr(.x(0)), displacement: -8, mulVL: false)
        #expect(render(.ld1b, [.scalableMemory(byteDisp)]) == "ld1b [x0, #-8]")
        // The renderer inherits the SVE vector-base arm (2s.7 never emits it).
        let vectorBase = ScalableMemoryOperand(base: .vector(ScalableVectorRef(registerIndex: 9, element: .d)))
        #expect(render(.ld1d, [.scalableMemory(vectorBase)]) == "ld1d [z9.d]")
        let bareVector = ScalableMemoryOperand(base: .vector(ScalableVectorRef(registerIndex: 9)))
        #expect(render(.ld1d, [.scalableMemory(bareVector)]) == "ld1d [z9]")
    }

    @Test func aGprRendersByRole() {
        #expect(render(.movt, [.register(.x(5))]) == "movt x5")
        #expect(render(.fadd, [.register(.sp())]) == "fadd sp")
        #expect(render(.fadd, [.register(.xzr())]) == "fadd xzr")
    }

    @Test func immediatesRenderWithAHashPrefix() {
        #expect(render(.sqrshr, [.immediate(value: -3, width: 6)]) == "sqrshr #-3")
        #expect(render(.sqrshr, [.unsignedImmediate(value: 7, width: 8)]) == "sqrshr #7")
    }
}

/// Validates the alias-driven special forms the renderer keys off the mnemonic
/// and operand shape rather than a plain operand join: the ZT0 ZERO braced
/// list, and the LUTv2 vector MOVT with its `, mul vl` index.
@Suite("SME2 / canonicalizer special forms")
struct SME2CanonicalizerSpecialFormTests {
    @Test func zeroOfZT0RendersABracedList() {
        #expect(render(.zero, [.zt0(elementIndex: nil)]) == "zero { zt0 }")
    }

    @Test func theVectorMovtRendersItsMulVLIndex() {
        let z = Operand.scalableVector(ScalableVectorRef(registerIndex: 3))
        #expect(render(.movt, [.zt0(elementIndex: nil), z]) == "movt zt0, z3")
        #expect(render(.movt, [.zt0(elementIndex: 2), z]) == "movt zt0[2, mul vl], z3")
    }

    @Test func aScalarMovtIsNotMistakenForTheVectorForm() {
        // The vector special-case only fires when operand two is a vector; a
        // GPR second operand renders through the normal join.
        #expect(render(.movt, [.zt0(elementIndex: 3), .register(.x(4))]) == "movt zt0[3], x4")
    }
}

/// Validates the canonicalizer's defensive rendering — the paths a well-formed
/// 2s.7 decode never produces but which keep `format` total over any
/// `Instruction`. The validator formats whatever the decoder returns, so an
/// unexpected shape must produce a visible marker rather than silently dropping
/// an operand and printing text that looks correct.
@Suite("SME2 / canonicalizer defensive rendering")
struct SME2CanonicalizerDefensiveTests {
    @Test func anUndefinedRecordRendersTheDataDirective() {
        let draft = Instruction(address: 0, encoding: 0xC100_2000, mnemonic: .undefined, category: .sme)
        #expect(draft.text == ".long 0xc1002000")
    }

    @Test func anOperandlessRecordRendersJustItsMnemonic() {
        #expect(render(.fadd, []) == "fadd")
    }

    @Test func aMnemonicOutsideTheSME2SurfaceRendersAnEmptyName() {
        // `name` has no entry for another tier's token; with operands present
        // that surfaces as a leading space rather than a wrong instruction.
        #expect(render(.udf, []) == "")
        #expect(render(.udf, [.register(.x(1))]) == " x1")
    }

    @Test func anUnsupportedOperandRendersThePlaceholder() {
        // The `?` marker is what the decode suites' "renders no placeholder"
        // assertion detects, so it must actually be produced.
        #expect(render(.fadd, [.svePredicatePattern(SVEPredicatePattern(raw: 31))]) == "fadd ?")
    }
}
