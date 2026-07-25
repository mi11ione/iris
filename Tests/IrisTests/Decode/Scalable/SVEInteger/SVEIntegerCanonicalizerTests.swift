// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func text(_ encoding: UInt32) -> String {
    Iris.decode(encoding, at: 0).text
}

/// A draft with a hand-built operand list, for the shape-violation paths.
private func draft(_ mnemonic: Mnemonic, _ operands: [Operand]) -> Instruction {
    Instruction(
        address: 0, encoding: 0x2400_0000, mnemonic: mnemonic, category: .sve, operands: operands,
    )
}

private func format(_ mnemonic: Mnemonic, _ operands: [Operand]) -> String {
    draft(mnemonic, operands).text
}

/// Validates the disassembly-text rendering rules. The text is what the
/// corpus runner diffs against the reference assembler, so every rule that
/// changes a character is pinned here: which predicates carry an element
/// suffix and which stay bare, scalar and NEON-vector reduction destinations,
/// the signed/unsigned/hex immediate ladders, the ADR bracket shapes, the
/// register-pair braces — and, because the renderer must never crash on a
/// record whose operand list violates its expected shape, the `?` placeholder
/// arms for every operand kind the integer decoders do not emit.
@Suite("SVE integer / disassembly text")
struct SVEIntegerCanonicalizerTests {
    @Test func anUndefinedRecordRendersTheDataDirective() {
        // A rejected encoding has no instruction text; the renderer emits the
        // raw word as a `.long` data directive, the convention every UNDEFINED
        // record shares.
        #expect(text(0x2530_8000) == ".long 0x25308000")
        #expect(format(.undefined, []) == ".long 0x24000000")
    }

    @Test func aSizelessGroupRendersItsMembersWithoutSuffixes() {
        // ScalableVectorGroup carries an optional element to share the type with
        // SME2's size-less table lists; SVE integer decode always supplies a
        // suffix, but the renderer stays total over a nil element.
        let group = ScalableVectorGroup(firstIndex: 0, count: 2, element: nil, layout: .consecutive)
        #expect(format(.sqcvtn, [.scalableVectorGroup(group)]) == "sqcvtn { z0, z1 }")
    }

    @Test func theGoverningPredicateIsBareAndTheResultPredicateCarriesItsSize() {
        #expect(text(0x2402_A020) == "cmpeq p0.b, p0/z, z1.b, z2.b")
        #expect(text(0x0400_2443) == "saddv d3, p1, z2.b")
        #expect(text(0x0456_A820) == "abs z0.h, p2/m, z1.h")
    }

    @Test func theReductionDestinationsSpanScalarAndVectorViews() {
        #expect(text(0x0408_2443) == "smaxv b3, p1, z2.b")
        #expect(text(0x0448_2443) == "smaxv h3, p1, z2.h")
        #expect(text(0x0488_2443) == "smaxv s3, p1, z2.s")
        #expect(text(0x04C8_2443) == "smaxv d3, p1, z2.d")
        #expect(text(0x0405_2443) == "addqv v3.16b, p1, z2.b")
        #expect(text(0x0445_2443) == "addqv v3.8h, p1, z2.h")
        #expect(text(0x0485_2443) == "addqv v3.4s, p1, z2.s")
        #expect(text(0x04C5_2443) == "addqv v3.2d, p1, z2.d")
    }

    @Test func immediateSignednessFollowsTheOperandKind() {
        #expect(text(0x2528_DFE0) == "smax z0.b, z0.b, #-1")
        #expect(text(0x2529_DFE0) == "umax z0.b, z0.b, #255")
        #expect(text(0x243F_C020) == "cmphs p0.b, p0/z, z1.b, #127")
        #expect(text(0x2510_0020) == "cmpge p0.b, p0/z, z1.b, #-16")
    }

    @Test func theLogicalImmediateFamilyPrintsHexAndTheMovLadderPrintsAll() {
        #expect(text(0x0580_0020) == "and z0.s, z0.s, #0x3")
        #expect(text(0x05C0_0420) == "dupm z0.h, #0x3")
        #expect(text(0x05C0_64E0) == "mov z0.h, #4080")
        #expect(text(0x05C0_24E0) == "mov z0.h, #-4081")
        #expect(text(0x05C0_8020) == "mov z0.s, #0x30000")
    }

    @Test func theRegisterPairBracesAreSpacePadded() {
        #expect(text(0x4531_4040) == "sqcvtn z0.h, { z2.s, z3.s }")
        #expect(text(0x45A8_03C0) == "sqshrn z0.b, { z30.h, z31.h }, #8")
    }

    @Test func theAddressFormsElideOnlyThePackedZeroShift() {
        #expect(text(0x0422_A020) == "adr z0.d, [z1.d, z2.d, sxtw]")
        #expect(text(0x0462_A420) == "adr z0.d, [z1.d, z2.d, uxtw #1]")
        #expect(text(0x04A2_A020) == "adr z0.s, [z1.s, z2.s]")
        #expect(text(0x04A2_AC20) == "adr z0.s, [z1.s, z2.s, lsl #3]")
    }

    @Test func scalarSourcesRenderAtTheirRegisterWidth() {
        #expect(text(0x0520_3800) == "mov z0.b, w0")
        #expect(text(0x05E0_3800) == "mov z0.d, x0")
        #expect(text(0x0520_3BE0) == "mov z0.b, wsp")
        #expect(text(0x05E0_3BE0) == "mov z0.d, sp")
        #expect(text(0x0530_2000) == "mov z0.q, q0")
        #expect(text(0x0570_2000) == "mov z0.q, z0.q[1]")
    }

    @Test func aMnemonicWithoutOperandsRendersBare() {
        // No integer decoder emits an operand-less named record, but the
        // renderer's contract is total: the mnemonic text stands alone.
        #expect(format(.add, []) == "add")
        #expect(format(.dupm, []) == "dupm")
    }

    @Test func aForeignMnemonicRendersItsRawValuePlaceholder() {
        // The name table covers exactly the mnemonics the integer decoders
        // emit; anything else renders a visible placeholder, never a crash.
        let foreign = format(.udf, [])
        #expect(foreign.hasPrefix("?"))
        #expect(foreign.contains("\(Mnemonic.udf.rawValue)"))
    }

    @Test func aZeroRegisterOperandRendersItsArchitecturalName() {
        // The move decoders map register 31 to SP, so a zero register can
        // only arrive on a malformed record — it still renders faithfully,
        // and an index-31 register with a plain general role falls through
        // to its numbered spelling.
        #expect(format(.mov, [.scalableVector(ScalableVectorRef(registerIndex: 0, element: .s)),
                              .register(.xzr())]) == "mov z0.s, xzr")
        #expect(format(.mov, [.scalableVector(ScalableVectorRef(registerIndex: 0, element: .s)),
                              .register(.wzr())]) == "mov z0.s, wzr")
        #expect(format(.mov, [
            .register(RegisterRef(canonicalIndex: 31, role: .general, width: .x64)),
        ]) == "mov x31")
    }

    @Test func shapeViolationsRenderPlaceholdersInsteadOfCrashing() {
        // A SIMD register smuggled into a GPR slot.
        let simdAsGPR = format(.mov, [
            .register(RegisterRef(canonicalIndex: 40, role: .general, width: .vectorImplied)),
        ])
        #expect(simdAsGPR == "mov ?s40")
        // A vector register in a view no reduction produces.
        let elementView = format(.mov, [
            .vectorRegister(VectorRegisterRef(registerIndex: 3, view: .element(arrangement: .s4, index: 1))),
        ])
        #expect(elementView == "mov ?v3")
        // A memory operand with a GPR base or no index at all.
        let gprBase = format(.adr, [
            .scalableMemory(ScalableMemoryOperand(
                base: .gpr(.x(0)),
                index: ScalableVectorRef(registerIndex: 1, element: .d),
                indexExtend: .lsl, scaleShift: 0,
            )),
        ])
        #expect(gprBase == "adr ?mem")
        let noIndex = format(.adr, [
            .scalableMemory(ScalableMemoryOperand(
                base: .vector(ScalableVectorRef(registerIndex: 1, element: .d)),
                index: nil, indexExtend: .lsl, scaleShift: 0,
            )),
        ])
        #expect(noIndex == "adr ?mem")
        // An operand kind no integer decoder emits.
        #expect(format(.add, [.label(byteOffset: 8)]) == "add ?op")
    }

    @Test func theUnreachableRenderingArmsStillProduceFaithfulText() {
        // These operand shapes belong to other families (or to no decoder at
        // all), but the renderer is exhaustive over the frozen operand union,
        // so each arm has a defined answer.
        #expect(format(.mov, [.shiftAmount(kind: .lsr, amount: 3)]) == "mov lsr #3")
        #expect(format(.mov, [.shiftAmount(kind: .asr, amount: 3)]) == "mov asr #3")
        #expect(format(.mov, [.shiftAmount(kind: .ror, amount: 3)]) == "mov ror #3")
        #expect(format(.mov, [.shiftAmount(kind: .msl, amount: 3)]) == "mov msl #3")
        let arrangements: [(VectorArrangement, String)] = [
            (.b8, "v1.8b"), (.h2, "v1.2h"), (.h4, "v1.4h"), (.s2, "v1.2s"),
            (.d1, "v1.1d"), (.q1, "v1.1q"),
        ]
        for (arrangement, expected) in arrangements {
            let rendered = format(.mov, [
                .vectorRegister(VectorRegisterRef(registerIndex: 1, view: .full(arrangement: arrangement))),
            ])
            #expect(rendered == "mov \(expected)")
        }
        // A memory operand whose registers carry no element suffix, with an
        // extend kind the ADR decoder never produces.
        let bare = format(.adr, [
            .scalableMemory(ScalableMemoryOperand(
                base: .vector(ScalableVectorRef(registerIndex: 1)),
                index: ScalableVectorRef(registerIndex: 2),
                indexExtend: .uxtx, scaleShift: 1,
            )),
        ])
        #expect(bare == "adr [z1, z2]")
        // An element-suffixed vector register that also carries an index but
        // no element, and a bare Z register.
        #expect(format(.mov, [.scalableVector(ScalableVectorRef(registerIndex: 7))]) == "mov z7")
        // A result predicate without an element renders bare; a governing
        // predicate with an element stays bare too.
        #expect(format(.mov, [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 3, role: .result)),
        ]) == "mov p3")
        #expect(format(.mov, [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 3, element: .s, role: .governing)),
        ]) == "mov p3")
    }

    @Test func theMovImmediateLadderCoversItsUnsignedDecimalBand() {
        // Hand-built unsigned immediates walk the printSVELogicalImm ladder
        // edges: int16-max, the unsigned band, and the hex fallback.
        let mov = { (value: UInt64, width: UInt8) in
            format(.mov, [.unsignedImmediate(value: value, width: width)])
        }
        #expect(mov(32767, 32) == "mov #32767")
        #expect(mov(40000, 32) == "mov #40000")
        #expect(mov(0x10000, 32) == "mov #0x10000")
        #expect(mov(UInt64.max, 64) == "mov #-1")
    }
}
