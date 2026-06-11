// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the data-processing 3-source family and its reserved /
/// don't-care field rules. Covers MADD/MSUB + wide multiply (SMADDL/etc.)
/// + multiply-high (SMULH/UMULH) and their MUL/MNEG/SMULL/SMNEGL/UMULL/
/// UMNEGL alias predicates (Ra=XZR).
@Suite("DPR / 3-source multiply")
struct DPR3SourceTests {
    @Test func baseMadd64Bit() {
        // MADD x0, x1, x2, x3 — opc=000, isSub=0.
        let d = decode(0x9B02_0C20, at: 0)
        #expect(d.mnemonic == .madd)
        #expect(d.flagEffect == .none)
        #expect(d.operands.count == 4)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1)), .register(.x(2)), .register(.x(3))])
    }

    @Test func baseMsub64Bit() {
        // MSUB x0, x1, x2, x3 — isSub=1.
        let d = decode(0x9B02_8C20, at: 0)
        #expect(d.mnemonic == .msub)
    }

    @Test func madd32Bit() {
        // MADD w0, w1, w2, w3.
        let d = decode(0x1B02_0C20, at: 0)
        #expect(d.mnemonic == .madd)
        #expect(d.operands[0] == .register(.w(0)))
    }

    @Test func mulAliasFromMaddRaXZR() {
        // MADD x0, x1, x2, xzr → MUL x0, x1, x2.
        let d = decode(0x9B02_7C20, at: 0)
        #expect(d.mnemonic == .mul)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1)), .register(.x(2))])
    }

    @Test func mnegAliasFromMsubRaXZR() {
        let d = decode(0x9B02_FC20, at: 0)
        #expect(d.mnemonic == .mneg)
    }

    @Test func smaddl() {
        // SMADDL x0, w1, w2, x3 — opc=001, sf=1, isSub=0.
        let d = decode(0x9B22_0C20, at: 0)
        #expect(d.mnemonic == .smaddl)
        // Rd=x, Rn=w, Rm=w, Ra=x
        #expect(d.operands[0] == .register(.x(0)))
        #expect(d.operands[1] == .register(.w(1)))
        #expect(d.operands[2] == .register(.w(2)))
        #expect(d.operands[3] == .register(.x(3)))
    }

    @Test func smsubl() {
        let d = decode(0x9B22_8C20, at: 0)
        #expect(d.mnemonic == .smsubl)
    }

    @Test func smullAliasFromSmaddlRaXZR() {
        let d = decode(0x9B22_7C20, at: 0)
        #expect(d.mnemonic == .smull)
    }

    @Test func smneglAliasFromSmsublRaXZR() {
        let d = decode(0x9B22_FC20, at: 0)
        #expect(d.mnemonic == .smnegl)
    }

    @Test func smaddl32BitReturnsUndefined() {
        // Wide-multiply requires sf=1; sf=0 is reserved.
        let d = decode(0x1B22_0C20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func smulh() {
        // SMULH x0, x1, x2 — opc=010, isSub=0, Ra=XZR (encoded fixed).
        let d = decode(0x9B42_7C20, at: 0)
        #expect(d.mnemonic == .smulh)
        #expect(d.operands.count == 3)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1)), .register(.x(2))])
    }

    @Test func smulhIsSubSetReturnsUndefined() {
        // isSub != 0 is invalid for multiply-high.
        let d = decode(0x9B42_FC20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func smulhAtSf0ReturnsUndefined() {
        let d = decode(0x1B42_7C20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func smulhRaNonZeroAcceptedAsDontCare() {
        // Ra is don't-care for SMULH (llvm-mc parity).
        // 0x9b4103c0 = SMULH with Ra=0 → renders as smulh x0, x30, x1.
        let d = decode(0x9B41_03C0, at: 0)
        #expect(d.mnemonic == .smulh)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(30)), .register(.x(1))])
        #expect(d.semanticReads.mask == (UInt64(1) << 30) | (UInt64(1) << 1))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func umulhRaNonZeroAcceptedAsDontCare() {
        // Mirror of smulhRaNonZeroAcceptedAsDontCare for UMULH (opc=110).
        let d = decode(0x9BC1_03C0, at: 0)
        #expect(d.mnemonic == .umulh)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(30)), .register(.x(1))])
        #expect(d.semanticReads.mask == (UInt64(1) << 30) | (UInt64(1) << 1))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func umaddl() {
        // UMADDL x0, w1, w2, x3 — opc=101.
        let d = decode(0x9BA2_0C20, at: 0)
        #expect(d.mnemonic == .umaddl)
    }

    @Test func umsubl() {
        let d = decode(0x9BA2_8C20, at: 0)
        #expect(d.mnemonic == .umsubl)
    }

    @Test func umullAliasFromUmaddlRaXZR() {
        let d = decode(0x9BA2_7C20, at: 0)
        #expect(d.mnemonic == .umull)
    }

    @Test func umneglAliasFromUmsublRaXZR() {
        let d = decode(0x9BA2_FC20, at: 0)
        #expect(d.mnemonic == .umnegl)
    }

    @Test func umaddl32BitReturnsUndefined() {
        let d = decode(0x1BA2_0C20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func umulh() {
        let d = decode(0x9BC2_7C20, at: 0)
        #expect(d.mnemonic == .umulh)
    }

    @Test func umulhIsSubSetReturnsUndefined() {
        let d = decode(0x9BC2_FC20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func umulhAtSf0ReturnsUndefined() {
        let d = decode(0x1BC2_7C20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func op54NonZeroReturnsUndefined() {
        // bits 30:29 must be 00.
        let d = decode(0x9B02_0C20 | (1 << 29), at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func opc011DecodesCpaMaddpt() {
        // opc=011 is FEAT_CPA MADDPT (in scope) — not reserved.
        let d = decode(0x9B62_0C20, at: 0)
        #expect(d.mnemonic == .maddpt)
    }

    @Test func reservedOpc100ReturnsUndefined() {
        // opc=100 — reserved.
        let d = decode(0x9B82_0C20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedOpc111ReturnsUndefined() {
        // opc=111 — reserved.
        let d = decode(0x9BE2_0C20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func cpaMultiplyAddDecodes64BitOnly() {
        // FEAT_CPA MADDPT/MSUBPT share the 3-source tier (opc=011).
        let madd = decode(0x9B62_0C20, at: 0)
        #expect(madd.mnemonic == .maddpt)
        #expect(Array(madd.operands) == [
            .register(.x(0)), .register(.x(1)), .register(.x(2)), .register(.x(3)),
        ])
        #expect(madd.semanticReads.contains(.x(1)) && madd.semanticReads.contains(.x(2))
            && madd.semanticReads.contains(.x(3)))
        #expect(madd.semanticWrites.contains(.x(0)))
        #expect(madd.text == "maddpt x0, x1, x2, x3")
        let msub = decode(0x9B62_8C20, at: 0)
        #expect(msub.mnemonic == .msubpt)
        #expect(msub.text == "msubpt x0, x1, x2, x3")
        // The 32-bit form is reserved.
        #expect(decode(0x1B62_0C20, at: 0).isUndefined)
    }
}
