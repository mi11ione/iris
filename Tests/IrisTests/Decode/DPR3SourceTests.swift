// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the 3-source family and its reserved rules.
@Suite("DPR / 3-source multiply")
struct DPR3SourceTests {
    @Test func baseMadd64Bit() {
        let d = decode(0x9B02_0C20, at: 0)
        #expect(d.mnemonic == .madd)
        #expect(d.flagEffect == .none)
        #expect(d.operands.count == 4)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1)), .register(.x(2)), .register(.x(3))])
    }

    @Test func baseMsub64Bit() {
        let d = decode(0x9B02_8C20, at: 0)
        #expect(d.mnemonic == .msub)
    }

    @Test func madd32Bit() {
        let d = decode(0x1B02_0C20, at: 0)
        #expect(d.mnemonic == .madd)
        #expect(d.operands[0] == .register(.w(0)))
    }

    @Test func mulAliasFromMaddRaXZR() {
        let d = decode(0x9B02_7C20, at: 0)
        #expect(d.mnemonic == .mul)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1)), .register(.x(2))])
    }

    @Test func mnegAliasFromMsubRaXZR() {
        let d = decode(0x9B02_FC20, at: 0)
        #expect(d.mnemonic == .mneg)
    }

    @Test func smaddl() {
        let d = decode(0x9B22_0C20, at: 0)
        #expect(d.mnemonic == .smaddl)
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
        let d = decode(0x1B22_0C20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func smulh() {
        let d = decode(0x9B42_7C20, at: 0)
        #expect(d.mnemonic == .smulh)
        #expect(d.operands.count == 3)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(1)), .register(.x(2))])
    }

    @Test func smulhIsSubSetReturnsUndefined() {
        let d = decode(0x9B42_FC20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func smulhAtSf0ReturnsUndefined() {
        let d = decode(0x1B42_7C20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func smulhRaNonZeroAcceptedAsDontCare() {
        let d = decode(0x9B41_03C0, at: 0)
        #expect(d.mnemonic == .smulh)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(30)), .register(.x(1))])
        #expect(d.semanticReads.mask == (UInt64(1) << 30) | (UInt64(1) << 1))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func umulhRaNonZeroAcceptedAsDontCare() {
        let d = decode(0x9BC1_03C0, at: 0)
        #expect(d.mnemonic == .umulh)
        #expect(Array(d.operands) == [.register(.x(0)), .register(.x(30)), .register(.x(1))])
        #expect(d.semanticReads.mask == (UInt64(1) << 30) | (UInt64(1) << 1))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func umaddl() {
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
        let d = decode(0x9B02_0C20 | (1 << 29), at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func opc011DecodesCpaMaddpt() {
        let d = decode(0x9B62_0C20, at: 0)
        #expect(d.mnemonic == .maddpt)
    }

    @Test func reservedOpc100ReturnsUndefined() {
        let d = decode(0x9B82_0C20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedOpc111ReturnsUndefined() {
        let d = decode(0x9BE2_0C20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func cpaMultiplyAddDecodes64BitOnly() {
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
        #expect(decode(0x1B62_0C20, at: 0).isUndefined)
    }
}
