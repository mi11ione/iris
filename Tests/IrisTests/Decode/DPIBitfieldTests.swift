// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates BFM/SBFM/UBFM and the 12-rule alias precedence chain, the
/// read-modify-write Rd semantics, and the reserved-encoding rules.
@Suite("DPI / Bitfield decode + 12 alias rules")
struct DPIBitfieldTests {
    @Test func sxtbAliasAtSF0() {
        let d = decode(0x1300_1C20, at: 0)
        #expect(d.mnemonic == .sxtb)
        #expect(d.operands.count == 2)
    }

    @Test func sxtbAliasAtSF1MixedWidths() {
        let d = decode(0x9340_1C20, at: 0)
        #expect(d.mnemonic == .sxtb)
        #expect(d.operands[1] == .register(.w(1)), "expected Wn at index 1")
    }

    @Test func sxthAlias() {
        let d = decode(0x1300_3C20, at: 0)
        #expect(d.mnemonic == .sxth)
    }

    @Test func sxtwAliasMixedWidth() {
        let d = decode(0x9340_7C20, at: 0)
        #expect(d.mnemonic == .sxtw)
        if case let .register(rn) = d.operands[1] {
            #expect(rn.width == .w32)
        }
    }

    @Test func uxtbAlias32BitOnly() {
        let d = decode(0x5300_1C20, at: 0)
        #expect(d.mnemonic == .uxtb)
    }

    @Test func uxthAlias32BitOnly() {
        let d = decode(0x5300_3C20, at: 0)
        #expect(d.mnemonic == .uxth)
    }

    @Test func ubfmImmrZeroNonExtensionFallsThroughToUBFX() {
        let d = decode(0x5300_0C20, at: 0)
        #expect(d.mnemonic == .ubfx)
    }

    @Test func asrAlias64Bit() {
        let d = decode(0x9340_FC1F, at: 0)
        #expect(d.mnemonic == .asr)
        #expect(d.operands.count == 3)
    }

    @Test func asrAlias32Bit() {
        let d = decode(0x1301_7C20, at: 0)
        #expect(d.mnemonic == .asr)
    }

    @Test func lsrAlias64Bit() {
        let d = decode(0xD342_FC20, at: 0)
        #expect(d.mnemonic == .lsr)
    }

    @Test func lsrAlias32Bit() {
        let d = decode(0x5302_7C20, at: 0)
        #expect(d.mnemonic == .lsr)
    }

    @Test func lslAlias64Bit() {
        let d = decode(0xD37C_EC20, at: 0)
        #expect(d.mnemonic == .lsl)
    }

    @Test func lslAlias32Bit() {
        let d = decode(0x531C_6C20, at: 0)
        #expect(d.mnemonic == .lsl)
    }

    @Test func sbfizAliasWhenImmsLessThanImmr() {
        let d = decode(0x937E_1020, at: 0)
        #expect(d.mnemonic == .sbfiz)
    }

    @Test func sbfxAliasWhenImmsGreaterEqualImmr() {
        let d = decode(0x9362_C020, at: 0)
        #expect(d.mnemonic == .sbfx)
    }

    @Test func ubfizAliasWhenImmsLessThanImmr() {
        let d = decode(0xD374_1420, at: 0)
        #expect(d.mnemonic == .ubfiz)
    }

    @Test func ubfxAliasFallback() {
        let d = decode(0xD35D_EC20, at: 0)
        #expect(d.mnemonic == .ubfx)
    }

    @Test func bfiAliasWhenImmsLessThanImmrAndRnNotXZR() {
        let d = decode(0xB37C_1020, at: 0)
        #expect(d.mnemonic == .bfi)
        #expect(d.operands.count == 4)
        #expect(d.semanticReads.contains(.x(0)))
        #expect(d.semanticReads.contains(.x(1)))
    }

    @Test func bfcAliasFromBFMRnXZR() {
        let d = decode(0xB37C_13E0, at: 0)
        #expect(d.mnemonic == .bfc)
        #expect(d.operands.count == 3)
        #expect(d.semanticReads.contains(.x(0)))
    }

    @Test func bfcWhenImmrIsZero() {
        let d = decode(0xB340_03E0, at: 0)
        #expect(d.mnemonic == .bfc)
    }

    @Test func bfxilAliasWhenImmsGreaterEqualImmr() {
        let d = decode(0x3301_0920, at: 0)
        #expect(d.mnemonic == .bfxil)
        #expect(d.operands.count == 4)
    }

    @Test func bfxilEvenWhenRnIsXZR_NotBFC() {
        let d = decode(0xB341_09E0, at: 0)
        #expect(d.mnemonic == .bfxil)
    }

    @Test func reservedNMismatchSF1N0() {
        let d = decode(0xB300_0020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedNMismatchSF0N1() {
        let d = decode(0x1340_7C20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reserved32BitImmrHighBit() {
        let d = decode(0x1320_7C20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reserved32BitImmsHighBit() {
        let d = decode(0x1300_A020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedOpc11IsUndefined() {
        let d = decode(0xF340_0020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func sbfmRdNotReadJustWritten() {
        let d = decode(0x9340_3C20, at: 0)
        #expect(d.mnemonic == .sxth)
        #expect(!d.semanticReads.contains(.x(0)))
        #expect(d.semanticWrites.contains(.x(0)))
    }
}
