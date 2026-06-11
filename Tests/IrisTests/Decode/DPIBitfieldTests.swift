// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates Bitfield (BFM, SBFM, UBFM) decode + the 12-rule alias
/// precedence chain: SXTB/SXTH/SXTW > UXTB/UXTH >
/// ASR/LSR/LSL > SBFIZ/SBFX > UBFIZ/UBFX > BFC > BFI > BFXIL > base.
/// Also covers the BFM-family read-modify-write Rd semantics
/// and the reserved-encoding rules (N != sf, 32-bit immr[5]/imms[5], opc=11).
@Suite("DPI / Bitfield decode + 12 alias rules")
struct DPIBitfieldTests {
    @Test func sxtbAliasAtSF0() {
        // SBFM w0, w1, #0, #7  →  SXTB w0, w1
        let d = decode(0x1300_1C20, at: 0)
        #expect(d.mnemonic == .sxtb)
        #expect(d.operands.count == 2)
    }

    @Test func sxtbAliasAtSF1MixedWidths() {
        // SBFM x0, w1, #0, #7 → SXTB x0, w1 — Rn rendered as Wn even though sf=1
        let d = decode(0x9340_1C20, at: 0)
        #expect(d.mnemonic == .sxtb)
        #expect(d.operands[1] == .register(.w(1)), "expected Wn at index 1")
    }

    @Test func sxthAlias() {
        // SBFM w0, w1, #0, #15  →  SXTH w0, w1
        let d = decode(0x1300_3C20, at: 0)
        #expect(d.mnemonic == .sxth)
    }

    @Test func sxtwAliasMixedWidth() {
        // SBFM x0, x1, #0, #31  →  SXTW x0, w1
        let d = decode(0x9340_7C20, at: 0)
        #expect(d.mnemonic == .sxtw)
        if case let .register(rn) = d.operands[1] {
            #expect(rn.width == .w32)
        }
    }

    @Test func uxtbAlias32BitOnly() {
        // UBFM w0, w1, #0, #7  →  UXTB w0, w1
        let d = decode(0x5300_1C20, at: 0)
        #expect(d.mnemonic == .uxtb)
    }

    @Test func uxthAlias32BitOnly() {
        let d = decode(0x5300_3C20, at: 0)
        #expect(d.mnemonic == .uxth)
    }

    @Test func ubfmImmrZeroNonExtensionFallsThroughToUBFX() {
        // UBFM w0, w1, #0, #3 does not meet UXTB/UXTH's imms=7/15 aliases.
        let d = decode(0x5300_0C20, at: 0)
        #expect(d.mnemonic == .ubfx)
    }

    @Test func asrAlias64Bit() {
        // SBFM xzr, x0, #0, #63  →  ASR xzr, x0, #0
        let d = decode(0x9340_FC1F, at: 0)
        #expect(d.mnemonic == .asr)
        #expect(d.operands.count == 3)
    }

    @Test func asrAlias32Bit() {
        // SBFM w0, w1, #1, #31  →  ASR w0, w1, #1
        let d = decode(0x1301_7C20, at: 0)
        #expect(d.mnemonic == .asr)
    }

    @Test func lsrAlias64Bit() {
        // UBFM x0, x1, #2, #63  →  LSR x0, x1, #2
        let d = decode(0xD342_FC20, at: 0)
        #expect(d.mnemonic == .lsr)
    }

    @Test func lsrAlias32Bit() {
        // UBFM w0, w1, #2, #31  →  LSR w0, w1, #2
        let d = decode(0x5302_7C20, at: 0)
        #expect(d.mnemonic == .lsr)
    }

    @Test func lslAlias64Bit() {
        // LSL x0, x1, #4 → UBFM x0, x1, #60, #59 (imms+1==immr, imms!=63)
        let d = decode(0xD37C_EC20, at: 0)
        #expect(d.mnemonic == .lsl)
    }

    @Test func lslAlias32Bit() {
        // LSL w0, w1, #4 → UBFM w0, w1, #28, #27 (immr=28, imms=27)
        let d = decode(0x531C_6C20, at: 0)
        #expect(d.mnemonic == .lsl)
    }

    @Test func sbfizAliasWhenImmsLessThanImmr() {
        // SBFIZ x0, x1, #2, #5 → SBFM x0, x1, #62, #4 (immr=62, imms=4)
        let d = decode(0x937E_1020, at: 0)
        #expect(d.mnemonic == .sbfiz)
    }

    @Test func sbfxAliasWhenImmsGreaterEqualImmr() {
        // SBFX x0, x1, #34, #15  →  SBFM x0, x1, #34, #48
        let d = decode(0x9362_C020, at: 0)
        #expect(d.mnemonic == .sbfx)
    }

    @Test func ubfizAliasWhenImmsLessThanImmr() {
        // UBFIZ x0, x1, #12, #6 → UBFM x0, x1, #52, #5 (immr=52, imms=5)
        let d = decode(0xD374_1420, at: 0)
        #expect(d.mnemonic == .ubfiz)
    }

    @Test func ubfxAliasFallback() {
        // UBFM x0, x1, #29, #59  →  UBFX x0, x1, #29, #31
        let d = decode(0xD35D_EC20, at: 0)
        #expect(d.mnemonic == .ubfx)
    }

    @Test func bfiAliasWhenImmsLessThanImmrAndRnNotXZR() {
        // BFM x0, x1, #4, #5 (immr=60, imms=4) → BFI x0, x1, #4, #5
        let d = decode(0xB37C_1020, at: 0)
        #expect(d.mnemonic == .bfi)
        #expect(d.operands.count == 4)
        // The BFM family inserts into Rd, so it reads Rd (read-modify-write).
        #expect(d.semanticReads.contains(.x(0)))
        #expect(d.semanticReads.contains(.x(1)))
    }

    @Test func bfcAliasFromBFMRnXZR() {
        // BFM x0, xzr, #60, #4 (immr=60, imms=4, Rn=31, immr!=0, imms<immr)
        //   → BFC x0, #4, #5 (3 operands; Rn dropped)
        let d = decode(0xB37C_13E0, at: 0)
        #expect(d.mnemonic == .bfc)
        #expect(d.operands.count == 3)
        // BFC still preserves un-replaced bits of Rd → Rd in read set.
        #expect(d.semanticReads.contains(.x(0)))
    }

    @Test func bfcWhenImmrIsZero() {
        // BFM x0, xzr, #0, #0 (N=1 sf=1, immr=0, imms=0, Rn=31)
        // BFC predicate: Rn=31 AND (immr==0 OR imms<immr). immr=0 → BFC.
        // lsb=(-immr)&63=0, width=imms+1=1 → BFC x0, #0, #1.
        let d = decode(0xB340_03E0, at: 0)
        #expect(d.mnemonic == .bfc)
    }

    @Test func bfxilAliasWhenImmsGreaterEqualImmr() {
        // BFM w0, w9, #1, #2 (immr=1, imms=2) → BFXIL w0, w9, #1, #2
        let d = decode(0x3301_0920, at: 0)
        #expect(d.mnemonic == .bfxil)
        #expect(d.operands.count == 4)
    }

    @Test func bfxilEvenWhenRnIsXZR_NotBFC() {
        // BFM x0, xzr, #1, #2 (N=1 sf=1, immr=1, imms=2, Rn=31).
        // BFC predicate requires (immr==0 OR imms<immr). Here immr=1, imms=2 →
        // imms>=immr → NOT BFC. Falls through to BFXIL.
        let d = decode(0xB341_09E0, at: 0)
        #expect(d.mnemonic == .bfxil)
    }

    @Test func reservedNMismatchSF1N0() {
        // BFM sf=1 N=0 → reserved
        let d = decode(0xB300_0020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedNMismatchSF0N1() {
        // SBFM sf=0 N=1 → reserved
        let d = decode(0x1340_7C20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reserved32BitImmrHighBit() {
        // SBFM sf=0 immr[5]=1 (immr=32)
        let d = decode(0x1320_7C20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reserved32BitImmsHighBit() {
        // SBFM sf=0 imms[5]=1 (imms=32)
        let d = decode(0x1300_A020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedOpc11IsUndefined() {
        // Bitfield opc=11 is reserved.
        // sf=1, opc=11, bits 28:23=100110, N=1 → top byte 1_11_100110 = 1111_0011 = 0xF3
        let d = decode(0xF340_0020, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func sbfmRdNotReadJustWritten() {
        // SBFM x0, x1, #0, #15 → SXTH (not read-modify-write)
        let d = decode(0x9340_3C20, at: 0)
        // SXTH x0, w1
        #expect(d.mnemonic == .sxth)
        #expect(!d.semanticReads.contains(.x(0)))
        #expect(d.semanticWrites.contains(.x(0)))
    }
}
