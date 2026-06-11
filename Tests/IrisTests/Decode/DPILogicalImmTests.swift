// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates Logical (immediate) decode + DecodeBitMasks integration
/// + TST / MOV-bitmask alias precedence. Includes
/// 32-bit sign-extension validation for MOV-bitmask and the
/// isMOVWRepresentable gating that prevents MOV-bitmask when MOVZ/MOVN
/// could produce the same value.
@Suite("DPI / Logical-imm decode + aliases")
struct DPILogicalImmTests {
    @Test func baseAnd32Bit() {
        // AND w0, w1, #0x7 (sf=0, opc=00, N=0, imms=2, immr=0)
        let d = decode(0x1200_0820, at: 0)
        #expect(d.mnemonic == .and)
        #expect(d.flagEffect == .none)
        #expect(d.operands.count == 3)
        #expect(d.semanticReads.contains(.w(1)))
        #expect(d.semanticWrites.contains(.w(0)))
    }

    @Test func baseAnd64Bit() {
        // AND x0, x1, #0x33333333_33333333 (sf=1, N=0, imms=57, immr=0)
        let d = decode(0x9200_E420, at: 0)
        #expect(d.mnemonic == .and)
        // Decoded wmask should be 0x33333333_33333333.
        #expect(
            d.operands[2] == .unsignedImmediate(value: 0x3333_3333_3333_3333, width: 64),
            "expected unsigned immediate operand",
        )
    }

    @Test func baseOrr() {
        // ORR w0, w1, #0x7 (sf=0, opc=01, N=0, imms=2, immr=0, Rn=1)
        let d = decode(0x3200_0820, at: 0)
        #expect(d.mnemonic == .orr)
    }

    @Test func baseEor() {
        // EOR w0, w1, #0x7 (sf=0, opc=10, N=0, imms=2, immr=0, Rn=1)
        let d = decode(0x5200_0820, at: 0)
        #expect(d.mnemonic == .eor)
    }

    @Test func andsSetsFlags() {
        // ANDS x0, x1, #1 (sf=1, opc=11, N=1, imms=0, immr=0, Rn=1)
        let d = decode(0xF240_0020, at: 0)
        #expect(d.mnemonic == .ands)
        #expect(d.flagEffect == .nzcv)
    }

    @Test func tstAliasFromAndsRdXZR() {
        // ANDS xzr, x3, #1  →  TST x3, #1
        let d = decode(0xF240_007F, at: 0)
        #expect(d.mnemonic == .tst)
        #expect(d.operands.count == 2)
        #expect(d.flagEffect == .nzcv)
        #expect(d.semanticWrites == .empty)
        #expect(d.semanticReads.contains(.x(3)))
    }

    @Test func tst32Bit() {
        // ANDS wzr, w3, #1  →  TST w3, #1
        let d = decode(0x7200_007F, at: 0)
        #expect(d.mnemonic == .tst)
    }

    @Test func movBitmaskAlias64BitWideValue() {
        // ORR x0, xzr, #0x7FFFFFFFFFFFE  →  MOV x0, #2251799813685246
        // (Empirical: confirmed against llvm-mc.)
        let d = decode(0xB27F_C7E0, at: 0)
        #expect(d.mnemonic == .mov)
        #expect(d.operands.count == 2)
        #expect(d.semanticReads == .empty) // Rn=XZR
        #expect(
            d.operands[1] == .immediate(value: 2_251_799_813_685_246, width: 64),
            "expected signed-immediate operand at index 1",
        )
    }

    @Test func movBitmaskAlias32BitSignsExtendsThroughInt32() {
        // ORR w0, wzr, #0x80000001 (sf=0, opc=01, N=0, imms=1, immr=1, Rn=31)
        // wmask = 0x80000001 → as Int32 = -2147483647 → as Int64 = -2147483647.
        let d = decode(0x3201_07E0, at: 0)
        #expect(d.mnemonic == .mov)
        #expect(
            d.operands[1] == .immediate(value: -2_147_483_647, width: 32),
            "expected signed-decimal immediate with 32-bit width",
        )
    }

    @Test func movBitmaskNotTriggeredWhenMOVZRepresentable() {
        // ORR w0, wzr, #0x1 — value 1 IS MOVZ-representable, so MOV
        // bitmask alias does NOT apply; stays as ORR.
        let d = decode(0x3200_03E0, at: 0)
        #expect(d.mnemonic == .orr)
    }

    @Test func movBitmaskNotTriggeredWhen64BitMOVZRepresentable() {
        // ORR x0, xzr, #0x1 — the 64-bit value is also MOVZ-representable,
        // so MOV-bitmask alias does NOT apply; stays as ORR.
        let d = decode(0xB240_03E0, at: 0)
        #expect(d.mnemonic == .orr)
    }

    @Test func andEorTstStaysWhenRnXZRButMovBitmaskDoesNotApplyForAND() {
        // AND x0, xzr, #1 — even though Rn=XZR, MOV-bitmask only applies
        // to ORR (opc=01), not AND (opc=00).
        let d = decode(0x9240_03E0, at: 0)
        #expect(d.mnemonic == .and)
    }

    @Test func reserved32BitWithN1IsUndefined() {
        // ORR w0, w1, ... with N=1 → reserved
        let d = decode(0x3240_0020, at: 0)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
        #expect(d.operands.isEmpty)
    }

    @Test func reservedAllZerosPatternIsUndefined() {
        // Encoding with combined=0 → reserved.
        // For sf=1 N=0 imms=0b111111 → combined = (~0x3f & 0x3f) = 0. Reserved.
        // Encoding: opc=00, N=0, immr=0, imms=63 (0x3F), Rn=1, Rd=0, sf=1
        // = 1_00_100100_0_000000_111111_00001_00000 = 0x9200FC20
        let d = decode(0x9200_FC20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedAllOnesElementIsUndefined() {
        // S == size-1 → reserved (all-ones element).
        // For N=1 sf=1 imms=63 (S=63=size-1=63) → reserved at any immr.
        // Encoding: sf=1, opc=00, bits 28:23=100100, N=1, immr=0, imms=63
        // = 1_00_100100_1_000000_111111_00001_00000 = 0x9240FC20
        let d = decode(0x9240_FC20, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func decodeBitMasksLen0CaseReturnsNil() {
        // combined=1: N=0, imms=0x3E (~imms & 0x3F = 1) → len=0 → reserved.
        // sf=0 (so we don't hit the N=1 rejection), opc=00 (AND), N=0, immr=0, imms=0x3E, Rn=1, Rd=0
        // = 0_00_100100_0_000000_111110_00001_00000 = 0x1200F820
        let d = decode(0x1200_F820, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func andsX0XzrNotTSTBecauseRdNotXZR() {
        // ANDS x0, xzr, #1 (Rn=31, Rd=0) — Rd != XZR so NOT TST.
        // This is a base ANDS with Rn=XZR (which is also valid).
        // Encoding: sf=1, opc=11, N=1, imms=0, immr=0, Rn=31, Rd=0
        // = 1_11_100100_1_000000_000000_11111_00000 = 0xF24003E0
        let d = decode(0xF240_03E0, at: 0)
        #expect(d.mnemonic == .ands)
        #expect(d.flagEffect == .nzcv)
    }

    @Test func eachOpcGetsBaseMnemonic() {
        // Cycle through opc 00/01/10/11 with the SAME (N,immr,imms) and Rd/Rn ≠ 31
        // so no alias triggers. Use sf=0, N=0, imms=2, immr=0, Rn=1, Rd=0.
        let pairs: [(UInt32, Mnemonic)] = [
            (0x1200_0820, .and), // opc=00 (sf=0,opc=00,1001000_0_000000_000010_00001_00000)
            (0x3200_0820, .orr), // opc=01
            (0x5200_0820, .eor), // opc=10
            (0x7200_0820, .ands), // opc=11
        ]
        for (enc, expected) in pairs {
            let d = decode(enc, at: 0)
            #expect(d.mnemonic == expected, "encoding 0x\(String(enc, radix: 16))")
        }
    }
}
