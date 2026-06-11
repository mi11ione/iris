// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates crypto/Apple-extensions text rendering (via
/// `Instruction.text`) for every sub-family: AES / SHA / SM* text, PAC
/// standalone, MTE (including IRG XZR alias and MTE-store offset-0
/// alias), AMX (set/clr no operand, X-register operand for documented
/// ops, `.long` form for amxUnknownOp), and defensive sentinels for
/// operand variants outside the family's scope.
@Suite("CryptoAppleExtensions / Canonicalizer.format")
struct CryptoAppleExtensionsCanonicalizerTests {
    @Test func undefinedRecordRendersLongDirective() {
        // Text is total: undefined records render the raw word as a
        // `.long` directive (the router owns the sentinel rendering).
        let undefined = Instruction(address: 0, encoding: 0, mnemonic: .undefined, category: .undefined)
        #expect(undefined.text == ".long 0x0")
    }

    @Test func cryptoFormatterGuardsForeignMnemonicRanges() {
        // Hand-built record: crypto category carrying a non-crypto
        // mnemonic (.add) — the formatter's range guard fires.
        let hostile = Instruction(
            address: 0, encoding: 0, mnemonic: .add,
            category: .crypto, operands: [],
        )
        #expect(hostile.text == "?256")
    }

    @Test func crossFamilyDelegationRendersCryptoMnemonics() {
        // A crypto/MTE/AMX-range mnemonic on a GPR-family record routes
        // through that family's formatter into the crypto canonicalizer
        // (the in-formatter `owns()` delegation, observed via text).
        let aese = Instruction(
            address: 0, encoding: 0, mnemonic: .aese,
            category: .dataProcessingImmediate, operands: [],
        )
        #expect(aese.text == "aese")
        // Non-crypto mnemonics stay with their own family formatter.
        let add = Instruction(
            address: 0, encoding: 0, mnemonic: .add,
            category: .dataProcessingImmediate, operands: [],
        )
        #expect(add.text == "add")
    }

    @Test func aeseFormatting() {
        let d = decode(0x4E28_4820, at: 0)
        #expect(d.text == "aese v0.16b, v1.16b")
    }

    @Test func aesdFormatting() {
        let d = decode(0x4E28_5820, at: 0)
        #expect(d.text == "aesd v0.16b, v1.16b")
    }

    @Test func aesmcFormatting() {
        let d = decode(0x4E28_6820, at: 0)
        #expect(d.text == "aesmc v0.16b, v1.16b")
    }

    @Test func aesimcFormatting() {
        let d = decode(0x4E28_7820, at: 0)
        #expect(d.text == "aesimc v0.16b, v1.16b")
    }

    @Test func sha1cFormatting() {
        // SHA1C q0, s1, v2.4s.
        let d = decode(0x5E02_0020, at: 0)
        #expect(d.text == "sha1c q0, s1, v2.4s")
    }

    @Test func sha1pFormatting() {
        let d = decode(0x5E02_1020, at: 0)
        #expect(d.text == "sha1p q0, s1, v2.4s")
    }

    @Test func sha1mFormatting() {
        let d = decode(0x5E02_2020, at: 0)
        #expect(d.text == "sha1m q0, s1, v2.4s")
    }

    @Test func sha1su0Formatting() {
        let d = decode(0x5E02_3020, at: 0)
        #expect(d.text == "sha1su0 v0.4s, v1.4s, v2.4s")
    }

    @Test func sha256hFormatting() {
        let d = decode(0x5E02_4020, at: 0)
        #expect(d.text == "sha256h q0, q1, v2.4s")
    }

    @Test func sha256h2Formatting() {
        let d = decode(0x5E02_5020, at: 0)
        #expect(d.text == "sha256h2 q0, q1, v2.4s")
    }

    @Test func sha256su1Formatting() {
        let d = decode(0x5E02_6020, at: 0)
        #expect(d.text == "sha256su1 v0.4s, v1.4s, v2.4s")
    }

    @Test func sha1hFormatting() {
        // SHA1H s0, s1.
        let d = decode(0x5E28_0820, at: 0)
        #expect(d.text == "sha1h s0, s1")
    }

    @Test func sha1su1Formatting() {
        let d = decode(0x5E28_1820, at: 0)
        #expect(d.text == "sha1su1 v0.4s, v1.4s")
    }

    @Test func sha256su0Formatting() {
        let d = decode(0x5E28_2820, at: 0)
        #expect(d.text == "sha256su0 v0.4s, v1.4s")
    }

    @Test func eor3Formatting() {
        // EOR3 v0.16b, v1.16b, v2.16b, v3.16b.
        let d = decode(0xCE02_0C20, at: 0)
        #expect(d.text ==
            "eor3 v0.16b, v1.16b, v2.16b, v3.16b")
    }

    @Test func bcaxFormatting() {
        // BCAX v0.16b, v1.16b, v2.16b, v3.16b.
        let d = decode(0xCE22_0C20, at: 0)
        #expect(d.text ==
            "bcax v0.16b, v1.16b, v2.16b, v3.16b")
    }

    @Test func xarFormatting() {
        // XAR v0.2d, v1.2d, v2.2d, #1.
        let d = decode(0xCE82_0420, at: 0)
        #expect(d.text ==
            "xar v0.2d, v1.2d, v2.2d, #1")
    }

    @Test func rax1Formatting() {
        let d = decode(0xCE62_8C20, at: 0)
        #expect(d.text ==
            "rax1 v0.2d, v1.2d, v2.2d")
    }

    @Test func sha512hFormatting() {
        let d = decode(0xCE62_8020, at: 0)
        #expect(d.text ==
            "sha512h q0, q1, v2.2d")
    }

    @Test func sha512h2Formatting() {
        let d = decode(0xCE62_8420, at: 0)
        #expect(d.text ==
            "sha512h2 q0, q1, v2.2d")
    }

    @Test func sha512su0Formatting() {
        let d = decode(0xCEC0_8020, at: 0)
        #expect(d.text ==
            "sha512su0 v0.2d, v1.2d")
    }

    @Test func sha512su1Formatting() {
        let d = decode(0xCE62_8820, at: 0)
        #expect(d.text ==
            "sha512su1 v0.2d, v1.2d, v2.2d")
    }

    @Test func sm3ss1Formatting() {
        // SM3SS1 v0.4s, v1.4s, v2.4s, v3.4s.
        let d = decode(0xCE42_0C20, at: 0)
        #expect(d.text ==
            "sm3ss1 v0.4s, v1.4s, v2.4s, v3.4s")
    }

    @Test func sm3tt1aFormattingWithLaneIndex() {
        // SM3TT1A v0.4s, v1.4s, v2.s[3].
        let d = decode(0xCE42_B020, at: 0)
        #expect(d.text ==
            "sm3tt1a v0.4s, v1.4s, v2.s[3]")
    }

    @Test func sm3tt1bFormatting() {
        let d = decode(0xCE42_8420, at: 0)
        #expect(d.text ==
            "sm3tt1b v0.4s, v1.4s, v2.s[0]")
    }

    @Test func sm3tt2aFormatting() {
        let d = decode(0xCE42_8820, at: 0)
        #expect(d.text ==
            "sm3tt2a v0.4s, v1.4s, v2.s[0]")
    }

    @Test func sm3tt2bFormatting() {
        let d = decode(0xCE42_8C20, at: 0)
        #expect(d.text ==
            "sm3tt2b v0.4s, v1.4s, v2.s[0]")
    }

    @Test func sm3partw1Formatting() {
        let d = decode(0xCE62_C020, at: 0)
        #expect(d.text ==
            "sm3partw1 v0.4s, v1.4s, v2.4s")
    }

    @Test func sm3partw2Formatting() {
        let d = decode(0xCE62_C420, at: 0)
        #expect(d.text ==
            "sm3partw2 v0.4s, v1.4s, v2.4s")
    }

    @Test func sm4ekeyFormatting() {
        let d = decode(0xCE62_C820, at: 0)
        #expect(d.text ==
            "sm4ekey v0.4s, v1.4s, v2.4s")
    }

    @Test func sm4eFormatting() {
        let d = decode(0xCEC0_8420, at: 0)
        #expect(d.text ==
            "sm4e v0.4s, v1.4s")
    }

    @Test func paciaFormatting() {
        let d = decode(0xDAC1_0020, at: 0)
        #expect(d.text == "pacia x0, x1")
    }

    @Test func pacibFormatting() {
        let d = decode(0xDAC1_0420, at: 0)
        #expect(d.text == "pacib x0, x1")
    }

    @Test func pacdaFormatting() {
        let d = decode(0xDAC1_0820, at: 0)
        #expect(d.text == "pacda x0, x1")
    }

    @Test func pacdbFormatting() {
        let d = decode(0xDAC1_0C20, at: 0)
        #expect(d.text == "pacdb x0, x1")
    }

    @Test func autiaFormatting() {
        let d = decode(0xDAC1_1020, at: 0)
        #expect(d.text == "autia x0, x1")
    }

    @Test func autibFormatting() {
        let d = decode(0xDAC1_1420, at: 0)
        #expect(d.text == "autib x0, x1")
    }

    @Test func autdaFormatting() {
        let d = decode(0xDAC1_1820, at: 0)
        #expect(d.text == "autda x0, x1")
    }

    @Test func autdbFormatting() {
        let d = decode(0xDAC1_1C20, at: 0)
        #expect(d.text == "autdb x0, x1")
    }

    @Test func pacizaFormatting() {
        let d = decode(0xDAC1_23E0, at: 0)
        #expect(d.text == "paciza x0")
    }

    @Test func pacizbFormatting() {
        let d = decode(0xDAC1_27E0, at: 0)
        #expect(d.text == "pacizb x0")
    }

    @Test func pacdzaFormatting() {
        let d = decode(0xDAC1_2BE0, at: 0)
        #expect(d.text == "pacdza x0")
    }

    @Test func pacdzbFormatting() {
        let d = decode(0xDAC1_2FE0, at: 0)
        #expect(d.text == "pacdzb x0")
    }

    @Test func autizaFormatting() {
        let d = decode(0xDAC1_33E0, at: 0)
        #expect(d.text == "autiza x0")
    }

    @Test func autizbFormatting() {
        let d = decode(0xDAC1_37E0, at: 0)
        #expect(d.text == "autizb x0")
    }

    @Test func autdzaFormatting() {
        let d = decode(0xDAC1_3BE0, at: 0)
        #expect(d.text == "autdza x0")
    }

    @Test func autdzbFormatting() {
        let d = decode(0xDAC1_3FE0, at: 0)
        #expect(d.text == "autdzb x0")
    }

    @Test func xpaciFormatting() {
        let d = decode(0xDAC1_43E0, at: 0)
        #expect(d.text == "xpaci x0")
    }

    @Test func xpacdFormatting() {
        let d = decode(0xDAC1_47E0, at: 0)
        #expect(d.text == "xpacd x0")
    }

    @Test func pacgaFormatting() {
        let d = decode(0x9AC2_3020, at: 0)
        #expect(d.text == "pacga x0, x1, x2")
    }

    @Test func pacgaWithRmSPFormatting() {
        // PACGA x0, x1, sp — Rm SP-form renders as "sp" not "x31".
        let d = decode(0x9ADF_3020, at: 0)
        #expect(d.text == "pacga x0, x1, sp")
    }

    @Test func addgFormatting() {
        // ADDG sp, x2, #32, #3 = 0x91820C5F (Rd=11111 → sp, Rn=00010 → x2).
        let d = decode(0x9182_0C5F, at: 0)
        #expect(d.text == "addg sp, x2, #32, #3")
    }

    @Test func subgFormatting() {
        let d = decode(0xD182_0C5F, at: 0)
        #expect(d.text == "subg sp, x2, #32, #3")
    }

    @Test func subpFormatting() {
        // SUBP x0, x1, x2 = 0x9AC20020.
        let d = decode(0x9AC2_0020, at: 0)
        #expect(d.text == "subp x0, x1, x2")
    }

    @Test func subpsFormatting() {
        let d = decode(0xBAC2_0020, at: 0)
        #expect(d.text == "subps x0, x1, x2")
    }

    @Test func irgThreeOperandFormatting() {
        // IRG x0, x1, x2 — 3-operand form (Rm != XZR).
        let d = decode(0x9AC2_1020, at: 0)
        #expect(d.text == "irg x0, x1, x2")
    }

    @Test func irgWithXZRRendersAsTwoOperandAlias() {
        // IRG x0, x1, xzr — Rm=11111 collapses to 2-operand `irg x0, x1`.
        let d = decode(0x9ADF_1020, at: 0)
        #expect(d.text == "irg x0, x1")
    }

    @Test func gmiFormatting() {
        let d = decode(0x9AC2_1420, at: 0)
        #expect(d.text == "gmi x0, x1, x2")
    }

    @Test func ldgFormatting() {
        // LDG x0, [x1, #0] — signed offset, displacement 0 → bare [Xn] alias.
        let d = decode(0xD960_0020, at: 0)
        #expect(d.text == "ldg x0, [x1]")
    }

    @Test func ldgWithOffsetFormatting() {
        // LDG x0, [x1, #16] — simm9 = 1, scaled × 16.
        let d = decode(0xD960_1020, at: 0)
        #expect(d.text == "ldg x0, [x1, #16]")
    }

    @Test func ldgmFormatting() {
        // LDGM x0, [x1] — bare addressing.
        let d = decode(0xD9E0_0020, at: 0)
        #expect(d.text == "ldgm x0, [x1]")
    }

    @Test func stgmFormatting() {
        let d = decode(0xD9A0_0020, at: 0)
        #expect(d.text == "stgm x0, [x1]")
    }

    @Test func stzgmFormatting() {
        let d = decode(0xD920_0020, at: 0)
        #expect(d.text == "stzgm x0, [x1]")
    }

    @Test func stgOffsetZeroRendersBareAlias() {
        // STG x0, [x1] — signed offset with displacement 0 → omit `, #0`.
        let d = decode(0xD920_0820, at: 0)
        #expect(d.text == "stg x0, [x1]")
    }

    @Test func stgWithSignedOffset() {
        // STG x0, [x1, #16].
        let d = decode(0xD920_1820, at: 0)
        #expect(d.text == "stg x0, [x1, #16]")
    }

    @Test func stgPostIndex() {
        // STG x0, [x1], #16 — post-index.
        let d = decode(0xD920_1420, at: 0)
        #expect(d.text == "stg x0, [x1], #16")
    }

    @Test func stgPreIndex() {
        // STG x0, [x1, #16]! — pre-index.
        let d = decode(0xD920_1C20, at: 0)
        #expect(d.text == "stg x0, [x1, #16]!")
    }

    @Test func stzgFormattingAcrossAddressingModes() {
        let signedOff = decode(0xD960_0820, at: 0)
        #expect(signedOff.text == "stzg x0, [x1]")
        let postIdx = decode(0xD960_1420, at: 0)
        #expect(postIdx.text == "stzg x0, [x1], #16")
        let preIdx = decode(0xD960_1C20, at: 0)
        #expect(preIdx.text == "stzg x0, [x1, #16]!")
    }

    @Test func st2gFormattingAcrossAddressingModes() {
        let signedOff = decode(0xD9A0_0820, at: 0)
        #expect(signedOff.text == "st2g x0, [x1]")
        let postIdx = decode(0xD9A0_1420, at: 0)
        #expect(postIdx.text == "st2g x0, [x1], #16")
        let preIdx = decode(0xD9A0_1C20, at: 0)
        #expect(preIdx.text == "st2g x0, [x1, #16]!")
    }

    @Test func stz2gFormattingAcrossAddressingModes() {
        let signedOff = decode(0xD9E0_0820, at: 0)
        #expect(signedOff.text == "stz2g x0, [x1]")
        let postIdx = decode(0xD9E0_1420, at: 0)
        #expect(postIdx.text == "stz2g x0, [x1], #16")
        let preIdx = decode(0xD9E0_1C20, at: 0)
        #expect(preIdx.text == "stz2g x0, [x1, #16]!")
    }

    @Test func amxSetRendersWithNoOperand() {
        let d = decode(0x0020_1220, at: 0)
        #expect(d.text == "set")
    }

    @Test func amxClrRendersWithNoOperand() {
        let d = decode(0x0020_1221, at: 0)
        #expect(d.text == "clr")
    }

    @Test func amxLdxRendersXRegister() {
        // amxLdx with operand X5.
        let d = decode(0x0020_1005, at: 0)
        #expect(d.text == "ldx x5")
    }

    @Test func amxLdyRendersXRegister() {
        let d = decode(0x0020_1020, at: 0)
        #expect(d.text == "ldy x0")
    }

    @Test func amxStxRendersXRegister() {
        let d = decode(0x0020_1040, at: 0)
        #expect(d.text == "stx x0")
    }

    @Test func amxStyRendersXRegister() {
        let d = decode(0x0020_1060, at: 0)
        #expect(d.text == "sty x0")
    }

    @Test func amxLdzRendersXRegister() {
        let d = decode(0x0020_1080, at: 0)
        #expect(d.text == "ldz x0")
    }

    @Test func amxStzRendersXRegister() {
        let d = decode(0x0020_10A0, at: 0)
        #expect(d.text == "stz x0")
    }

    @Test func amxLdziRendersXRegister() {
        let d = decode(0x0020_10C0, at: 0)
        #expect(d.text == "ldzi x0")
    }

    @Test func amxStziRendersXRegister() {
        let d = decode(0x0020_10E0, at: 0)
        #expect(d.text == "stzi x0")
    }

    @Test func amxExtrxRendersXRegister() {
        let d = decode(0x0020_1100, at: 0)
        #expect(d.text == "extrx x0")
    }

    @Test func amxExtryRendersXRegister() {
        let d = decode(0x0020_1120, at: 0)
        #expect(d.text == "extry x0")
    }

    @Test func amxFma64RendersXRegister() {
        let d = decode(0x0020_1140, at: 0)
        #expect(d.text == "fma64 x0")
    }

    @Test func amxFms64RendersXRegister() {
        let d = decode(0x0020_1160, at: 0)
        #expect(d.text == "fms64 x0")
    }

    @Test func amxFma32RendersXRegister() {
        let d = decode(0x0020_1180, at: 0)
        #expect(d.text == "fma32 x0")
    }

    @Test func amxFms32RendersXRegister() {
        let d = decode(0x0020_11A0, at: 0)
        #expect(d.text == "fms32 x0")
    }

    @Test func amxMac16RendersXRegister() {
        let d = decode(0x0020_11C0, at: 0)
        #expect(d.text == "mac16 x0")
    }

    @Test func amxFma16RendersXRegister() {
        let d = decode(0x0020_11E0, at: 0)
        #expect(d.text == "fma16 x0")
    }

    @Test func amxFms16RendersXRegister() {
        let d = decode(0x0020_1200, at: 0)
        #expect(d.text == "fms16 x0")
    }

    @Test func amxVecintRendersXRegister() {
        let d = decode(0x0020_1240, at: 0)
        #expect(d.text == "vecint x0")
    }

    @Test func amxVecfpRendersXRegister() {
        let d = decode(0x0020_1260, at: 0)
        #expect(d.text == "vecfp x0")
    }

    @Test func amxMatintRendersXRegister() {
        let d = decode(0x0020_1280, at: 0)
        #expect(d.text == "matint x0")
    }

    @Test func amxMatfpRendersXRegister() {
        let d = decode(0x0020_12A0, at: 0)
        #expect(d.text == "matfp x0")
    }

    @Test func amxGenlutRendersXRegister() {
        let d = decode(0x0020_12C0, at: 0)
        #expect(d.text == "genlut x0")
    }

    @Test func amxWithXZRRendersAsXzr() {
        // amxLdx X31 = ldx xzr.
        let d = decode(0x0020_101F, at: 0)
        #expect(d.text == "ldx xzr")
    }

    @Test func amxUnknownOpRendersLongHex() {
        // Opcode 23 (first opcode outside documented set) → amxUnknownOp.
        // Hard-code the oracle string so a regression in our hex
        // formatter (casing / zero-pad) can't be silently mirrored by
        // an oracle built via the same `String(radix:16)` call.
        let d = decode(0x0020_12E0, at: 0)
        #expect(d.text ==
            ".long 0x2012e0")
    }

    @Test func registerNameRendersSPCorrectly() {
        // ADDG SP, x2, #0, #0 — Rd = SP.
        let d = decode(0x9180_005F, at: 0)
        #expect(d.text.contains("sp"))
    }

    @Test func formatGenericOperandHandlesAmxFieldOperandOutsideDispatch() {
        // Construct a draft with .amxField that ISN'T in the per-mnemonic
        // dispatch list (e.g. .sha1c). This exercises the
        // formatGenericOperand .amxField branch.
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .sha1c,
            category: .crypto,
            operands: [.amxField(AMXField(rawBits: 0x0020_1005))],
        )
        // SHA1C dispatches via defaultOperandList → formatGenericOperand →
        // .amxField → xRegisterName(5) → "x5".
        #expect(draft.text == "sha1c x5")
    }

    @Test func formatGenericOperandHandlesAmxUnknownOperandOutsideDispatch() {
        // .amxUnknown carried by a non-amxUnknownOp mnemonic still
        // renders via formatGenericOperand → formatLongHex.
        let raw: UInt32 = 0xDEAD_BEEF
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .sha1c,
            category: .crypto,
            operands: [.amxUnknown(rawFields: raw)],
        )
        #expect(draft.text ==
            "sha1c .long 0x\(String(raw, radix: 16))")
    }

    @Test func unsupportedOperandVariantsRenderSentinel() {
        // Operand variants this family never emits (e.g. .conditionCode)
        // flow through the defensive sentinel "?unsupported-operand".
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .sha1c,
            category: .crypto,
            operands: [.conditionCode(.eq)],
        )
        #expect(draft.text ==
            "sha1c ?unsupported-operand")
    }

    @Test func mnemonicOutsideExplicitTableFallsToRawValueSentinel() {
        // A family-range mnemonic that's not in the name table should
        // render as "?<rawValue>". Every declared constant IS in the
        // table, but reserved gap values (e.g. 12350) are not.
        let draft = Instruction(
            address: 0, encoding: 0,
            mnemonic: Mnemonic(rawValue: 12350),
            category: .crypto, operands: [],
        )
        #expect(draft.text == "?12350")
    }

    @Test func memoryOperandPcBaseRendersPcSentinel() {
        // formatMemoryOperand has a PC-base branch (unreachable for MTE
        // but exists in code). Exercise via formatGenericOperand with a
        // manually-constructed memory operand.
        let mem = MemoryOperand(base: .pc, displacement: 16)
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .sha1c,
            category: .crypto,
            operands: [.memory(mem)],
        )
        #expect(draft.text ==
            "sha1c [pc, #16]")
    }

    @Test func memoryOperandPcBaseAtOffsetZero() {
        let mem = MemoryOperand(base: .pc, displacement: 0)
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .sha1c,
            category: .crypto,
            operands: [.memory(mem)],
        )
        #expect(draft.text == "sha1c [pc]")
    }

    @Test func memoryOperandPcBasePostIndex() {
        let mem = MemoryOperand(base: .pc, displacement: 8, writeback: .postIndex)
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .sha1c,
            category: .crypto,
            operands: [.memory(mem)],
        )
        #expect(draft.text ==
            "sha1c [pc], #8")
    }

    @Test func memoryOperandPcBasePreIndex() {
        let mem = MemoryOperand(base: .pc, displacement: 8, writeback: .preIndex)
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .sha1c,
            category: .crypto,
            operands: [.memory(mem)],
        )
        #expect(draft.text ==
            "sha1c [pc, #8]!")
    }

    @Test func mteStoreWithPcBaseInOperandRenders() {
        // MTE store helper hits .pc branch as well via formatMTEStore.
        let mem = MemoryOperand(base: .pc, displacement: 16)
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .stg,
            category: .memoryTagging,
            operands: [.register(.x(0)), .memory(mem)],
        )
        #expect(draft.text ==
            "stg x0, [pc, #16]")
    }

    @Test func mteStorePreIndexWithPcBase() {
        let mem = MemoryOperand(base: .pc, displacement: 8, writeback: .preIndex)
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .stg,
            category: .memoryTagging,
            operands: [.register(.x(0)), .memory(mem)],
        )
        #expect(draft.text ==
            "stg x0, [pc, #8]!")
    }

    @Test func mteStorePostIndexWithPcBase() {
        let mem = MemoryOperand(base: .pc, displacement: 8, writeback: .postIndex)
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .stg,
            category: .memoryTagging,
            operands: [.register(.x(0)), .memory(mem)],
        )
        #expect(draft.text ==
            "stg x0, [pc], #8")
    }

    @Test func mteStoreWithUnexpectedOperandFallsThroughToDefault() {
        // formatMTEStore expects operands.count == 2 with operand[1] = .memory.
        // If the layout differs, falls back to defaultOperandList.
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .stg,
            category: .memoryTagging,
            operands: [.register(.x(0)), .register(.x(1)), .register(.x(2))],
        )
        #expect(draft.text ==
            "stg x0, x1, x2")
    }

    @Test func irgWithWrongOperandCountFallsThrough() {
        // formatIRG expects operands.count == 3.
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .irg,
            category: .memoryTagging,
            operands: [.register(.x(0)), .register(.x(1))],
        )
        #expect(draft.text ==
            "irg x0, x1")
    }

    @Test func amxFieldOperandlessForAmxOpcodeRendersEmpty() {
        // Force operand list to be empty for an AMX docop. The amx-X
        // formatter returns empty when the operand isn't .amxField.
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .amxLdx,
            category: .amx, operands: [],
        )
        #expect(draft.text == "ldx")
    }

    @Test func amxUnknownOpFallsBackToDraftEncodingWhenOperandMissing() {
        // amxUnknownOp without an .amxUnknown operand still renders via
        // formatLongHex(draft.encoding).
        let draft = Instruction(
            address: 0, encoding: 0xCAFE_BABE, mnemonic: .amxUnknownOp,
            category: .amx, operands: [],
        )
        #expect(draft.text ==
            ".long 0xcafebabe")
    }

    @Test func registerTextRendersStackPointer64Bit() {
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .sha1c,
            category: .crypto, operands: [.register(.sp())],
        )
        #expect(draft.text == "sha1c sp")
    }

    @Test func registerTextRendersStackPointer32Bit() {
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .sha1c,
            category: .crypto, operands: [.register(.wsp())],
        )
        #expect(draft.text == "sha1c wsp")
    }

    @Test func registerTextRendersZeroRegister64Bit() {
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .sha1c,
            category: .crypto, operands: [.register(.xzr())],
        )
        #expect(draft.text == "sha1c xzr")
    }

    @Test func registerTextRendersZeroRegister32Bit() {
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .sha1c,
            category: .crypto, operands: [.register(.wzr())],
        )
        #expect(draft.text == "sha1c wzr")
    }

    @Test func registerTextRendersW32Form() {
        // Below-31 GPR with 32-bit width → "wN".
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .sha1c,
            category: .crypto, operands: [.register(.w(5))],
        )
        #expect(draft.text == "sha1c w5")
    }

    @Test func registerTextRendersSIMDRegisterByCanonicalIndex() {
        // .register(.simd(n)) has canonicalIndex 32+n; registerText
        // maps it to "vN".
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .sha1c,
            category: .crypto, operands: [.register(.simd(7))],
        )
        #expect(draft.text == "sha1c v7")
    }

    @Test func registerTextFallsToRawIndexWhenOutOfRange() {
        // canonicalIndex >= 64 has no named mapping — fallback is "?N".
        let reg = RegisterRef(canonicalIndex: 64, role: .general, width: .x64)
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .sha1c,
            category: .crypto, operands: [.register(reg)],
        )
        #expect(draft.text == "sha1c ?64")
    }

    @Test func vectorRegisterRendersEvery64BitArrangement() {
        for (arr, suffix) in [
            (VectorArrangement.b8, "v0.8b"),
            (VectorArrangement.h4, "v0.4h"),
            (VectorArrangement.s2, "v0.2s"),
            (VectorArrangement.d1, "v0.1d"),
        ] {
            let vr = VectorRegisterRef(registerIndex: 0, view: .full(arrangement: arr))
            let draft = Instruction(
                address: 0, encoding: 0, mnemonic: .sha1c,
                category: .crypto, operands: [.vectorRegister(vr)],
            )
            #expect(draft.text ==
                "sha1c \(suffix)")
        }
    }

    @Test func vectorRegisterRendersH8Arrangement() {
        let vr = VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .h8))
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .sha1c,
            category: .crypto, operands: [.vectorRegister(vr)],
        )
        #expect(draft.text == "sha1c v0.8h")
    }

    @Test func scalarRendersEverySize() {
        // scalarPrefix has cases b/h/s/d/q; SHA1C / SHA1H exercise s/q.
        // Add explicit coverage for b/h/d via manual drafts.
        for (size, prefix) in [
            (ScalarSize.b, "b"),
            (ScalarSize.h, "h"),
            (ScalarSize.d, "d"),
        ] {
            let vr = VectorRegisterRef(registerIndex: 3, view: .scalar(size: size))
            let draft = Instruction(
                address: 0, encoding: 0, mnemonic: .sha1c,
                category: .crypto, operands: [.vectorRegister(vr)],
            )
            #expect(draft.text ==
                "sha1c \(prefix)3")
        }
    }

    @Test func elementSubscriptRendersEveryScalarSize() {
        // scalarSizeName has b/h/s/d/q. SM3TT exercises s; cover b/h/d
        // via manual drafts.
        for (arrangement, expectedSize) in [
            (VectorArrangement.b16, "b"),
            (VectorArrangement.h8, "h"),
            (VectorArrangement.d2, "d"),
        ] {
            let vr = VectorRegisterRef(
                registerIndex: 4,
                view: .element(arrangement: arrangement, index: 1),
            )
            let draft = Instruction(
                address: 0, encoding: 0, mnemonic: .sha1c,
                category: .crypto, operands: [.vectorRegister(vr)],
            )
            #expect(draft.text ==
                "sha1c v4.\(expectedSize)[1]")
        }
    }

    @Test func formatGenericOperandHandlesSignedImmediate() {
        // .immediate is only reachable via a hand-built value (the real
        // decoders only emit .unsignedImmediate for crypto/MTE/PAC).
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .sha1c,
            category: .crypto, operands: [.immediate(value: -42, width: 16)],
        )
        #expect(draft.text ==
            "sha1c #-42")
    }

    @Test func undefinedMnemonicOnCryptoCategoryRecordRendersEmpty() {
        // The crypto formatter's own defensive arm (reachable only via a
        // hand-built crypto-category record) yields "".
        let d = Instruction(mnemonic: .undefined, category: .crypto)
        #expect(d.text == "")
    }

    @Test func quadAndTwoHalfArrangementsRenderTheirNames() {
        // .q1 / .h2 arrangements are only reachable on crypto records via
        // hand-built operands; the name table is total.
        let q1 = Instruction(mnemonic: .aese, category: .crypto, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 2, view: .full(arrangement: .q1))),
        ])
        #expect(q1.text == "aese v2.1q")
        let h2 = Instruction(mnemonic: .aese, category: .crypto, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 4, view: .full(arrangement: .h2))),
        ])
        #expect(h2.text == "aese v4.2h")
    }

    @Test func vectorViewRenderingCoversGroupAndLaneViews() {
        // .elementGroup and .lane views are only reachable via hand-built
        // records (the crypto decoders emit .full/.scalar/.element); the
        // renderer is total over the view enum.
        let group = Instruction(mnemonic: .aese, category: .crypto, operands: [
            .vectorRegister(VectorRegisterRef(
                registerIndex: 3, view: .elementGroup(elementSize: .s, count: 4, index: 2),
            )),
        ])
        #expect(group.text == "aese v3.4s[2]")
        let lane = Instruction(mnemonic: .aese, category: .crypto, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 7, view: .lane(index: 1))),
        ])
        #expect(lane.text == "aese v7[1]")
    }
}
