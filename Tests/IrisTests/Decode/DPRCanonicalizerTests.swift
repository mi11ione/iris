// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates DPR text rendering (via `Instruction.text`) for every
/// DPR instruction class + the SP-extended display-collapse rule + the
/// condition-name canonical mapping + every operand-variant render path.
@Suite("DPR / Canonicalizer text rendering")
struct DPRCanonicalizerTests {
    private func canonical(_ encoding: UInt32) -> String {
        let d = decode(encoding, at: 0)
        return d.text
    }

    @Test func undefinedRendersLongDirective() {
        // Undefined records render the raw word as `.long` (text is
        // total).
        let d = Instruction(address: 0, encoding: 0xDEAD_BEEF, mnemonic: .undefined, category: .undefined)
        #expect(d.isUndefined)
        #expect(d.text == ".long 0xdeadbeef")
        // The DPR formatter's own defensive arm (reachable only via a
        // hand-built family-category record) still yields "".
        let armed = Instruction(address: 0, encoding: 0, mnemonic: .undefined, category: .dataProcessingRegister)
        #expect(armed.text == "")
    }

    @Test func addNoShift() {
        #expect(canonical(0x8B02_0020) == "add x0, x1, x2")
    }

    @Test func addLslShiftDisplays() {
        #expect(canonical(0x8B02_0C20) == "add x0, x1, x2, lsl #3")
    }

    @Test func addLsrShiftDisplays() {
        #expect(canonical(0x8B42_0C20) == "add x0, x1, x2, lsr #3")
    }

    @Test func addAsrShiftDisplays() {
        #expect(canonical(0x8B82_0C20) == "add x0, x1, x2, asr #3")
    }

    @Test func add32Bit() {
        #expect(canonical(0x0B02_0020) == "add w0, w1, w2")
    }

    @Test func cmpAliasRenders() {
        #expect(canonical(0xEB02_003F) == "cmp x1, x2")
    }

    @Test func cmnAliasRenders() {
        #expect(canonical(0xAB02_003F) == "cmn x1, x2")
    }

    @Test func negAliasRenders() {
        #expect(canonical(0xCB01_03E0) == "neg x0, x1")
    }

    @Test func negsAliasRenders() {
        #expect(canonical(0xEB01_03E0) == "negs x0, x1")
    }

    @Test func extendedUxtxWithSpCollapsesToBareAtSf1() {
        // SP-collapse: UXTX-with-SP at sf=1 → "add sp, x1, x2".
        #expect(canonical(0x8B22_603F) == "add sp, x1, x2")
    }

    @Test func extendedUxtxWithSpAtNonZeroShiftRendersAsLsl() {
        // SP-collapse: UXTX-with-SP at sf=1, shift > 0 → "add sp, x1, x2, lsl #N".
        #expect(canonical(0x8B22_643F) == "add sp, x1, x2, lsl #1")
    }

    @Test func extendedUxtwWithWspAtSf0CollapsesToBare() {
        // SP-collapse: UXTW-with-WSP at sf=0 → "add wsp, w1, w2".
        #expect(canonical(0x0B22_403F) == "add wsp, w1, w2")
    }

    @Test func extendedUxtwWithWspAtSf0NonZeroShiftRendersAsLsl() {
        // Encoding 0x0B22_483F has imm3=010=2.
        #expect(canonical(0x0B22_483F) == "add wsp, w1, w2, lsl #2")
    }

    @Test func extendedSxtxWithSpKeepsExtendKeyword() {
        // SXTX never collapses, even with SP at sf=1.
        #expect(canonical(0x8B22_E03F) == "add sp, x1, x2, sxtx")
    }

    @Test func extendedUxtwWithSpAtSf1KeepsExtendKeyword() {
        // UXTW at sf=1 (with SP) does NOT collapse — natural extend is UXTX, not UXTW.
        #expect(canonical(0x8B22_403F) == "add sp, x1, w2, uxtw")
    }

    @Test func extendedUxtwAtNoSpRendersExtend() {
        // No SP present → no collapse, extend keyword shown.
        #expect(canonical(0x8B22_4020) == "add x0, x1, w2, uxtw")
    }

    @Test func extendedUxtwAtShiftKeepsKeywordAndAmount() {
        #expect(canonical(0x8B22_4820) == "add x0, x1, w2, uxtw #2")
    }

    @Test func extendedSxtwRenders() {
        #expect(canonical(0x8B22_C020) == "add x0, x1, w2, sxtw")
    }

    @Test func andRenders() {
        #expect(canonical(0x8A02_0020) == "and x0, x1, x2")
    }

    @Test func andWithRorShift() {
        #expect(canonical(0x8AC2_1420) == "and x0, x1, x2, ror #5")
    }

    @Test func bicRenders() {
        #expect(canonical(0x8A22_0020) == "bic x0, x1, x2")
    }

    @Test func ornRenders() {
        #expect(canonical(0xAA22_0020) == "orn x0, x1, x2")
    }

    @Test func eonRenders() {
        #expect(canonical(0xCA22_0020) == "eon x0, x1, x2")
    }

    @Test func bicsRenders() {
        #expect(canonical(0xEA22_0020) == "bics x0, x1, x2")
    }

    @Test func eorRenders() {
        #expect(canonical(0xCA02_0020) == "eor x0, x1, x2")
    }

    @Test func andsRenders() {
        #expect(canonical(0xEA02_0020) == "ands x0, x1, x2")
    }

    @Test func orrRenders() {
        #expect(canonical(0xAA02_0020) == "orr x0, x1, x2")
    }

    @Test func movRegisterAlias() {
        #expect(canonical(0xAA02_03E0) == "mov x0, x2")
    }

    @Test func mvnAlias() {
        #expect(canonical(0xAA22_03E0) == "mvn x0, x2")
    }

    @Test func mvnAliasWithShift() {
        #expect(canonical(0xAA22_0FE0) == "mvn x0, x2, lsl #3")
    }

    @Test func tstAlias() {
        #expect(canonical(0xEA02_003F) == "tst x1, x2")
    }

    @Test func adcRenders() {
        #expect(canonical(0x9A02_0020) == "adc x0, x1, x2")
    }

    @Test func adcsRenders() {
        #expect(canonical(0xBA02_0020) == "adcs x0, x1, x2")
    }

    @Test func sbcRenders() {
        #expect(canonical(0xDA02_0020) == "sbc x0, x1, x2")
    }

    @Test func sbcsRenders() {
        #expect(canonical(0xFA02_0020) == "sbcs x0, x1, x2")
    }

    @Test func ngcAlias() {
        #expect(canonical(0xDA01_03E0) == "ngc x0, x1")
    }

    @Test func ngcsAlias() {
        #expect(canonical(0xFA01_03E0) == "ngcs x0, x1")
    }

    @Test func ccmpRegRenders() {
        #expect(canonical(0xFA42_0025) == "ccmp x1, x2, #5, eq")
    }

    @Test func ccmpImmRenders() {
        #expect(canonical(0xFA40_0825) == "ccmp x1, #0, #5, eq")
    }

    @Test func ccmnRegRenders() {
        #expect(canonical(0xBA42_1025) == "ccmn x1, x2, #5, ne")
    }

    @Test func cselRenders() {
        #expect(canonical(0x9A82_0020) == "csel x0, x1, x2, eq")
    }

    @Test func csincRenders() {
        #expect(canonical(0x9A82_0420) == "csinc x0, x1, x2, eq")
    }

    @Test func csinvRenders() {
        #expect(canonical(0xDA82_0020) == "csinv x0, x1, x2, eq")
    }

    @Test func csnegRenders() {
        #expect(canonical(0xDA82_0420) == "csneg x0, x1, x2, eq")
    }

    @Test func csetAlias() {
        #expect(canonical(0x9A9F_07E0) == "cset x0, ne")
    }

    @Test func csetmAlias() {
        #expect(canonical(0xDA9F_03E0) == "csetm x0, ne")
    }

    @Test func cincAlias() {
        #expect(canonical(0x9A81_0420) == "cinc x0, x1, ne")
    }

    @Test func cinvAlias() {
        #expect(canonical(0xDA81_0020) == "cinv x0, x1, ne")
    }

    @Test func cnegAlias() {
        #expect(canonical(0xDA81_0420) == "cneg x0, x1, ne")
    }

    @Test func cnegWithXZR() {
        #expect(canonical(0xDA9F_07E0) == "cneg x0, xzr, ne")
    }

    @Test func maddRenders() {
        #expect(canonical(0x9B02_0C20) == "madd x0, x1, x2, x3")
    }

    @Test func msubRenders() {
        #expect(canonical(0x9B02_8C20) == "msub x0, x1, x2, x3")
    }

    @Test func mulAlias() {
        #expect(canonical(0x9B02_7C20) == "mul x0, x1, x2")
    }

    @Test func mnegAlias() {
        #expect(canonical(0x9B02_FC20) == "mneg x0, x1, x2")
    }

    @Test func smaddl() {
        #expect(canonical(0x9B22_0C20) == "smaddl x0, w1, w2, x3")
    }

    @Test func smull() {
        #expect(canonical(0x9B22_7C20) == "smull x0, w1, w2")
    }

    @Test func smnegl() {
        #expect(canonical(0x9B22_FC20) == "smnegl x0, w1, w2")
    }

    @Test func smsubl() {
        #expect(canonical(0x9B22_8C20) == "smsubl x0, w1, w2, x3")
    }

    @Test func smulh() {
        #expect(canonical(0x9B42_7C20) == "smulh x0, x1, x2")
    }

    @Test func umaddl() {
        #expect(canonical(0x9BA2_0C20) == "umaddl x0, w1, w2, x3")
    }

    @Test func umsubl() {
        #expect(canonical(0x9BA2_8C20) == "umsubl x0, w1, w2, x3")
    }

    @Test func umull() {
        #expect(canonical(0x9BA2_7C20) == "umull x0, w1, w2")
    }

    @Test func umnegl() {
        #expect(canonical(0x9BA2_FC20) == "umnegl x0, w1, w2")
    }

    @Test func umulh() {
        #expect(canonical(0x9BC2_7C20) == "umulh x0, x1, x2")
    }

    @Test func udivRenders() {
        #expect(canonical(0x9AC2_0820) == "udiv x0, x1, x2")
    }

    @Test func sdivRenders() {
        #expect(canonical(0x9AC2_0C20) == "sdiv x0, x1, x2")
    }

    @Test func lslRegisterRenders() {
        #expect(canonical(0x9AC2_2020) == "lsl x0, x1, x2")
    }

    @Test func lsrRegisterRenders() {
        #expect(canonical(0x9AC2_2420) == "lsr x0, x1, x2")
    }

    @Test func asrRegisterRenders() {
        #expect(canonical(0x9AC2_2820) == "asr x0, x1, x2")
    }

    @Test func rorRegisterRenders() {
        #expect(canonical(0x9AC2_2C20) == "ror x0, x1, x2")
    }

    @Test func crc32bRenders() {
        #expect(canonical(0x1AC2_4020) == "crc32b w0, w1, w2")
    }

    @Test func crc32hRenders() {
        #expect(canonical(0x1AC2_4420) == "crc32h w0, w1, w2")
    }

    @Test func crc32wRenders() {
        #expect(canonical(0x1AC2_4820) == "crc32w w0, w1, w2")
    }

    @Test func crc32xRenders() {
        #expect(canonical(0x9AC2_4C20) == "crc32x w0, w1, x2")
    }

    @Test func crc32cbRenders() {
        #expect(canonical(0x1AC2_5020) == "crc32cb w0, w1, w2")
    }

    @Test func crc32chRenders() {
        #expect(canonical(0x1AC2_5420) == "crc32ch w0, w1, w2")
    }

    @Test func crc32cwRenders() {
        #expect(canonical(0x1AC2_5820) == "crc32cw w0, w1, w2")
    }

    @Test func crc32cxRenders() {
        #expect(canonical(0x9AC2_5C20) == "crc32cx w0, w1, x2")
    }

    @Test func rbitRenders() {
        #expect(canonical(0xDAC0_0020) == "rbit x0, x1")
    }

    @Test func rev16Renders() {
        #expect(canonical(0xDAC0_0420) == "rev16 x0, x1")
    }

    @Test func rev32Renders() {
        #expect(canonical(0xDAC0_0820) == "rev32 x0, x1")
    }

    @Test func revRenders() {
        #expect(canonical(0xDAC0_0C20) == "rev x0, x1")
    }

    @Test func clzRenders() {
        #expect(canonical(0xDAC0_1020) == "clz x0, x1")
    }

    @Test func clsRenders() {
        #expect(canonical(0xDAC0_1420) == "cls x0, x1")
    }

    @Test func conditionCsRendersAsHs() {
        // CCMP x1, x2, #0, CS → "ccmp x1, x2, #0, hs"
        #expect(canonical(0xFA42_2020) == "ccmp x1, x2, #0, hs")
    }

    @Test func conditionCcRendersAsLo() {
        #expect(canonical(0xFA42_3020) == "ccmp x1, x2, #0, lo")
    }

    @Test func everyConditionRendersLowercase() {
        let expected = ["eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
                        "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"]
        for (raw, name) in expected.enumerated() {
            let encoding: UInt32 = 0xFA42_0020 | (UInt32(raw) << 12)
            let text = canonical(encoding)
            #expect(text.hasSuffix(", \(name)"), "cond=\(raw) → expected suffix `, \(name)`, got `\(text)`")
        }
    }

    @Test func wspRenders() {
        // ADD w0, wsp, #imm doesn't apply (immediate-form is DPI's), but
        // ADD wsp, w1, w2 extended hits wsp via Rd.
        let d = decode(0x0B22_403F, at: 0)
        // After SP-collapse: "add wsp, w1, w2".
        #expect(d.text == "add wsp, w1, w2")
    }

    @Test func wzrRenders() {
        // SUBS wzr, w1, w2 → cmp w1, w2 (alias drops Rd). To exercise
        // bare wzr rendering, construct a draft directly with .wzr().
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .add,
            category: .dataProcessingRegister,
            operands: [.register(.wzr()), .register(.w(1)), .register(.w(2))],
        )
        #expect(draft.text == "add wzr, w1, w2")
    }

    @Test func xzrRenders() {
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .add,
            category: .dataProcessingRegister,
            operands: [.register(.xzr()), .register(.x(1)), .register(.x(2))],
        )
        #expect(draft.text == "add xzr, x1, x2")
    }

    @Test func simdRegisterRenders() {
        // DPR never emits SIMD, but the canonicalizer's registerText fallback
        // must handle it for defensive completeness.
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .add,
            category: .dataProcessingRegister,
            operands: [.register(.simd(3))],
        )
        #expect(draft.text == "add v3")
    }

    @Test func unknownRegisterIndexRendersWithQuestionMark() {
        // canonicalIndex >= 64 is defensive — the decoder never
        // produces one, but registerText returns "?N" as a safe sentinel.
        let weirdReg = RegisterRef(canonicalIndex: 100, role: .general, width: .x64)
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .add,
            category: .dataProcessingRegister,
            operands: [.register(weirdReg)],
        )
        #expect(draft.text == "add ?100")
    }

    @Test func unsupportedOperandRendersSentinel() {
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .add,
            category: .dataProcessingRegister,
            operands: [.label(byteOffset: 4)],
        )
        #expect(draft.text == "add ?unsupported-operand")
    }

    @Test func mslShiftKindRenders() {
        // DPR instructions don't emit .msl naturally, but the canonicalizer
        // includes the case for completeness in case SIMD/FP's AdvSIMD
        // modified-immediate ever shares a code path. A direct value
        // exercises it.
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .add,
            category: .dataProcessingRegister,
            operands: [.shiftedRegister(reg: .x(1), shift: .msl, amount: 8)],
        )
        #expect(draft.text == "add x1, msl #8")
    }

    @Test func signedImmediateOperandRenders() {
        // .immediate is allowed by the formatter but DPR doesn't emit it.
        // Constructing directly to cover the rendering branch.
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .add,
            category: .dataProcessingRegister,
            operands: [.immediate(value: -42, width: 12)],
        )
        #expect(draft.text == "add #-42")
    }

    @Test func foreignMnemonicResolvesThroughConsolidatedName() {
        // Mnemonic names are consolidated: a hand-built DPR-category
        // record carrying a BES-range mnemonic renders that mnemonic's
        // real name; only unallocated raw values fall back to "?<raw>".
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .b,
            category: .dataProcessingRegister,
        )
        #expect(draft.text == "b")
        let unallocated = Instruction(
            address: 0, encoding: 0, mnemonic: Mnemonic(rawValue: 5000),
            category: .dataProcessingRegister,
        )
        #expect(unallocated.text == "?5000")
    }

    // canonicalizer defensively handles them).

    @Test func extendKindUxtbRenders() {
        // ADD x0, x1, w2, UXTB. sf=1 + UXTB → Rm renders as Wn.
        #expect(canonical(0x8B22_0020) == "add x0, x1, w2, uxtb")
    }

    @Test func extendKindUxthRenders() {
        #expect(canonical(0x8B22_2020) == "add x0, x1, w2, uxth")
    }

    @Test func extendKindUxtxWithoutSpRenders() {
        // UXTX without SP doesn't collapse → renders "uxtx". sf=1 + UXTX → Xn.
        #expect(canonical(0x8B22_6020) == "add x0, x1, x2, uxtx")
    }

    @Test func extendKindSxtbRenders() {
        #expect(canonical(0x8B22_8020) == "add x0, x1, w2, sxtb")
    }

    @Test func extendKindSxthRenders() {
        #expect(canonical(0x8B22_A020) == "add x0, x1, w2, sxth")
    }

    @Test func extendKindNoneDefensiveRender() {
        // Decoder never produces .none, but the canonicalizer's
        // extendKindName must handle it defensively (returns "").
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .add,
            category: .dataProcessingRegister,
            operands: [
                .register(.x(0)),
                .register(.x(1)),
                .extendedRegister(reg: .x(2), extend: .none, shift: 0),
            ],
        )
        // Renders "x2, " (empty extend keyword after the comma).
        let text = draft.text
        #expect(text == "add x0, x1, x2, ", "extend=.none renders empty keyword")
    }

    @Test func extendKindLslDefensiveRender() {
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .add,
            category: .dataProcessingRegister,
            operands: [
                .register(.x(0)),
                .register(.x(1)),
                .extendedRegister(reg: .x(2), extend: .lsl, shift: 0),
            ],
        )
        #expect(draft.text == "add x0, x1, x2, lsl")
    }

    @Test func addsBaseMnemonicRendersDirectly() {
        // adds is hit by extended path with Rd != 31 (ADDS x1, x2, x3, UXTX).
        #expect(canonical(0xAB23_6041) == "adds x1, x2, x3, uxtx")
    }

    @Test func subBaseMnemonicRendersDirectly() {
        // SUB x0, x1, x2, UXTX (no SP → keeps extend keyword).
        #expect(canonical(0xCB22_6020) == "sub x0, x1, x2, uxtx")
    }

    @Test func subsBaseMnemonicRendersDirectly() {
        #expect(canonical(0xEB23_6041) == "subs x1, x2, x3, uxtx")
    }

    // The mnemonicName switch must still handle them.

    @Test func lslvMnemonicRendersDirectly() {
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .lslv,
            category: .dataProcessingRegister,
            operands: [.register(.x(0)), .register(.x(1)), .register(.x(2))],
        )
        #expect(draft.text == "lslv x0, x1, x2")
    }

    @Test func lsrvMnemonicRendersDirectly() {
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .lsrv,
            category: .dataProcessingRegister,
            operands: [.register(.x(0)), .register(.x(1)), .register(.x(2))],
        )
        #expect(draft.text == "lsrv x0, x1, x2")
    }

    @Test func asrvMnemonicRendersDirectly() {
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .asrv,
            category: .dataProcessingRegister,
            operands: [.register(.x(0)), .register(.x(1)), .register(.x(2))],
        )
        #expect(draft.text == "asrv x0, x1, x2")
    }

    @Test func rorvMnemonicRendersDirectly() {
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .rorv,
            category: .dataProcessingRegister,
            operands: [.register(.x(0)), .register(.x(1)), .register(.x(2))],
        )
        #expect(draft.text == "rorv x0, x1, x2")
    }

    // register (covers the `else continue` branch in the loop).

    @Test func spCollapseFromRnSPAtSf1() {
        // ADD x0, sp, x2, UXTX #0 — Rn is SP, Rd is general.
        #expect(canonical(0x8B22_63E0) == "add x0, sp, x2")
    }

    @Test func spCollapseFromBothRdAndRnSP() {
        // ADD sp, sp, x2, UXTX #0.
        #expect(canonical(0x8B22_63FF) == "add sp, sp, x2")
    }

    @Test func wspCollapseFromRnWSPAtSf0() {
        // ADD w0, wsp, w2, UXTW #0.
        #expect(canonical(0x0B22_43E0) == "add w0, wsp, w2")
    }

    @Test func spCollapseDoesNotFireWhenPrecedingOperandIsNotRegister() {
        // Construct a draft where operand[0] is a NON-register, followed
        // by .extendedRegister(.uxtx, 0). The collapse rule should NOT fire
        // because there's no preceding stackPointer-role register.
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .add,
            category: .dataProcessingRegister,
            operands: [
                .unsignedImmediate(value: 1, width: 4),
                .extendedRegister(reg: .x(2), extend: .uxtx, shift: 0),
            ],
        )
        // Should keep the extend keyword (collapse predicate fails).
        #expect(draft.text == "add #1, x2, uxtx")
    }

    @Test func cryptoOwnedMnemonicsRouteToTheCryptoFormatter() {
        // Crypto-owned mnemonics on a DPR-category record (hand-built;
        // real PAC/MTE records decode with their own categories) route
        // to the crypto/Apple-extensions formatter.
        let irg = Instruction(mnemonic: .irg, category: .dataProcessingRegister)
        #expect(irg.text == "irg")
    }
}
