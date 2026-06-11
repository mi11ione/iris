// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Builds a minimal L/S draft for exercising `LSCanonicalizer` paths the
/// decoder itself never produces (crafted operand kinds, non-L/S
/// mnemonics, out-of-range registers).
private func draft(_ mnemonic: Mnemonic, _ operands: [Operand]) -> Instruction {
    Instruction(
        address: 0, encoding: 0, mnemonic: mnemonic,
        category: .loadsAndStores, operands: operands,
    )
}

/// Validates `LSCanonicalizer.format` — the disassembly-text layer. The
/// golden-corpus suite proves text parity end-to-end; this suite targets
/// the per-operand rendering rules and the defensive
/// fallbacks for operand shapes the L/S decoders never emit.
@Suite("L/S canonicalizer formatting")
struct LSCanonicalizerTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func undefinedRecordRendersLongDirective() {
        // A reserved encoding decodes to UNDEFINED and renders as a
        // `.long` directive (text is total).
        let d = decode(0x0900_0000)
        #expect(d.isUndefined)
        #expect(d.text == ".long 0x9000000")
        // The L/S formatter's own defensive arm (reachable only via a
        // hand-built family-category record) still yields "".
        let armed = Instruction(address: 0, encoding: 0, mnemonic: .undefined, category: .loadsAndStores)
        #expect(armed.text == "")
    }

    @Test func everyMnemonicRendersItsLowercaseName() {
        // With no operands `format` returns the bare mnemonic text — this
        // exercises every arm of the canonicalizer's mnemonic switch.
        for (mnemonic, _, name) in LSMnemonicConstantsTests.allLSMnemonics {
            #expect(draft(mnemonic, []).text == name)
        }
    }

    @Test func nonLoadStoreMnemonicResolvesThroughConsolidatedName() {
        // Mnemonic names are consolidated: a hand-built L/S-category
        // record carrying a DPI-range mnemonic renders that mnemonic's
        // real name; only unallocated raw values fall back to "?<raw>".
        #expect(draft(.add, []).text == "add")
        #expect(draft(Mnemonic(rawValue: 3000), []).text == "?3000")
    }

    @Test func bareBaseRegisterMemoryOperand() {
        // 0xf9400000 = ldr x0, [x0] — zero displacement drops the `#0`.
        #expect(decode(0xF940_0000).text == "ldr x0, [x0]")
    }

    @Test func immediateOffsetMemoryOperand() {
        // 0xb9000400 = str w0, [x0, #4].
        #expect(decode(0xB900_0400).text == "str w0, [x0, #4]")
    }

    @Test func preIndexMemoryOperandRendersBangAfterBracket() {
        // 0xb8500c00 = ldr w0, [x0, #-256]!.
        #expect(decode(0xB850_0C00).text == "ldr w0, [x0, #-256]!")
    }

    @Test func postIndexMemoryOperandRendersCommaAfterBracket() {
        // 0xf85ff400 = ldr x0, [x0], #-1.
        #expect(decode(0xF85F_F400).text == "ldr x0, [x0], #-1")
    }

    @Test func pcRelativeLiteralRendersAsBareImmediate() {
        // 0x18000020 = ldr w0, #4 — PC-base literal, no brackets.
        #expect(decode(0x1800_0020).text == "ldr w0, #4")
    }

    @Test func registerOffsetLslCollapsesToBareIndex() {
        // 0x38206800 = strb w0, [x0, x0] — option=LSL, S=0 collapses.
        #expect(decode(0x3820_6800).text == "strb w0, [x0, x0]")
    }

    @Test func registerOffsetExtendWithoutAmount() {
        // 0x38204800 = strb w0, [x0, w0, uxtw] — S=0 omits the #amount.
        #expect(decode(0x3820_4800).text == "strb w0, [x0, w0, uxtw]")
    }

    @Test func registerOffsetExtendWithAmount() {
        // 0xf8207800 = str x0, [x0, x0, lsl #3] — S=1 shows the #amount.
        #expect(decode(0xF820_7800).text == "str x0, [x0, x0, lsl #3]")
    }

    @Test func stackPointerBaseRendersAsSp() {
        // 0xb80003e0 = stur w0, [sp].
        #expect(decode(0xB800_03E0).text == "stur w0, [sp]")
    }

    @Test func zeroRegisterOperandsRenderAsWzrAndXzr() {
        // 0x1800001f = ldr wzr, #0; 0x5800001f = ldr xzr, #0.
        #expect(decode(0x1800_001F).text == "ldr wzr, #0")
        #expect(decode(0x5800_001F).text == "ldr xzr, #0")
    }

    @Test func stackPointerWordFormRendersAsWsp() {
        // WSP appears in no decoded L/S operand — render it via a draft.
        let formatted = draft(.ldr, [.register(.wsp())]).text
        #expect(formatted == "ldr wsp")
    }

    @Test func simdRegisterIndexRendersAsVn() {
        // canonicalIndex 32..63 renders as v0..v31.
        let formatted = draft(.ldr, [.register(.simd(3))]).text
        #expect(formatted == "ldr v3")
    }

    @Test func outOfRangeRegisterIndexRendersAsSentinel() {
        // canonicalIndex >= 64 is neither GPR nor SIMD — `?N` fallback.
        let reg = RegisterRef(canonicalIndex: 64, role: .general, width: .x64)
        #expect(draft(.ldr, [.register(reg)]).text == "ldr ?64")
    }

    @Test func immediateOperandsRenderWithHashPrefix() {
        // `.immediate` / `.unsignedImmediate` are not produced by L/S
        // decoders but the canonicalizer renders them defensively.
        #expect(draft(.ldr, [.immediate(value: -7, width: 8)]).text == "ldr #-7")
        #expect(draft(.ldr, [.unsignedImmediate(value: 9, width: 8)]).text == "ldr #9")
    }

    @Test func unsupportedOperandKindRendersAsSentinel() {
        // `.label` is a control-flow operand — never an L/S operand.
        #expect(draft(.ldr, [.label(byteOffset: 0)]).text == "ldr ?unsupported-operand")
    }

    @Test func everyExtendKeywordRenders() {
        // The decoder only emits uxtw/sxtw/sxtx/lsl; craft the rest so
        // every arm of the extend-keyword switch is exercised.
        let extends: [(ExtendKind, String)] = [
            (.uxtb, "uxtb"), (.uxth, "uxth"), (.uxtw, "uxtw"), (.uxtx, "uxtx"),
            (.sxtb, "sxtb"), (.sxth, "sxth"), (.sxtw, "sxtw"), (.sxtx, "sxtx"),
            (.lsl, "lsl"),
        ]
        for (kind, keyword) in extends {
            let mem = MemoryOperand(
                base: .register(.x(1)), index: .x(2),
                displacement: 0, extend: kind, shift: 0, writeback: .none,
            )
            let formatted = draft(.ldr, [.register(.x(0)), .memory(mem)]).text
            #expect(formatted == "ldr x0, [x1, x2, \(keyword) #0]", "extend \(keyword)")
        }
    }

    @Test func prefetchOperationRendersSymbolicAndReservedForms() {
        // pli (instruction prefetch) and reserved-level forms.
        let pli = draft(.prfm, [.prefetchOperation(PrefetchOperation(rawValue: 8))]).text
        #expect(pli == "prfm plil1keep")
        let reservedLevel = draft(.prfm, [.prefetchOperation(PrefetchOperation(rawValue: 6))]).text
        #expect(reservedLevel == "prfm pldslckeep")
        let reservedOp = draft(.prfm, [.prefetchOperation(PrefetchOperation(rawValue: 31))]).text
        #expect(reservedOp == "prfm #31")
    }

    @Test func rprfmRendersSymbolicAndNumericPrefetchOperands() {
        // The 6-bit range-prefetch operand has symbolic names only for
        // {0, 1, 4, 5}; every other value renders numeric.
        #expect(decode(0xF8A2_4838).text == "rprfm pldkeep, x2, [x1]")
        #expect(decode(0xF8A2_4839).text == "rprfm pstkeep, x2, [x1]")
        #expect(decode(0xF8A2_483C).text == "rprfm pldstrm, x2, [x1]")
        #expect(decode(0xF8A2_483D).text == "rprfm pststrm, x2, [x1]")
        #expect(decode(0xF8A2_C83A).text == "rprfm #34, x2, [x1]")
    }

    @Test func rprfmWithForeignOperandShapeFallsBackToGenericFormatting() {
        // Hand-built RPRFM whose operands are not (imm, reg, mem) — the
        // dedicated renderer declines and the generic formatter runs.
        let d = draft(.rprfm, [.register(.x(0)), .register(.x(1)), .register(.x(2))])
        #expect(d.text == "rprfm x0, x1, x2")
    }

    @Test func mopsRecordWithForeignOperandShapeRendersBareMnemonic() {
        // The MOPS renderer requires exactly three register operands; a
        // hand-built record with any other shape renders no operand text.
        let d = draft(.cpyfp, [.register(.x(0)), .unsignedImmediate(value: 1, width: 4)])
        #expect(d.text == "cpyfp ")
    }

    @Test func cryptoOwnedMnemonicsRouteToTheCryptoFormatter() {
        // Crypto-owned mnemonics on an L/S-category record (hand-built;
        // real MTE records decode with category .memoryTagging) route to
        // the crypto/Apple-extensions formatter.
        #expect(draft(.stg, []).text == "stg")
    }
}
