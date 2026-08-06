// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func draft(_ mnemonic: Mnemonic, _ operands: [Operand]) -> Instruction {
    Instruction(
        address: 0, encoding: 0, mnemonic: mnemonic,
        category: .loadsAndStores, operands: operands,
    )
}

/// Validates `LSCanonicalizer.format`'s per-operand rendering rules and its
/// defensive fallbacks for shapes the L/S decoders never emit.
@Suite("L/S canonicalizer formatting")
struct LSCanonicalizerTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func undefinedRecordRendersLongDirective() {
        let d = decode(0x0900_0000)
        #expect(d.isUndefined)
        #expect(d.text == ".long 0x9000000")
        let armed = Instruction(address: 0, encoding: 0, mnemonic: .undefined, category: .loadsAndStores)
        #expect(armed.text == "")
    }

    @Test func everyMnemonicRendersItsLowercaseName() {
        for (mnemonic, _, name) in LSMnemonicConstantsTests.allLSMnemonics {
            #expect(draft(mnemonic, []).text == name)
        }
    }

    @Test func nonLoadStoreMnemonicResolvesThroughConsolidatedName() {
        #expect(draft(.add, []).text == "add")
        #expect(draft(Mnemonic(rawValue: 3000), []).text == "?3000")
    }

    @Test func bareBaseRegisterMemoryOperand() {
        #expect(decode(0xF940_0000).text == "ldr x0, [x0]")
    }

    @Test func immediateOffsetMemoryOperand() {
        #expect(decode(0xB900_0400).text == "str w0, [x0, #4]")
    }

    @Test func preIndexMemoryOperandRendersBangAfterBracket() {
        #expect(decode(0xB850_0C00).text == "ldr w0, [x0, #-256]!")
    }

    @Test func postIndexMemoryOperandRendersCommaAfterBracket() {
        #expect(decode(0xF85F_F400).text == "ldr x0, [x0], #-1")
    }

    @Test func pcRelativeLiteralRendersAsBareImmediate() {
        #expect(decode(0x1800_0020).text == "ldr w0, #4")
    }

    @Test func registerOffsetLslCollapsesToBareIndex() {
        #expect(decode(0x3820_6800).text == "strb w0, [x0, x0]")
    }

    @Test func registerOffsetExtendWithoutAmount() {
        #expect(decode(0x3820_4800).text == "strb w0, [x0, w0, uxtw]")
    }

    @Test func registerOffsetExtendWithAmount() {
        #expect(decode(0xF820_7800).text == "str x0, [x0, x0, lsl #3]")
    }

    @Test func stackPointerBaseRendersAsSp() {
        #expect(decode(0xB800_03E0).text == "stur w0, [sp]")
    }

    @Test func zeroRegisterOperandsRenderAsWzrAndXzr() {
        #expect(decode(0x1800_001F).text == "ldr wzr, #0")
        #expect(decode(0x5800_001F).text == "ldr xzr, #0")
    }

    @Test func stackPointerWordFormRendersAsWsp() {
        let formatted = draft(.ldr, [.register(.wsp())]).text
        #expect(formatted == "ldr wsp")
    }

    @Test func simdRegisterIndexRendersAsVn() {
        let formatted = draft(.ldr, [.register(.simd(3))]).text
        #expect(formatted == "ldr v3")
    }

    @Test func outOfRangeRegisterIndexRendersAsSentinel() {
        let reg = RegisterRef(canonicalIndex: 64, role: .general, width: .x64)
        #expect(draft(.ldr, [.register(reg)]).text == "ldr ?64")
    }

    @Test func immediateOperandsRenderWithHashPrefix() {
        #expect(draft(.ldr, [.immediate(value: -7, width: 8)]).text == "ldr #-7")
        #expect(draft(.ldr, [.unsignedImmediate(value: 9, width: 8)]).text == "ldr #9")
    }

    @Test func unsupportedOperandKindRendersAsSentinel() {
        #expect(draft(.ldr, [.label(byteOffset: 0)]).text == "ldr ?unsupported-operand")
    }

    @Test func everyExtendKeywordRenders() {
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
        let pli = draft(.prfm, [.prefetchOperation(PrefetchOperation(rawValue: 8))]).text
        #expect(pli == "prfm plil1keep")
        let reservedLevel = draft(.prfm, [.prefetchOperation(PrefetchOperation(rawValue: 6))]).text
        #expect(reservedLevel == "prfm pldslckeep")
        let reservedOp = draft(.prfm, [.prefetchOperation(PrefetchOperation(rawValue: 31))]).text
        #expect(reservedOp == "prfm #31")
    }

    @Test func rprfmRendersSymbolicAndNumericPrefetchOperands() {
        #expect(decode(0xF8A2_4838).text == "rprfm pldkeep, x2, [x1]")
        #expect(decode(0xF8A2_4839).text == "rprfm pstkeep, x2, [x1]")
        #expect(decode(0xF8A2_483C).text == "rprfm pldstrm, x2, [x1]")
        #expect(decode(0xF8A2_483D).text == "rprfm pststrm, x2, [x1]")
        #expect(decode(0xF8A2_C83A).text == "rprfm #34, x2, [x1]")
    }

    @Test func rprfmWithForeignOperandShapeFallsBackToGenericFormatting() {
        let d = draft(.rprfm, [.register(.x(0)), .register(.x(1)), .register(.x(2))])
        #expect(d.text == "rprfm x0, x1, x2")
    }

    @Test func mopsRecordWithForeignOperandShapeRendersBareMnemonic() {
        let d = draft(.cpyfp, [.register(.x(0)), .unsignedImmediate(value: 1, width: 4)])
        #expect(d.text == "cpyfp ")
    }

    @Test func setGORecordWithForeignOperandShapeRendersBareMnemonic() {
        #expect(draft(.setgop, [.register(.x(0))]).text == "setgop ")
        #expect(draft(.setgoetn, [
            .register(.x(0)), .unsignedImmediate(value: 1, width: 4),
        ]).text == "setgoetn ")
    }

    @Test func cryptoOwnedMnemonicsRouteToTheCryptoFormatter() {
        #expect(draft(.stg, []).text == "stg")
    }
}
