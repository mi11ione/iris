// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates `DPICanonicalizer.format(draft:)` — the public Sources/
/// Iris/Disassembler/ formatter that produces llvm-mc-compatible
/// disassembly text from a `Instruction`. Each test crafts a draft
/// directly so the formatter is exercised in isolation from the per-
/// family decoders.
@Suite("Disassembler / DPICanonicalizer.format")
struct DPICanonicalizerFormatTests {
    private func draft(
        mnemonic: Mnemonic,
        operands: [Operand],
        flagEffect: FlagEffect = .none,
        category: Category = .dataProcessingImmediate,
    ) -> Instruction {
        Instruction(
            address: 0,
            encoding: 0,
            mnemonic: mnemonic,
            flagEffect: flagEffect,
            category: category,
            operands: operands,
        )
    }

    @Test func undefinedRecordRendersLongDirective() {
        // Undefined records render the raw word as `.long` (the text
        // router owns sentinel rendering — text is total).
        let d = draft(mnemonic: .undefined, operands: [], category: .undefined)
        #expect(d.text == ".long 0x0")
        // The DPI formatter's own defensive arm (reachable only via a
        // hand-built family-category record) still yields "".
        let armed = draft(mnemonic: .undefined, operands: [])
        #expect(armed.text == "")
    }

    @Test func mnemonicWithNoOperandsFormatsAsJustMnemonic() {
        // Defensive — DPI never produces this shape, but the formatter handles it.
        let d = draft(mnemonic: .add, operands: [])
        #expect(d.text == "add")
    }

    @Test func addWithThreeOperandsFormatsCorrectly() {
        let d = draft(mnemonic: .add, operands: [
            .register(.x(0)), .register(.x(1)),
            .unsignedImmediate(value: 1, width: 12),
        ])
        #expect(d.text == "add x0, x1, #1")
    }

    @Test func addWithShiftAmountFormatsLslComma() {
        let d = draft(mnemonic: .add, operands: [
            .register(.x(0)), .register(.x(1)),
            .unsignedImmediate(value: 1, width: 12),
            .shiftAmount(kind: .lsl, amount: 12),
        ])
        #expect(d.text == "add x0, x1, #1, lsl #12")
    }

    @Test func cmpDropsRdFromOperands() {
        let d = draft(mnemonic: .cmp, operands: [
            .register(.x(3)),
            .unsignedImmediate(value: 5, width: 12),
        ], flagEffect: .nzcv)
        #expect(d.text == "cmp x3, #5")
    }

    @Test func tstUsesHexImmediateDisplay() {
        let d = draft(mnemonic: .tst, operands: [
            .register(.x(3)),
            .unsignedImmediate(value: 0xFF, width: 64),
        ], flagEffect: .nzcv)
        #expect(d.text == "tst x3, #0xff")
    }

    @Test func andUsesHexImmediateDisplay() {
        let d = draft(mnemonic: .and, operands: [
            .register(.w(0)), .register(.w(1)),
            .unsignedImmediate(value: 0x7, width: 32),
        ])
        #expect(d.text == "and w0, w1, #0x7")
    }

    @Test func orrUsesHexImmediateDisplay() {
        let d = draft(mnemonic: .orr, operands: [
            .register(.w(0)), .register(.wzr()),
            .unsignedImmediate(value: 0x1, width: 32),
        ])
        #expect(d.text == "orr w0, wzr, #0x1")
    }

    @Test func eorUsesHexImmediateDisplay() {
        let d = draft(mnemonic: .eor, operands: [
            .register(.x(0)), .register(.x(1)),
            .unsignedImmediate(value: 0x33, width: 64),
        ])
        #expect(d.text == "eor x0, x1, #0x33")
    }

    @Test func andsUsesHexImmediateDisplay() {
        let d = draft(mnemonic: .ands, operands: [
            .register(.x(0)), .register(.x(1)),
            .unsignedImmediate(value: 0x1, width: 64),
        ], flagEffect: .nzcv)
        #expect(d.text == "ands x0, x1, #0x1")
    }

    @Test func movBitmaskUsesSignedDecimalForNegativeValue() {
        // MOV bitmask with the high bit set in 32-bit: signed display.
        let d = draft(mnemonic: .mov, operands: [
            .register(.w(0)),
            .immediate(value: -2_147_483_647, width: 32),
        ])
        #expect(d.text == "mov w0, #-2147483647")
    }

    @Test func movWideOfMinusOneUsesSignedDecimal() {
        let d = draft(mnemonic: .mov, operands: [
            .register(.x(0)),
            .immediate(value: -1, width: 64),
        ])
        #expect(d.text == "mov x0, #-1")
    }

    @Test func adrLabelUsesSignedDecimal() {
        let d = draft(mnemonic: .adr, operands: [
            .register(.x(0)),
            .label(byteOffset: -4),
        ])
        #expect(d.text == "adr x0, #-4")
    }

    @Test func adrpPageLabelUsesSignedDecimal() {
        let d = draft(mnemonic: .adrp, operands: [
            .register(.x(0)),
            .pageLabel(byteOffset: -16384),
        ])
        #expect(d.text == "adrp x0, #-16384")
    }

    @Test func bfiFormatsAsFourOperands() {
        let d = draft(mnemonic: .bfi, operands: [
            .register(.x(0)), .register(.x(1)),
            .unsignedImmediate(value: 4, width: 6),
            .unsignedImmediate(value: 5, width: 6),
        ])
        #expect(d.text == "bfi x0, x1, #4, #5")
    }

    @Test func bfcFormatsAsThreeOperands() {
        let d = draft(mnemonic: .bfc, operands: [
            .register(.x(0)),
            .unsignedImmediate(value: 4, width: 6),
            .unsignedImmediate(value: 5, width: 6),
        ])
        #expect(d.text == "bfc x0, #4, #5")
    }

    @Test func bfxilFormatsAsFourOperands() {
        let d = draft(mnemonic: .bfxil, operands: [
            .register(.w(0)), .register(.w(9)),
            .unsignedImmediate(value: 1, width: 6),
            .unsignedImmediate(value: 2, width: 6),
        ])
        #expect(d.text == "bfxil w0, w9, #1, #2")
    }

    @Test func lslFormatsAsThreeOperands() {
        let d = draft(mnemonic: .lsl, operands: [
            .register(.x(0)), .register(.x(1)),
            .unsignedImmediate(value: 4, width: 6),
        ])
        #expect(d.text == "lsl x0, x1, #4")
    }

    @Test func sxtwMixesXdAndWn() {
        let d = draft(mnemonic: .sxtw, operands: [
            .register(.x(0)), .register(.w(1)),
        ])
        #expect(d.text == "sxtw x0, w1")
    }

    @Test func rorFormatsAsThreeOperands() {
        let d = draft(mnemonic: .ror, operands: [
            .register(.x(0)), .register(.x(1)),
            .unsignedImmediate(value: 5, width: 6),
        ])
        #expect(d.text == "ror x0, x1, #5")
    }

    @Test func extrFormatsAsFourOperands() {
        let d = draft(mnemonic: .extr, operands: [
            .register(.x(0)), .register(.x(1)), .register(.x(2)),
            .unsignedImmediate(value: 5, width: 6),
        ])
        #expect(d.text == "extr x0, x1, x2, #5")
    }

    @Test func movzWithShiftFormatsAsThreeOperands() {
        let d = draft(mnemonic: .movz, operands: [
            .register(.x(0)),
            .unsignedImmediate(value: 0x1234, width: 16),
            .shiftAmount(kind: .lsl, amount: 16),
        ])
        #expect(d.text == "movz x0, #4660, lsl #16")
    }

    @Test func movkWithNoShiftFormatsAsTwoOperands() {
        let d = draft(mnemonic: .movk, operands: [
            .register(.x(0)),
            .unsignedImmediate(value: 5, width: 16),
        ])
        #expect(d.text == "movk x0, #5")
    }

    @Test func registerSPFormats() {
        let d = draft(mnemonic: .mov, operands: [
            .register(.x(0)), .register(.sp()),
        ])
        #expect(d.text == "mov x0, sp")
    }

    @Test func registerWSPFormats() {
        let d = draft(mnemonic: .mov, operands: [
            .register(.w(0)), .register(.wsp()),
        ])
        #expect(d.text == "mov w0, wsp")
    }

    @Test func registerXZRFormats() {
        let d = draft(mnemonic: .cmp, operands: [
            .register(.xzr()),
            .unsignedImmediate(value: 0, width: 12),
        ])
        #expect(d.text == "cmp xzr, #0")
    }

    @Test func registerWZRFormats() {
        let d = draft(mnemonic: .cmp, operands: [
            .register(.wzr()),
            .unsignedImmediate(value: 0, width: 12),
        ])
        #expect(d.text == "cmp wzr, #0")
    }

    @Test func registerSimdRendersAsVName() {
        // `.register(.simd(0))` uses canonical-index 32 which the
        // formatter recognises as v0. (The defensive sentinel branch
        // only triggers for `.vectorRegister`, not `.register(.simd)`.)
        let d = draft(mnemonic: .add, operands: [
            .register(.simd(0)),
        ])
        #expect(d.text == "add v0")
    }

    @Test func unknownMnemonicFallsThroughToQuestionMark() {
        // Mnemonic raw values outside the allocated names fall through
        // to the name table's fallback.
        let d = draft(mnemonic: Mnemonic(rawValue: 999), operands: [])
        #expect(d.text == "?999")
    }

    @Test func registerOver64FallsThroughToQuestionMark() {
        // Defensive — register canonical index >= 64 shouldn't be
        // produced by any decoder, but the formatter falls through to
        // a "?N" marker.
        let r = RegisterRef(canonicalIndex: 64, role: .general, width: .x64)
        let d = draft(mnemonic: .add, operands: [.register(r)])
        let out = d.text
        #expect(out.contains("?64"))
    }

    @Test func vectorRegisterDirectVariantHitsSentinel() {
        // The .vectorRegister case (not .register(.simd)) is a defensive
        // sentinel for the DPI formatter — verify it doesn't crash and
        // produces the sentinel marker.
        let vec = VectorRegisterRef(registerIndex: 4, view: .full(arrangement: .s4))
        let d = draft(mnemonic: .add, operands: [.vectorRegister(vec)])
        let out = d.text
        #expect(out.contains("?unsupported-operand"))
    }

    @Test func eachShiftKindRendersCorrectly() {
        for (kind, expected) in [(ShiftKind.lsl, "lsl"), (.lsr, "lsr"), (.asr, "asr"), (.ror, "ror"), (.msl, "msl")] {
            let d = draft(mnemonic: .add, operands: [
                .register(.x(0)),
                .unsignedImmediate(value: 1, width: 12),
                .shiftAmount(kind: kind, amount: 4),
            ])
            #expect(d.text.hasSuffix("\(expected) #4"))
        }
    }

    @Test func allDefensiveOperandSentinelsRenderAsUnsupported() {
        // Hit every Operand case the DPI family doesn't itself emit but the
        // @frozen switch must handle. Each should render as the
        // "?unsupported-operand" sentinel (the formatter never crashes;
        // validation tooling surfaces it).
        let sysReg = SystemRegisterEncoding(op0: 3, op1: 3, crn: 13, crm: 0, op2: 2)
        let mem = MemoryOperand(base: .pc, displacement: 0)
        let prefetch = PrefetchOperation(rawValue: 0)
        let sysOp = SystemOp(rawEncoding: 0)
        let amx = AMXField(rawBits: 0)
        let defensives: [Operand] = [
            .floatImmediate(bits: 0, kind: .single),
            .memory(mem),
            .shiftedRegister(reg: .x(0), shift: .lsl, amount: 0),
            .extendedRegister(reg: .w(0), extend: .uxtw, shift: 0),
            .systemRegister(sysReg),
            .conditionCode(.eq),
            .pstateField(.daifSet),
            .barrierOption(.sy),
            .prefetchOperation(prefetch),
            .systemOp(sysOp),
            .amxField(amx),
        ]
        for op in defensives {
            let d = draft(mnemonic: .add, operands: [op])
            #expect(d.text.contains("?unsupported-operand"))
        }
    }

    @Test func everyDPIMnemonicNameFormatsLowercase() {
        let rows: [(Mnemonic, String)] = [
            (.add, "add"), (.adds, "adds"), (.sub, "sub"), (.subs, "subs"),
            (.and, "and"), (.orr, "orr"), (.eor, "eor"), (.ands, "ands"),
            (.movn, "movn"), (.movz, "movz"), (.movk, "movk"),
            (.adr, "adr"), (.adrp, "adrp"),
            (.bfm, "bfm"), (.sbfm, "sbfm"), (.ubfm, "ubfm"),
            (.extr, "extr"), (.cmp, "cmp"), (.cmn, "cmn"), (.tst, "tst"),
            (.mov, "mov"), (.bfi, "bfi"), (.bfxil, "bfxil"), (.bfc, "bfc"),
            (.sbfiz, "sbfiz"), (.sbfx, "sbfx"), (.ubfiz, "ubfiz"), (.ubfx, "ubfx"),
            (.lsl, "lsl"), (.lsr, "lsr"), (.asr, "asr"), (.ror, "ror"),
            (.sxtb, "sxtb"), (.sxth, "sxth"), (.sxtw, "sxtw"),
            (.uxtb, "uxtb"), (.uxth, "uxth"),
        ]
        for (mnemonic, expected) in rows {
            let d = draft(mnemonic: mnemonic, operands: [])
            #expect(d.text == expected)
        }
    }
}
