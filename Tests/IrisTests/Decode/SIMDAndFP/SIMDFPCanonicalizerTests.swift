// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates SIMD/FP text rendering (via `Instruction.text`) — the
/// formatter that produces llvm-mc-compatible disassembly text for
/// SIMD/FP records. Each test crafts an instruction value directly to
/// exercise the formatter in isolation from the decoder.
@Suite("Disassembler / SIMDFPCanonicalizer.format")
struct SIMDFPCanonicalizerFormatTests {
    private func draft(
        mnemonic: Mnemonic,
        operands: [Operand],
        flagEffect: FlagEffect = .none,
        memoryAccess: MemoryAccess = .none,
    ) -> Instruction {
        Instruction(
            address: 0,
            encoding: 0,
            mnemonic: mnemonic,
            memoryAccess: memoryAccess,
            flagEffect: flagEffect,
            category: .simdAndFP,
            operands: operands,
        )
    }

    @Test func undefinedRendersLongDirectiveOrFormatterArm() {
        // Undefined records render the raw word as `.long` (text is
        // total); the SIMD/FP formatter's own defensive arm (reachable
        // only via a hand-built family-category record) still yields "".
        let undefined = Instruction(address: 0, encoding: 0x1234, mnemonic: .undefined, category: .undefined)
        #expect(undefined.text == ".long 0x1234")
        let armed = draft(mnemonic: .undefined, operands: [])
        #expect(armed.text == "")
    }

    @Test func mnemonicWithoutOperandsFormatsBare() {
        let d = draft(mnemonic: .fadd, operands: [])
        #expect(d.text == "fadd")
    }

    @Test func faddScalarFormatsCorrectly() {
        let d = draft(mnemonic: .fadd, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .scalar(size: .s))),
            .vectorRegister(VectorRegisterRef(registerIndex: 1, view: .scalar(size: .s))),
            .vectorRegister(VectorRegisterRef(registerIndex: 2, view: .scalar(size: .s))),
        ])
        #expect(d.text == "fadd s0, s1, s2")
    }

    @Test func addVectorFormatsCorrectly() {
        let d = draft(mnemonic: .add, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .b8))),
            .vectorRegister(VectorRegisterRef(registerIndex: 1, view: .full(arrangement: .b8))),
            .vectorRegister(VectorRegisterRef(registerIndex: 2, view: .full(arrangement: .b8))),
        ])
        #expect(d.text == "add v0.8b, v1.8b, v2.8b")
    }

    @Test func vectorElementFormatsAsBracketIndex() {
        let d = draft(mnemonic: .mov, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .element(arrangement: .b16, index: 3))),
            .vectorRegister(VectorRegisterRef(registerIndex: 1, view: .element(arrangement: .b16, index: 7))),
        ])
        #expect(d.text == "mov v0.b[3], v1.b[7]")
    }

    @Test func gprXScalarFormatsAsXn() {
        let d = draft(mnemonic: .fmov, operands: [
            .register(.x(0)),
            .vectorRegister(VectorRegisterRef(registerIndex: 1, view: .scalar(size: .d))),
        ])
        #expect(d.text == "fmov x0, d1")
    }

    @Test func gprWFormatsAsWn() {
        let d = draft(mnemonic: .smov, operands: [
            .register(.w(0)),
            .vectorRegister(VectorRegisterRef(registerIndex: 1, view: .element(arrangement: .b16, index: 0))),
        ])
        #expect(d.text == "smov w0, v1.b[0]")
    }

    @Test func gprWzrFormatsAsWzr() {
        let d = draft(mnemonic: .smov, operands: [.register(.wzr())])
        #expect(d.text == "smov wzr")
    }

    @Test func gprXzrFormatsAsXzr() {
        let d = draft(mnemonic: .fmov, operands: [.register(.xzr())])
        #expect(d.text == "fmov xzr")
    }

    @Test func gprSPFormatsAsSp() {
        let d = draft(mnemonic: .ldr, operands: [.register(.sp())])
        #expect(d.text == "ldr sp")
    }

    @Test func gprWSPFormatsAsWsp() {
        let d = draft(mnemonic: .ldr, operands: [.register(.wsp())])
        #expect(d.text == "ldr wsp")
    }

    @Test func floatImmediateZeroFormatsAsFloatZero() {
        let d = draft(mnemonic: .fcmp, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .scalar(size: .d))),
            .floatImmediate(bits: 0, kind: .double),
        ])
        #expect(d.text == "fcmp d0, #0.0")
    }

    @Test func floatImmediateNonZeroFormatsAsDecimal() {
        let d = draft(mnemonic: .fmov, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .scalar(size: .s))),
            .floatImmediate(bits: 0x3F80_0000, kind: .single),
        ])
        #expect(d.text == "fmov s0, #1.00000000")
    }

    @Test func unsignedImmediateFormatsAsHashValue() {
        let d = draft(mnemonic: .shl, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .scalar(size: .d))),
            .vectorRegister(VectorRegisterRef(registerIndex: 1, view: .scalar(size: .d))),
            .unsignedImmediate(value: 5, width: 8),
        ])
        #expect(d.text == "shl d0, d1, #5")
    }

    @Test func signedImmediateFormatsAsHashValue() {
        let d = draft(mnemonic: .add, operands: [.immediate(value: -10, width: 32)])
        #expect(d.text == "add #-10")
    }

    @Test func conditionCodeFormatsLowercase() {
        let d = draft(mnemonic: .fcsel, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .scalar(size: .d))),
            .vectorRegister(VectorRegisterRef(registerIndex: 1, view: .scalar(size: .d))),
            .vectorRegister(VectorRegisterRef(registerIndex: 2, view: .scalar(size: .d))),
            .conditionCode(.eq),
        ])
        #expect(d.text == "fcsel d0, d1, d2, eq")
    }

    @Test func everyConditionCodeFormatsCorrectly() {
        for (cc, expected) in [
            (ConditionCode.eq, "eq"), (.ne, "ne"), (.cs, "hs"), (.cc, "lo"),
            (.mi, "mi"), (.pl, "pl"), (.vs, "vs"), (.vc, "vc"),
            (.hi, "hi"), (.ls, "ls"), (.ge, "ge"), (.lt, "lt"),
            (.gt, "gt"), (.le, "le"), (.al, "al"), (.nv, "nv"),
        ] {
            let d = draft(mnemonic: .fcsel, operands: [.conditionCode(cc)])
            #expect(d.text == "fcsel \(expected)")
        }
    }

    @Test func memoryRegisterBaseNoOffsetFormatsAsBracketed() {
        let d = draft(mnemonic: .ldr, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .scalar(size: .s))),
            .memory(MemoryOperand(base: .register(.x(0)))),
        ])
        #expect(d.text == "ldr s0, [x0]")
    }

    @Test func memoryWithDisplacementFormatsWithHashOffset() {
        let d = draft(mnemonic: .ldr, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .scalar(size: .s))),
            .memory(MemoryOperand(base: .register(.x(0)), displacement: 16)),
        ])
        #expect(d.text == "ldr s0, [x0, #16]")
    }

    @Test func memoryPreIndexedFormatsWithBang() {
        let d = draft(mnemonic: .ldr, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .scalar(size: .s))),
            .memory(MemoryOperand(
                base: .register(.x(0)), displacement: 16, writeback: .preIndex,
            )),
        ])
        #expect(d.text == "ldr s0, [x0, #16]!")
    }

    @Test func memoryPostIndexedFormatsWithComma() {
        let d = draft(mnemonic: .ldr, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .scalar(size: .s))),
            .memory(MemoryOperand(
                base: .register(.x(0)), displacement: 16, writeback: .postIndex,
            )),
        ])
        #expect(d.text == "ldr s0, [x0], #16")
    }

    @Test func memoryPostIndexedWithIndexRegisterFormats() {
        let d = draft(mnemonic: .ldr, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .scalar(size: .s))),
            .memory(MemoryOperand(
                base: .register(.x(0)), index: .x(1), writeback: .postIndex,
            )),
        ])
        #expect(d.text == "ldr s0, [x0], x1")
    }

    @Test func memoryWithIndexAndShiftFormats() {
        let d = draft(mnemonic: .ldr, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .scalar(size: .s))),
            .memory(MemoryOperand(
                base: .register(.x(0)), index: .x(1), extend: .lsl, shift: 2,
            )),
        ])
        #expect(d.text == "ldr s0, [x0, x1, lsl #2]")
    }

    @Test func memoryWithIndexNoExtendFormats() {
        let d = draft(mnemonic: .ldr, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .scalar(size: .s))),
            .memory(MemoryOperand(base: .register(.x(0)), index: .x(1))),
        ])
        #expect(d.text == "ldr s0, [x0, x1]")
    }

    @Test func memoryPCBaseFormatsAsPc() {
        let d = draft(mnemonic: .ldr, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .scalar(size: .s))),
            .memory(MemoryOperand(base: .pc, displacement: 16)),
        ])
        #expect(d.text == "ldr s0, #16")
    }

    @Test func shiftAmountFormats() {
        let d = draft(mnemonic: .movi, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .s4))),
            .unsignedImmediate(value: 1, width: 8),
            .shiftAmount(kind: .lsl, amount: 16),
        ])
        #expect(d.text == "movi v0.4s, #1, lsl #16")
    }

    @Test func shiftAmountMSLFormats() {
        let d = draft(mnemonic: .movi, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .s4))),
            .unsignedImmediate(value: 1, width: 8),
            .shiftAmount(kind: .msl, amount: 8),
        ])
        #expect(d.text == "movi v0.4s, #1, msl #8")
    }

    @Test func shiftedRegisterLSL0Formats() {
        let d = draft(mnemonic: .add, operands: [.shiftedRegister(reg: .x(0), shift: .lsl, amount: 0)])
        #expect(d.text == "add x0")
    }

    @Test func shiftedRegisterNonZeroFormats() {
        let d = draft(mnemonic: .add, operands: [.shiftedRegister(reg: .x(0), shift: .lsl, amount: 2)])
        #expect(d.text == "add x0, lsl #2")
    }

    @Test func extendedRegisterNoShiftFormats() {
        let d = draft(mnemonic: .add, operands: [.extendedRegister(reg: .x(0), extend: .uxtw, shift: 0)])
        #expect(d.text == "add x0, uxtw")
    }

    @Test func extendedRegisterWithShiftFormats() {
        let d = draft(mnemonic: .add, operands: [.extendedRegister(reg: .x(0), extend: .uxtw, shift: 2)])
        #expect(d.text == "add x0, uxtw #2")
    }

    @Test func ld1MultiStructureFormatsAsCurlyList() {
        let d = draft(mnemonic: .ld1, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .b8))),
            .vectorRegister(VectorRegisterRef(registerIndex: 1, view: .full(arrangement: .b8))),
            .memory(MemoryOperand(base: .register(.x(0)))),
        ])
        #expect(d.text == "ld1 { v0.8b, v1.8b }, [x0]")
    }

    @Test func ld4MultiStructureFormats() {
        let d = draft(mnemonic: .ld4, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .b8))),
            .vectorRegister(VectorRegisterRef(registerIndex: 1, view: .full(arrangement: .b8))),
            .vectorRegister(VectorRegisterRef(registerIndex: 2, view: .full(arrangement: .b8))),
            .vectorRegister(VectorRegisterRef(registerIndex: 3, view: .full(arrangement: .b8))),
            .memory(MemoryOperand(base: .register(.x(0)))),
        ])
        #expect(d.text == "ld4 { v0.8b, v1.8b, v2.8b, v3.8b }, [x0]")
    }

    @Test func ld1rReplicateFormatsAsCurlyList() {
        let d = draft(mnemonic: .ld1r, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .b8))),
            .memory(MemoryOperand(base: .register(.x(0)))),
        ])
        #expect(d.text == "ld1r { v0.8b }, [x0]")
    }

    @Test func tblFormatsListAtPositionOne() {
        // TBL Vd, {Vn.16B}, Vm.8B — list is operand[1..2], non-leading.
        let d = draft(mnemonic: .tbl, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .b8))),
            .vectorRegister(VectorRegisterRef(registerIndex: 1, view: .full(arrangement: .b16))),
            .vectorRegister(VectorRegisterRef(registerIndex: 2, view: .full(arrangement: .b8))),
        ])
        #expect(d.text == "tbl v0.8b, { v1.16b }, v2.8b")
    }

    @Test func tbxFormatsListAtPositionOne() {
        let d = draft(mnemonic: .tbx, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .b8))),
            .vectorRegister(VectorRegisterRef(registerIndex: 1, view: .full(arrangement: .b16))),
            .vectorRegister(VectorRegisterRef(registerIndex: 2, view: .full(arrangement: .b16))),
            .vectorRegister(VectorRegisterRef(registerIndex: 3, view: .full(arrangement: .b8))),
        ])
        #expect(d.text == "tbx v0.8b, { v1.16b, v2.16b }, v3.8b")
    }

    @Test func scalarSuffixForB() {
        let d = draft(mnemonic: .dup, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .scalar(size: .b))),
        ])
        #expect(d.text == "dup b0")
    }

    @Test func scalarSuffixForH() {
        let d = draft(mnemonic: .dup, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 1, view: .scalar(size: .h))),
        ])
        #expect(d.text == "dup h1")
    }

    @Test func scalarSuffixForQ() {
        let d = draft(mnemonic: .ldr, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 5, view: .scalar(size: .q))),
        ])
        #expect(d.text == "ldr q5")
    }

    @Test func arrangementsAllSuffixes() {
        let arrangements: [(VectorArrangement, String)] = [
            (.b8, "8b"), (.b16, "16b"),
            (.h4, "4h"), (.h8, "8h"),
            (.s2, "2s"), (.s4, "4s"),
            (.d1, "1d"), (.d2, "2d"),
        ]
        for (arr, expected) in arrangements {
            let d = draft(mnemonic: .add, operands: [
                .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .full(arrangement: arr))),
            ])
            #expect(d.text == "add v0.\(expected)")
        }
    }

    @Test func extendKindsAllRender() {
        let kinds: [(ExtendKind, String)] = [
            (.uxtb, "uxtb"), (.uxth, "uxth"), (.uxtw, "uxtw"), (.uxtx, "uxtx"),
            (.sxtb, "sxtb"), (.sxth, "sxth"), (.sxtw, "sxtw"), (.sxtx, "sxtx"),
            (.lsl, "lsl"),
        ]
        for (kind, expected) in kinds {
            let d = draft(mnemonic: .add, operands: [.extendedRegister(reg: .x(0), extend: kind, shift: 0)])
            #expect(d.text == "add x0, \(expected)")
        }
    }

    @Test func extendNoneRendersEmpty() {
        let d = draft(mnemonic: .add, operands: [.extendedRegister(reg: .x(0), extend: .none, shift: 0)])
        // The formatter renders `"\(reg.name), \(extendKindName(extend))"`
        // and extendKindName(.none) is the empty string, so the rendered
        // text is "add x0, " — pinned as-is.
        #expect(d.text == "add x0, ")
    }

    @Test func shiftKindsAllRender() {
        let kinds: [(ShiftKind, String)] = [
            (.lsl, "lsl"), (.lsr, "lsr"), (.asr, "asr"), (.ror, "ror"), (.msl, "msl"),
        ]
        for (kind, expected) in kinds {
            let d = draft(mnemonic: .add, operands: [.shiftedRegister(reg: .x(0), shift: kind, amount: 4)])
            // LSL with amount=4 ≠ 0, normal render.
            #expect(d.text == "add x0, \(expected) #4")
        }
    }

    @Test func unknownMnemonicFormatsAsPlaceholder() {
        // A Mnemonic outside the SIMD/FP slab renders as "?N".
        let d = draft(mnemonic: Mnemonic(rawValue: 12000), operands: [])
        #expect(d.text == "?12000")
    }

    @Test func operandWithUnknownVariantRendersUnsupportedPlaceholder() {
        // PSTATEField operand is unsupported by the SIMD/FP formatter.
        let d = draft(mnemonic: .fadd, operands: [
            .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .scalar(size: .s))),
            .pstateField(.spSel),
        ])
        #expect(d.text == "fadd s0, ?unsupported-operand")
    }

    @Test func cryptoOwnedMnemonicsRouteToTheCryptoFormatter() {
        // Crypto-owned mnemonics on a SIMD/FP-category record (hand-built;
        // real crypto records decode with category .crypto) route to the
        // crypto/Apple-extensions formatter.
        let aese = Instruction(mnemonic: .aese, category: .simdAndFP)
        #expect(aese.text == "aese")
    }
}
