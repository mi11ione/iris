// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates Operand — the single discriminated union over every
/// ARM64 operand variant. Each of the 18 cases is exercised at the
/// construction + equality level.
@Suite("Operand / variants instantiable and distinct")
struct OperandTests {
    @Test func registerVariantCarriesRegisterRef() {
        let op = Operand.register(RegisterRef.x(7))
        #expect(op == .register(RegisterRef.x(7)))
    }

    @Test func vectorRegisterVariantCarriesVectorRef() {
        let vec = VectorRegisterRef(registerIndex: 4, view: .full(arrangement: .s4))
        let op = Operand.vectorRegister(vec)
        #expect(op == .vectorRegister(vec))
    }

    @Test func immediateVariantCarriesValueAndWidth() {
        let op = Operand.immediate(value: -1234, width: 32)
        #expect(op == .immediate(value: -1234, width: 32))
    }

    @Test func unsignedImmediateVariantCarriesValueAndWidth() {
        let op = Operand.unsignedImmediate(value: 0xDEAD, width: 16)
        #expect(op == .unsignedImmediate(value: 0xDEAD, width: 16))
    }

    @Test func floatImmediateVariantCarriesBitsAndKind() {
        let op = Operand.floatImmediate(bits: 0x4048_F5C3, kind: .single)
        #expect(op == .floatImmediate(bits: 0x4048_F5C3, kind: .single))
    }

    @Test func labelVariantCarriesByteOffsetAndCoversAdrpRange() {
        let op = Operand.label(byteOffset: 0x4_0000_0000)
        #expect(op == .label(byteOffset: 0x4_0000_0000))
    }

    @Test func labelVariantCarriesNegativeByteOffset() {
        let op = Operand.label(byteOffset: -0x1000)
        #expect(op == .label(byteOffset: -0x1000))
    }

    @Test func memoryVariantCarriesMemoryOperand() {
        let mem = MemoryOperand(base: .pc, displacement: 16)
        let op = Operand.memory(mem)
        #expect(op == .memory(mem))
    }

    @Test func shiftedRegisterVariantCarriesReg() {
        let op = Operand.shiftedRegister(reg: RegisterRef.x(3), shift: .lsl, amount: 12)
        #expect(op == .shiftedRegister(reg: RegisterRef.x(3), shift: .lsl, amount: 12))
    }

    @Test func extendedRegisterVariantCarriesReg() {
        let op = Operand.extendedRegister(reg: RegisterRef.w(2), extend: .uxtw, shift: 2)
        #expect(op == .extendedRegister(reg: RegisterRef.w(2), extend: .uxtw, shift: 2))
    }

    @Test func systemRegisterVariantCarriesEncoding() {
        let enc = SystemRegisterEncoding(op0: 3, op1: 3, crn: 13, crm: 0, op2: 2)
        let op = Operand.systemRegister(enc)
        #expect(op == .systemRegister(enc))
    }

    @Test func conditionCodeVariantCarriesCondition() {
        let op = Operand.conditionCode(.eq)
        #expect(op == .conditionCode(.eq))
    }

    @Test func pstateFieldVariantCarriesField() {
        let op = Operand.pstateField(.daifSet)
        #expect(op == .pstateField(.daifSet))
    }

    @Test func barrierOptionVariantCarriesOption() {
        let op = Operand.barrierOption(.sy)
        #expect(op == .barrierOption(.sy))
    }

    @Test func prefetchOperationVariantCarriesComposite() {
        let p = PrefetchOperation(rawValue: 0b00101)
        let op = Operand.prefetchOperation(p)
        #expect(op == .prefetchOperation(p))
    }

    @Test func systemOpVariantCarriesRawEncoding() {
        let s = SystemOp(rawEncoding: 0xD508_741F)
        let op = Operand.systemOp(s)
        #expect(op == .systemOp(s))
    }

    @Test func amxFieldVariantCarriesField() {
        let f = AMXField(rawBits: 0x1234)
        let op = Operand.amxField(f)
        #expect(op == .amxField(f))
    }

    @Test func shiftAmountVariantCarriesKindAndAmount() {
        let op = Operand.shiftAmount(kind: .lsl, amount: 12)
        #expect(op == .shiftAmount(kind: .lsl, amount: 12))
    }

    @Test func pageLabelVariantCarriesByteOffset() {
        let op = Operand.pageLabel(byteOffset: -0x10000)
        #expect(op == .pageLabel(byteOffset: -0x10000))
    }

    @Test func pageLabelDistinctFromLabel() {
        // ADRP target semantics differ from ADR (page-aligned vs PC-relative).
        let pl = Operand.pageLabel(byteOffset: 4096)
        let l = Operand.label(byteOffset: 4096)
        #expect(pl != l)
    }

    @Test func equalOperandsHashEqual() {
        let a = Operand.immediate(value: 42, width: 64)
        let b = Operand.immediate(value: 42, width: 64)
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }

    @Test func variantsWithDifferentTagsAreDistinct() {
        let imm = Operand.immediate(value: 0, width: 8)
        let uimm = Operand.unsignedImmediate(value: 0, width: 8)
        #expect(imm != uimm)
    }
}

/// Pins MemoryLayout<Operand>.size so any future Swift toolchain change
/// that grows the enum past its 24-byte budget surfaces
/// here. Operand's payload is dominated by
/// the Int64 in `.immediate` and the MemoryOperand in `.memory`; a
/// growth past 24 bytes triggers a multiplicative cost across the
/// operand buffer for every binary.
@Suite("Operand / memory-layout invariant")
struct OperandLayoutTests {
    @Test func sizeFitsInTwentyFourByteBudget() {
        #expect(MemoryLayout<Operand>.size <= 24)
    }

    @Test func alignmentIsAtMostEightBytes() {
        #expect(MemoryLayout<Operand>.alignment <= 8)
    }
}
