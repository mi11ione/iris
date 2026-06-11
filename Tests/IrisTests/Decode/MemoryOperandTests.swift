// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates MemoryOperand + MemoryBase — the addressing-mode operand
/// for every ARM64 load and store, including the PC-relative literal
/// form (`base = .pc`).
@Suite("MemoryOperand / addressing-mode field preservation")
struct MemoryOperandTests {
    @Test func defaultedInitProducesRegisterBaseWithNoModifiers() {
        let mem = MemoryOperand(base: .register(RegisterRef.x(5)))
        #expect(mem.base == .register(RegisterRef.x(5)))
        #expect(mem.index == nil)
        #expect(mem.displacement == 0)
        #expect(mem.extend == .none)
        #expect(mem.shift == 0)
        #expect(mem.writeback == .none)
    }

    @Test func fullySpecifiedFieldsArePreserved() {
        let mem = MemoryOperand(
            base: .register(RegisterRef.sp()),
            index: RegisterRef.x(2),
            displacement: -0x1234,
            extend: .sxtw,
            shift: 3,
            writeback: .preIndex,
        )
        #expect(mem.index == RegisterRef.x(2))
        #expect(mem.displacement == -0x1234)
        #expect(mem.extend == .sxtw)
        #expect(mem.shift == 3)
        #expect(mem.writeback == .preIndex)
    }

    @Test func literalLoadHasPcBase() {
        let mem = MemoryOperand(base: .pc, displacement: 0x4_0000_0000)
        #expect(mem.base == .pc)
        #expect(mem.displacement == 0x4_0000_0000)
    }

    @Test func equalMemoryOperandsHashEqual() {
        let a = MemoryOperand(base: .register(RegisterRef.x(0)), displacement: 16)
        let b = MemoryOperand(base: .register(RegisterRef.x(0)), displacement: 16)
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }

    @Test func writebackPreAndPostIndexDifferFromNone() {
        let pre = MemoryOperand(base: .register(RegisterRef.x(0)), writeback: .preIndex)
        let post = MemoryOperand(base: .register(RegisterRef.x(0)), writeback: .postIndex)
        let none = MemoryOperand(base: .register(RegisterRef.x(0)))
        #expect(pre != post)
        #expect(pre != none)
        #expect(post != none)
    }
}

/// Validates MemoryBase — register vs PC base disambiguation.
@Suite("MemoryBase / register vs pc")
struct MemoryBaseTests {
    @Test func registerCaseCarriesReference() {
        let base = MemoryBase.register(RegisterRef.x(10))
        #expect(base == .register(RegisterRef.x(10)))
    }

    @Test func pcCaseIsNotRegister() {
        #expect(MemoryBase.pc != .register(RegisterRef.x(0)))
        #expect(MemoryBase.pc != .register(RegisterRef.sp()))
    }

    @Test func twoEqualRegisterBasesHashEqual() {
        let a = MemoryBase.register(RegisterRef.x(3))
        let b = MemoryBase.register(RegisterRef.x(3))
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }

    @Test func pcAndRegisterAreDistinct() {
        #expect(MemoryBase.pc != .register(RegisterRef.x(0)))
    }
}
