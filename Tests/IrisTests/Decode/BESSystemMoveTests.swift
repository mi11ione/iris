// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates MSR-register / MRS.
@Suite("BES / MSR (register) / MRS decode")
struct BESSystemMoveTests {
    @Test func mrsTpidrEl0() {
        let d = decode(0xD53B_D040, at: 0)
        #expect(d.mnemonic == .mrs)
        #expect(d.operands.count == 2)
        #expect(d.operands[0] == .register(.x(0)))
        #expect(d.operands[1] == .systemRegister(SystemRegisterEncoding(op0: 3, op1: 3, crn: 13, crm: 0, op2: 2)))
        #expect(d.semanticWrites.contains(.x(0)))
        #expect(d.semanticReads.mask == 0)
    }

    @Test func mrsNzcv() {
        let d = decode(0xD53B_4201, at: 0)
        #expect(d.mnemonic == .mrs)
        #expect(d.operands[1] == .systemRegister(SystemRegisterEncoding(op0: 3, op1: 3, crn: 4, crm: 2, op2: 0)))
    }

    @Test func mrsRtXzr() {
        let d = decode(0xD53B_D05F, at: 0)
        #expect(d.mnemonic == .mrs)
        #expect(d.operands[0] == .register(.xzr()))
    }

    @Test func msrTpidrEl0() {
        let d = decode(0xD51B_D040, at: 0)
        #expect(d.mnemonic == .msr)
        #expect(d.operands.count == 2)
        #expect(d.operands[0] == .systemRegister(SystemRegisterEncoding(op0: 3, op1: 3, crn: 13, crm: 0, op2: 2)))
        #expect(d.operands[1] == .register(.x(0)))
        #expect(d.semanticReads.contains(.x(0)))
        #expect(d.semanticWrites.mask == 0)
    }

    @Test func msrRtXzr() {
        let d = decode(0xD51B_D05F, at: 0)
        #expect(d.mnemonic == .msr)
        #expect(d.operands[1] == .register(.xzr()))
    }

    @Test func msrOp0EqualsTwo() {
        let d = decode(0xD513_0000, at: 0)
        #expect(d.mnemonic == .msr)
        #expect(d.operands[0] == .systemRegister(SystemRegisterEncoding(op0: 2, op1: 3, crn: 0, crm: 0, op2: 0)))
    }

    @Test func mrsAppleImpdefCRn11() {
        let d = decode(0xD538_B020, at: 0)
        #expect(d.mnemonic == .mrs)
        #expect(d.operands[0] == .register(.x(0)))
        #expect(d.operands[1] == .systemRegister(SystemRegisterEncoding(op0: 3, op1: 0, crn: 11, crm: 0, op2: 1)))
        #expect(d.semanticWrites.contains(.x(0)))
    }

    @Test func msrAppleImpdefCRn15() {
        let d = decode(0xD51B_F3E5, at: 0)
        #expect(d.mnemonic == .msr)
        #expect(d.operands[0] == .systemRegister(SystemRegisterEncoding(op0: 3, op1: 3, crn: 15, crm: 3, op2: 7)))
        #expect(d.operands[1] == .register(.x(5)))
        #expect(d.semanticReads.contains(.x(5)))
    }
}
