// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates exception-generating decode.
@Suite("BES / Exception generation decode")
struct BESExceptionTests {
    @Test func svcImmZero() {
        let d = decode(0xD400_0001, at: 0)
        #expect(d.mnemonic == .svc)
        #expect(d.branchClass == .exception)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 0, width: 16)])
        #expect(d.semanticReads.mask == 0)
        #expect(d.semanticWrites.mask == 0)
    }

    @Test func svcImm16Nonzero() {
        let d = decode(0xD419_5FC1, at: 0)
        #expect(d.mnemonic == .svc)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 0xCAFE, width: 16)])
    }

    @Test func hvc() {
        let d = decode(0xD400_0002, at: 0)
        #expect(d.mnemonic == .hvc)
    }

    @Test func smc() {
        let d = decode(0xD400_0003, at: 0)
        #expect(d.mnemonic == .smc)
    }

    @Test func brk() {
        let d = decode(0xD420_0000, at: 0)
        #expect(d.mnemonic == .brk)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 0, width: 16)])
    }

    @Test func brkImm16Nonzero() {
        let d = decode(0xD420_5540, at: 0)
        #expect(d.mnemonic == .brk)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 0x2AA, width: 16)])
    }

    @Test func hlt() {
        let d = decode(0xD440_0000, at: 0)
        #expect(d.mnemonic == .hlt)
    }

    @Test func dcps1() {
        let d = decode(0xD4A0_0001, at: 0)
        #expect(d.mnemonic == .dcps1)
    }

    @Test func dcps2() {
        let d = decode(0xD4A0_0002, at: 0)
        #expect(d.mnemonic == .dcps2)
    }

    @Test func dcps3() {
        let d = decode(0xD4A0_0003, at: 0)
        #expect(d.mnemonic == .dcps3)
    }

    @Test func reservedOpHigh3IsUndefined() {
        let d = decode(0xD460_0000, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedLLIsUndefined() {
        let d = decode(0xD400_0000, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func nonZeroBits4to2IsUndefined() {
        let d = decode(0xD400_0005, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func dcpsReservedLLZero() {
        let d = decode(0xD4A0_0000, at: 0)
        #expect(d.mnemonic == .undefined)
    }
}
