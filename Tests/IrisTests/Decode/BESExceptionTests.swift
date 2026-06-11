// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates exception-generating decode and edge cases
/// 17/18: bits 4:2 must be 000 (else UNDEFINED), bits 23:21 + bits 1:0
/// select mnemonic. SVC/HVC/SMC use LL = 01/10/11; BRK/HLT use LL=00
/// with op_high3 = 001/010; DCPS1/2/3 use op_high3 = 101 with LL=01/10/11.
/// Reserved op_high3 / non-zero bits 4:2 → UNDEFINED.
@Suite("BES / Exception generation decode")
struct BESExceptionTests {
    @Test func svcImmZero() {
        // 0xD4000001 = svc #0
        let d = decode(0xD400_0001, at: 0)
        #expect(d.mnemonic == .svc)
        #expect(d.branchClass == .exception)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 0, width: 16)])
        #expect(d.semanticReads.mask == 0)
        #expect(d.semanticWrites.mask == 0)
    }

    @Test func svcImm16Nonzero() {
        // imm16 = 0xCAFE → encoding bits 20:5 = 0xCAFE → encoding = 0xD419_5FC1
        let d = decode(0xD419_5FC1, at: 0)
        #expect(d.mnemonic == .svc)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 0xCAFE, width: 16)])
    }

    @Test func hvc() {
        // 0xD4000002 = hvc #0 (LL=10)
        let d = decode(0xD400_0002, at: 0)
        #expect(d.mnemonic == .hvc)
    }

    @Test func smc() {
        // 0xD4000003 = smc #0 (LL=11)
        let d = decode(0xD400_0003, at: 0)
        #expect(d.mnemonic == .smc)
    }

    @Test func brk() {
        // 0xD4200000 = brk #0 (op_high3=001, LL=00)
        let d = decode(0xD420_0000, at: 0)
        #expect(d.mnemonic == .brk)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 0, width: 16)])
    }

    @Test func brkImm16Nonzero() {
        // brk #0x2AA — imm16 = 0x2AA → bits 20:5 = 0x2AA → encoding = 0xD4205540
        let d = decode(0xD420_5540, at: 0)
        #expect(d.mnemonic == .brk)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 0x2AA, width: 16)])
    }

    @Test func hlt() {
        // 0xD4400000 = hlt #0 (op_high3=010, LL=00)
        let d = decode(0xD440_0000, at: 0)
        #expect(d.mnemonic == .hlt)
    }

    @Test func dcps1() {
        // 0xD4A00001 = dcps1 #0 (op_high3=101, LL=01)
        let d = decode(0xD4A0_0001, at: 0)
        #expect(d.mnemonic == .dcps1)
    }

    @Test func dcps2() {
        // 0xD4A00002 = dcps2 #0 (LL=10)
        let d = decode(0xD4A0_0002, at: 0)
        #expect(d.mnemonic == .dcps2)
    }

    @Test func dcps3() {
        // 0xD4A00003 = dcps3 #0 (LL=11)
        let d = decode(0xD4A0_0003, at: 0)
        #expect(d.mnemonic == .dcps3)
    }

    @Test func reservedOpHigh3IsUndefined() {
        // op_high3 = 011 (reserved) → UNDEFINED
        // encoding bits 31:21 = 11010100 011, bits 20:0 = 0 → 0xD460_0000
        let d = decode(0xD460_0000, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedLLIsUndefined() {
        // svc family with LL=00 (only BRK/HLT use LL=00) → UNDEFINED
        let d = decode(0xD400_0000, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func nonZeroBits4to2IsUndefined() {
        // svc encoding with bit 2 = 1 (bits 4:2 = 001) → UNDEFINED per fixed-field check
        let d = decode(0xD400_0005, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func dcpsReservedLLZero() {
        // DCPS family with LL=00 → UNDEFINED (DCPS requires LL ≥ 01)
        let d = decode(0xD4A0_0000, at: 0)
        #expect(d.mnemonic == .undefined)
    }
}
