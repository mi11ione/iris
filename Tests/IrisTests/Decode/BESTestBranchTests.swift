// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates TBZ / TBNZ.
@Suite("BES / Test-bit-and-branch decode")
struct BESTestBranchTests {
    @Test func tbzBitPos0_32BitRegister() {
        let d = decode(0x3600_0000, at: 0)
        #expect(d.mnemonic == .tbz)
        #expect(d.branchClass == .conditional)
        #expect(d.operands.count == 3)
        #expect(d.operands[0] == .register(.w(0)))
        #expect(d.operands[1] == .unsignedImmediate(value: 0, width: 6))
        #expect(d.operands[2] == .label(byteOffset: 0))
        #expect(d.semanticReads.contains(.w(0)))
        #expect(d.semanticWrites.mask == 0)
    }

    @Test func tbzBitPos31_StillWn() {
        let d = decode(0x36F8_0000, at: 0)
        #expect(d.operands[0] == .register(.w(0)))
        #expect(d.operands[1] == .unsignedImmediate(value: 31, width: 6))
    }

    @Test func tbzBitPos32_SwitchesToXn() {
        let d = decode(0xB600_0000, at: 0)
        #expect(d.operands[0] == .register(.x(0)))
        #expect(d.operands[1] == .unsignedImmediate(value: 32, width: 6))
    }

    @Test func tbzBitPos63() {
        let d = decode(0xB6F8_0000, at: 0)
        #expect(d.operands[0] == .register(.x(0)))
        #expect(d.operands[1] == .unsignedImmediate(value: 63, width: 6))
    }

    @Test func tbnz32Bit() {
        let d = decode(0x3700_0000, at: 0)
        #expect(d.mnemonic == .tbnz)
    }

    @Test func tbnz64Bit() {
        let d = decode(0xB700_0000, at: 0)
        #expect(d.mnemonic == .tbnz)
    }

    @Test func tbzImm14PositiveOffset() {
        let d = decode(0x3600_0020, at: 0)
        #expect(d.operands[2] == .label(byteOffset: 4))
    }

    @Test func tbzImm14NegativeOffset() {
        let d = decode(0x3607_FFE0, at: 0)
        #expect(d.operands[2] == .label(byteOffset: -4))
    }

    @Test func tbzImm14MaxPositive() {
        let d = decode(0x3603_FFE0, at: 0)
        #expect(d.operands[2] == .label(byteOffset: 32764))
    }

    @Test func tbzImm14MaxNegative() {
        let d = decode(0x3604_0000, at: 0)
        #expect(d.operands[2] == .label(byteOffset: -32768))
    }

    @Test func tbzRtAtNonZero() {
        let d = decode(0x3600_001E, at: 0)
        #expect(d.operands[0] == .register(.w(30)))
        #expect(d.semanticReads.contains(.w(30)))
    }
}
