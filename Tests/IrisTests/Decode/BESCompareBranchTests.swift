// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates CBZ / CBNZ.
@Suite("BES / Compare-and-branch decode")
struct BESCompareBranchTests {
    @Test func cbz32BitZeroOffset() {
        let d = decode(0x3400_0000, at: 0)
        #expect(d.mnemonic == .cbz)
        #expect(d.branchClass == .conditional)
        #expect(d.operands.count == 2)
        #expect(d.operands[0] == .register(.w(0)))
        #expect(d.operands[1] == .label(byteOffset: 0))
        #expect(d.semanticReads.contains(.w(0)))
        #expect(d.semanticWrites.mask == 0)
    }

    @Test func cbz64BitWithRt() {
        let d = decode(0xB400_001E, at: 0)
        #expect(d.mnemonic == .cbz)
        #expect(d.operands[0] == .register(.x(30)))
        #expect(d.semanticReads.contains(.x(30)))
    }

    @Test func cbnz32Bit() {
        let d = decode(0x3500_0001, at: 0)
        #expect(d.mnemonic == .cbnz)
        #expect(d.branchClass == .conditional)
    }

    @Test func cbnz64Bit() {
        let d = decode(0xB500_000F, at: 0)
        #expect(d.mnemonic == .cbnz)
        #expect(d.operands[0] == .register(.x(15)))
    }

    @Test func cbzImm19PositiveOffset() {
        let d = decode(0xB400_0020, at: 0)
        #expect(d.operands.last == .label(byteOffset: 4))
    }

    @Test func cbzImm19NegativeOffset() {
        let d = decode(0xB4FF_FFE0, at: 0)
        #expect(d.operands.last == .label(byteOffset: -4))
    }

    @Test func cbzImm19MaxPositive() {
        let d = decode(0xB47F_FFE0, at: 0)
        #expect(d.operands.last == .label(byteOffset: 1_048_572))
    }

    @Test func cbzImm19MaxNegative() {
        let d = decode(0xB480_0000, at: 0)
        #expect(d.operands.last == .label(byteOffset: -1_048_576))
    }

    @Test func universalFields() {
        let d = decode(0x3400_0000, at: 0)
        #expect(d.memoryAccess == .none)
        #expect(d.memoryOrdering == [])
        #expect(d.flagEffect == .none)
    }
}
