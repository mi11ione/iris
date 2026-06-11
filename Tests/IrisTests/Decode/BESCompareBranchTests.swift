// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates CBZ / CBNZ decode: sf selects Wn (0) vs Xn (1),
/// imm19 sign-extended and ×4 into label offset, op (bit 24) discriminates
/// zero / non-zero, semanticReads contains Rt, no writes, branchClass
/// is .conditional. Hits both sizes and both ops with sign-edge imm19.
@Suite("BES / Compare-and-branch decode")
struct BESCompareBranchTests {
    @Test func cbz32BitZeroOffset() {
        // 0x34000000 = CBZ W0, #0
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
        // 0xB400001E = CBZ X30, #0 (sf=1, Rt=30)
        let d = decode(0xB400_001E, at: 0)
        #expect(d.mnemonic == .cbz)
        #expect(d.operands[0] == .register(.x(30)))
        #expect(d.semanticReads.contains(.x(30)))
    }

    @Test func cbnz32Bit() {
        // 0x35000001 = CBNZ W1, #0
        let d = decode(0x3500_0001, at: 0)
        #expect(d.mnemonic == .cbnz)
        #expect(d.branchClass == .conditional)
    }

    @Test func cbnz64Bit() {
        // 0xB500000F = CBNZ X15, #0
        let d = decode(0xB500_000F, at: 0)
        #expect(d.mnemonic == .cbnz)
        #expect(d.operands[0] == .register(.x(15)))
    }

    @Test func cbzImm19PositiveOffset() {
        // Construct: sf=1, op=0, imm19=1, Rt=0 → byteOffset = 4
        // bits: 1 011010 0 imm19=0000000000000000001 Rt=00000
        // 0xB4000020
        let d = decode(0xB400_0020, at: 0)
        #expect(d.operands.last == .label(byteOffset: 4))
    }

    @Test func cbzImm19NegativeOffset() {
        // sf=1, op=0, imm19=all-ones=-1, Rt=0 → byteOffset = -4
        // bits 23:5 = 19 ones; encoding = 0xB4 FFFF E0
        let d = decode(0xB4FF_FFE0, at: 0)
        #expect(d.operands.last == .label(byteOffset: -4))
    }

    @Test func cbzImm19MaxPositive() {
        // imm19 = 0x3FFFF (max positive signed) → byteOffset = 0xFFFFC = 1048572
        // sf=1, op=0, Rt=0, encoding = 0xB47FFFE0
        let d = decode(0xB47F_FFE0, at: 0)
        #expect(d.operands.last == .label(byteOffset: 1_048_572))
    }

    @Test func cbzImm19MaxNegative() {
        // imm19 = 0x40000 (sign bit set, all others 0) → byteOffset = -1048576
        // sf=1, op=0, Rt=0, encoding = 0xB4800000
        let d = decode(0xB480_0000, at: 0)
        #expect(d.operands.last == .label(byteOffset: -1_048_576))
    }

    @Test func universalFields() {
        // memoryAccess/Ordering/flagEffect uniform for CBZ.
        let d = decode(0x3400_0000, at: 0)
        #expect(d.memoryAccess == .none)
        #expect(d.memoryOrdering == [])
        #expect(d.flagEffect == .none)
    }
}
