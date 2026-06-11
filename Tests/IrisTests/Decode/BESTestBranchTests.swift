// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates TBZ / TBNZ decode: bit position is the
/// composite (b5 << 5) | b40 (range 0..63); b5 also selects register
/// width — Wn when bit position < 32, Xn when ≥ 32. imm14 sign-extended
/// and ×4. Operand layout is [register, immediate(bitPos, width=6), label].
@Suite("BES / Test-bit-and-branch decode")
struct BESTestBranchTests {
    @Test func tbzBitPos0_32BitRegister() {
        // 0x36000000 = TBZ W0, #0, #0 (b5=0, op=0, b40=0)
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
        // bitPos = 31 → b5=0, b40=31 (0x1F at bits 23:19) → encoding bits 23:19 = 11111
        // encoding = 0x36F80000 (b5=0, op=0, b40=11111, imm14=0, Rt=0)
        let d = decode(0x36F8_0000, at: 0)
        #expect(d.operands[0] == .register(.w(0)))
        #expect(d.operands[1] == .unsignedImmediate(value: 31, width: 6))
    }

    @Test func tbzBitPos32_SwitchesToXn() {
        // bitPos = 32 → b5=1, b40=0 → bit 31 = 1, bits 23:19 = 0
        // encoding = 0xB6000000 (b5=1, fixed 011011, op=0, b40=0, imm14=0, Rt=0)
        let d = decode(0xB600_0000, at: 0)
        #expect(d.operands[0] == .register(.x(0)))
        #expect(d.operands[1] == .unsignedImmediate(value: 32, width: 6))
    }

    @Test func tbzBitPos63() {
        // bitPos = 63 → b5=1, b40=31
        // encoding = 0xB6F80000
        let d = decode(0xB6F8_0000, at: 0)
        #expect(d.operands[0] == .register(.x(0)))
        #expect(d.operands[1] == .unsignedImmediate(value: 63, width: 6))
    }

    @Test func tbnz32Bit() {
        // op=1 → bit 24 = 1; encoding = 0x37000000 (b5=0, op=1, b40=0)
        let d = decode(0x3700_0000, at: 0)
        #expect(d.mnemonic == .tbnz)
    }

    @Test func tbnz64Bit() {
        // b5=1, op=1 → encoding = 0xB7000000
        let d = decode(0xB700_0000, at: 0)
        #expect(d.mnemonic == .tbnz)
    }

    @Test func tbzImm14PositiveOffset() {
        // imm14 = 1 → byteOffset = 4
        // b5=0, op=0, b40=0, imm14=1, Rt=0 → encoding = 0x36000020
        let d = decode(0x3600_0020, at: 0)
        #expect(d.operands[2] == .label(byteOffset: 4))
    }

    @Test func tbzImm14NegativeOffset() {
        // imm14 = -1 (all 14 bits set, 0x3FFF) → byteOffset = -4
        // imm14 << 5 = 0x7FFE0 → encoding = 0x3607FFE0
        let d = decode(0x3607_FFE0, at: 0)
        #expect(d.operands[2] == .label(byteOffset: -4))
    }

    @Test func tbzImm14MaxPositive() {
        // imm14 = 0x1FFF (max positive 14-bit signed) → byteOffset = 32764
        // imm14 << 5 = 0x3FFE0 → encoding = 0x3603FFE0
        let d = decode(0x3603_FFE0, at: 0)
        #expect(d.operands[2] == .label(byteOffset: 32764))
    }

    @Test func tbzImm14MaxNegative() {
        // imm14 = 0x2000 (sign bit set, all others 0) → byteOffset = -32768
        // imm14 << 5 = 0x40000 → encoding = 0x36040000
        let d = decode(0x3604_0000, at: 0)
        #expect(d.operands[2] == .label(byteOffset: -32768))
    }

    @Test func tbzRtAtNonZero() {
        // Rt = 30 → encoding bits 4:0 = 11110 → encoding = 0x3600001E
        let d = decode(0x3600_001E, at: 0)
        #expect(d.operands[0] == .register(.w(30)))
        #expect(d.semanticReads.contains(.w(30)))
    }
}
