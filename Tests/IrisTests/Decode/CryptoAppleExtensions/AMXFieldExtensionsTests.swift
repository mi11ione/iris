// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates ``AMXField``'s accessors decomposing the raw payload into opcode
/// (bits[9:5]) and operand field (bits[4:0]).
@Suite("AMX / AMXField computed accessors")
struct AMXFieldExtensionsTests {
    @Test func opcodeZeroOperandZero() {
        let f = AMXField(rawBits: 0x0020_1000)
        #expect(f.opcode == 0)
        #expect(f.operandField == 0)
        #expect(!f.operandIsImmediate)
        #expect(!f.isUnknownOpcode)
    }

    @Test func opcodeMaxDocumentedOperandMax() {
        let f = AMXField(rawBits: 0x0020_1000 | (22 << 5) | 31)
        #expect(f.opcode == 22)
        #expect(f.operandField == 31)
        #expect(!f.operandIsImmediate)
        #expect(!f.isUnknownOpcode)
    }

    @Test func opcodeSeventeenIsImmediate() {
        let f = AMXField(rawBits: 0x0020_1000 | (17 << 5) | 0)
        #expect(f.opcode == 17)
        #expect(f.operandIsImmediate)
        #expect(!f.isUnknownOpcode)
    }

    @Test func opcodeTwentyThreeIsUnknownOpcode() {
        let f = AMXField(rawBits: 0x0020_1000 | (23 << 5))
        #expect(f.opcode == 23)
        #expect(f.isUnknownOpcode)
        #expect(!f.operandIsImmediate)
    }

    @Test func opcodeThirtyOneIsUnknownOpcode() {
        let f = AMXField(rawBits: 0x0020_1000 | (31 << 5) | 31)
        #expect(f.opcode == 31)
        #expect(f.operandField == 31)
        #expect(f.isUnknownOpcode)
    }

    @Test func accessorsIgnoreBitsAboveTen() {
        let f = AMXField(rawBits: 0xFFFF_FC00 | (10 << 5) | 7)
        #expect(f.opcode == 10)
        #expect(f.operandField == 7)
    }

    @Test func operandFieldCoversEveryFiveBitValue() {
        for operand: UInt32 in 0 ..< 32 {
            let f = AMXField(rawBits: 0x0020_1000 | (5 << 5) | operand)
            #expect(f.operandField == UInt8(operand))
        }
    }

    @Test func opcodeFieldCoversEveryFiveBitValue() {
        for opcode: UInt32 in 0 ..< 32 {
            let f = AMXField(rawBits: 0x0020_1000 | (opcode << 5))
            #expect(f.opcode == UInt8(opcode))
            #expect(f.isUnknownOpcode == (opcode > 22))
            #expect(f.operandIsImmediate == (opcode == 17))
        }
    }
}
