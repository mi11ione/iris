// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

private func text(_ encoding: UInt32) -> String {
    decode(encoding).text
}

private func canonicalIndices(_ set: RegisterSet) -> [Int] {
    (0 ..< 64).filter { (set.mask >> UInt64($0)) & 1 == 1 }
}

/// Validates the 0x25 wide-immediate region.
@Suite("SVE integer / wide immediate and DUP immediate")
struct SVEIntImmediateDecodeTests {
    private static let opcodes: [(UInt32, Mnemonic, String)] = [
        (0x2520_C000, .add, "add z0.b, z0.b, #0"),
        (0x2521_C000, .sub, "sub z0.b, z0.b, #0"),
        (0x2523_C000, .subr, "subr z0.b, z0.b, #0"),
        (0x2524_C000, .sqadd, "sqadd z0.b, z0.b, #0"),
        (0x2527_C000, .uqsub, "uqsub z0.b, z0.b, #0"),
        (0x2528_C000, .smax, "smax z0.b, z0.b, #0"),
        (0x2529_C000, .umax, "umax z0.b, z0.b, #0"),
        (0x252A_C000, .smin, "smin z0.b, z0.b, #0"),
        (0x252B_C000, .umin, "umin z0.b, z0.b, #0"),
        (0x2530_C000, .mul, "mul z0.b, z0.b, #0"),
        (0x25B0_C000, .mul, "mul z0.s, z0.s, #0"),
        (0x25F0_C000, .mul, "mul z0.d, z0.d, #0"),
    ]

    @Test func everyWideImmediateOpcodeIsDestructive() {
        for (encoding, mnemonic, expected) in Self.opcodes {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticReads) == [32], "\(expected) reads Zdn")
            #expect(canonicalIndices(d.semanticWrites) == [32])
            #expect(d.scalableEffect == .readsStreamingMode, "\(expected) recomputes every lane")
            #expect(d.flagEffect == .none)
        }
    }

    @Test func theOpcodeSelectsTheImmediateSignedness() {
        #expect(text(0x2528_DFE0) == "smax z0.b, z0.b, #-1")
        #expect(decode(0x2528_DFE0).operands[2] == .immediate(value: -1, width: 8))
        #expect(text(0x2529_DFE0) == "umax z0.b, z0.b, #255")
        #expect(decode(0x2529_DFE0).operands[2] == .unsignedImmediate(value: 255, width: 8))
        #expect(text(0x2530_D000) == "mul z0.b, z0.b, #-128")
        #expect(text(0x2530_CFE0) == "mul z0.b, z0.b, #127")
        #expect(text(0x2520_DFE0) == "add z0.b, z0.b, #255")
    }

    @Test func theShiftFoldsIntoTheValueExceptAtZero() {
        #expect(text(0x2560_E020) == "add z0.h, z0.h, #256")
        #expect(decode(0x2560_E020).operands[2] == .unsignedImmediate(value: 256, width: 16))
        let zero = decode(0x2560_E000)
        #expect(text(0x2560_E000) == "add z0.h, z0.h, #0, lsl #8")
        #expect(zero.operands[2] == .unsignedImmediate(value: 0, width: 8))
        #expect(zero.operands[3] == .shiftAmount(kind: .lsl, amount: 8))
        #expect(text(0x25A0_E020) == "add z0.s, z0.s, #256")
    }

    @Test func theWideImmediateRejectsItsReservedSlots() {
        for (encoding, label) in [
            (UInt32(0x2530_8000), "the b14=0 fixed-field hole"),
            (UInt32(0x252C_C000), "unallocated opcode 0x0C"),
            (UInt32(0x2528_E000), "smax with the nonexistent shift bit"),
            (UInt32(0x2520_E000), "add lsl #8 at a byte element"),
        ] {
            #expect(decode(encoding).mnemonic == .undefined, "\(label)")
        }
    }

    @Test func dupImmediateRendersMovWithTheFoldedShift() {
        let rows: [(UInt32, String)] = [
            (0x2538_C000, "mov z0.b, #0"),
            (0x2538_D000, "mov z0.b, #-128"),
            (0x2578_CFE0, "mov z0.h, #127"),
            (0x2578_E020, "mov z0.h, #256"),
            (0x2578_E000, "mov z0.h, #0, lsl #8"),
        ]
        for (encoding, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == .mov, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticReads) == [], "\(expected) is a fresh write")
            #expect(canonicalIndices(d.semanticWrites) == [32])
            #expect(d.scalableEffect == .readsStreamingMode)
        }
        #expect(decode(0x2538_E000).mnemonic == .undefined, "dup lsl #8 at a byte element")
    }

    @Test func theAllZeroDupIsMovNotFmov() {
        for encoding: UInt32 in [0x2578_C000, 0x25B8_C000, 0x25F8_C000] {
            let d = decode(encoding)
            #expect(d.mnemonic == .mov, "0x\(String(encoding, radix: 16))")
        }
        #expect(text(0x25F8_C000) == "mov z0.d, #0")
    }
}
