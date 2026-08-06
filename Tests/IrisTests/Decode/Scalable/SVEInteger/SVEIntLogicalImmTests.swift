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

/// Validates the bitwise-immediate group, the highest-risk rendering in the
/// subpiece.
@Suite("SVE integer / bitwise immediate and DUPM")
struct SVEIntLogicalImmTests {
    @Test func theLogicalSlotsAlwaysRenderTheirOwnMnemonicInHex() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x0502_0000, .orr, "orr z0.d, z0.d, #0x1"),
            (0x0542_0000, .eor, "eor z0.d, z0.d, #0x1"),
            (0x0582_0000, .and, "and z0.d, z0.d, #0x1"),
            (0x0580_0020, .and, "and z0.s, z0.s, #0x3"),
            (0x0540_0420, .eor, "eor z0.h, z0.h, #0x3"),
            (0x0580_0620, .and, "and z0.b, z0.b, #0x3"),
        ]
        for (encoding, mnemonic, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticReads) == [32], "\(expected) is destructive")
            #expect(canonicalIndices(d.semanticWrites) == [32])
            #expect(d.scalableEffect == .readsStreamingMode)
        }
    }

    @Test func dupmKeepsItsNameForByteExpressibleValues() {
        let rows: [(UInt32, String)] = [
            (0x05C0_0620, "dupm z0.b, #0x3"),
            (0x05C0_0420, "dupm z0.h, #0x3"),
            (0x05C2_0000, "dupm z0.d, #0x1"),
            (0x05C0_C2E0, "dupm z0.s, #0xffffff00"),
        ]
        for (encoding, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == .dupm, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticReads) == [], "\(expected) writes fresh")
            #expect(canonicalIndices(d.semanticWrites) == [32])
        }
    }

    @Test func dupmCollapsesToMovForPreferredValuesAcrossTheDecimalLadder() {
        let rows: [(UInt32, String)] = [
            (0x05C0_64E0, "mov z0.h, #4080"),
            (0x05C0_24E0, "mov z0.h, #-4081"),
            (0x05C0_8020, "mov z0.s, #0x30000"),
            (0x05C3_0000, "mov z0.d, #0x100000000"),
        ]
        for (encoding, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == .mov, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
        }
        #expect(decode(0x05C0_8020).operands[1] == .unsignedImmediate(value: 0x30000, width: 32))
    }

    @Test func aReservedBitmaskImmediateIsUndefinedInEverySlot() {
        for encoding: UInt32 in [0x0500_07E0, 0x0540_07E0, 0x0580_07E0, 0x05C0_07E0] {
            #expect(decode(encoding).mnemonic == .undefined, "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func theElementSizeIsTheSmallestReplicationPeriod() {
        #expect(decode(0x0580_0620).operands[2] == .unsignedImmediate(value: 3, width: 8))
        #expect(decode(0x0540_0420).operands[2] == .unsignedImmediate(value: 3, width: 16))
        #expect(decode(0x0580_0020).operands[2] == .unsignedImmediate(value: 3, width: 32))
        #expect(decode(0x0502_0000).operands[2] == .unsignedImmediate(value: 1, width: 64))
    }
}
