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

/// Validates the move/copy group at 0x05.
@Suite("SVE integer / move and copy")
struct SVEIntMoveDecodeTests {
    @Test func dupFromAScalarBroadcastsWRegistersBelowDoubleword() {
        let rows: [(UInt32, String)] = [
            (0x0520_3800, "mov z0.b, w0"),
            (0x0560_3800, "mov z0.h, w0"),
            (0x05A0_3800, "mov z0.s, w0"),
            (0x05E0_3800, "mov z0.d, x0"),
        ]
        for (encoding, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == .mov, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticReads) == [0], "\(expected) reads the GPR")
            #expect(canonicalIndices(d.semanticWrites) == [32])
            #expect(d.scalableEffect == .readsStreamingMode)
        }
    }

    @Test func registerThirtyOneIsTheStackPointerAndStaysInTheMask() {
        let wsp = decode(0x0520_3BE0)
        #expect(text(0x0520_3BE0) == "mov z0.b, wsp")
        #expect(wsp.operands[1] == .register(.wsp()))
        #expect(canonicalIndices(wsp.semanticReads) == [31], "the stack pointer is a real read")
        let sp = decode(0x05E0_3BE0)
        #expect(text(0x05E0_3BE0) == "mov z0.d, sp")
        #expect(sp.operands[1] == .register(.sp()))
        #expect(canonicalIndices(sp.semanticReads) == [31])
    }

    @Test func dupIndexedUsesTheLowestSetBitSchemeThroughQuadword() {
        let rows: [(UInt32, String)] = [
            (0x0523_2000, "mov z0.b, z0.b[1]"),
            (0x057F_2000, "mov z0.b, z0.b[31]"),
            (0x057E_2000, "mov z0.h, z0.h[15]"),
            (0x057C_2000, "mov z0.s, z0.s[7]"),
            (0x0578_2000, "mov z0.d, z0.d[3]"),
            (0x0570_2000, "mov z0.q, z0.q[1]"),
        ]
        for (encoding, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == .mov, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticReads) == [32])
            #expect(canonicalIndices(d.semanticWrites) == [32])
        }
        let indexed = decode(0x0523_2000).operands[1]
        #expect(indexed == .scalableVector(ScalableVectorRef(registerIndex: 0, element: .b, elementIndex: 1)))
    }

    @Test func dupIndexedAtIndexZeroIsTheScalarBroadcast() {
        let rows: [(UInt32, ScalarSize, String)] = [
            (0x0521_2000, .b, "mov z0.b, b0"),
            (0x0522_2000, .h, "mov z0.h, h0"),
            (0x0524_2000, .s, "mov z0.s, s0"),
            (0x0528_2000, .d, "mov z0.d, d0"),
            (0x0530_2000, .q, "mov z0.q, q0"),
        ]
        for (encoding, element, expected) in rows {
            let d = decode(encoding)
            #expect(text(encoding) == expected, "0x\(String(encoding, radix: 16))")
            #expect(d.operands[1] == .vectorRegister(
                VectorRegisterRef(registerIndex: 0, view: .scalar(size: element)),
            ))
        }
    }

    @Test func dupIndexedRejectsTheReservedTszValues() {
        #expect(decode(0x0520_2000).mnemonic == .undefined, "tsz of zero")
        #expect(decode(0x05A0_2000).mnemonic == .undefined, "lowest set bit above quadword")
    }

    @Test func cpyFromAScalarMergesAndReadsItsDestination() {
        let rows: [(UInt32, String)] = [
            (0x0528_A000, "mov z0.b, p0/m, w0"),
            (0x0568_A000, "mov z0.h, p0/m, w0"),
            (0x0528_A3E0, "mov z0.b, p0/m, wsp"),
            (0x05E8_A3E0, "mov z0.d, p0/m, sp"),
        ]
        for (encoding, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == .mov, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite])
            #expect(d.scalableReads.containsPredicate(0))
            #expect(canonicalIndices(d.semanticWrites) == [32])
        }
        #expect(canonicalIndices(decode(0x0528_A000).semanticReads) == [0, 32], "GPR plus the merged Zd")
        #expect(canonicalIndices(decode(0x0528_A3E0).semanticReads) == [31, 32], "SP plus the merged Zd")
    }

    @Test func cpyFromASIMDScalarMergesAndReadsItsDestination() {
        let rows: [(UInt32, ScalarSize, String)] = [
            (0x0520_8000, .b, "mov z0.b, p0/m, b0"),
            (0x0560_8020, .h, "mov z0.h, p0/m, h1"),
            (0x05A0_8020, .s, "mov z0.s, p0/m, s1"),
            (0x05E0_8020, .d, "mov z0.d, p0/m, d1"),
        ]
        for (encoding, element, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == .mov, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite])
            let source = d.operands[2]
            #expect(source == .vectorRegister(VectorRegisterRef(
                registerIndex: UInt8(element == .b ? 0 : 1), view: .scalar(size: element),
            )))
        }
        #expect(canonicalIndices(decode(0x0560_8020).semanticReads) == [32, 33], "V1 plus the merged Zd")
    }

    @Test func cpyImmediateSplitsOnTheMergingBit() {
        let zeroing = decode(0x0510_0000)
        #expect(text(0x0510_0000) == "mov z0.b, p0/z, #0")
        #expect(zeroing.scalableEffect == .readsStreamingMode)
        #expect(canonicalIndices(zeroing.semanticReads) == [])
        let merging = decode(0x0510_4000)
        #expect(text(0x0510_4000) == "mov z0.b, p0/m, #0")
        #expect(merging.scalableEffect == [.readsStreamingMode, .partialWrite])
        #expect(canonicalIndices(merging.semanticReads) == [32])
        let high = decode(0x051F_0000)
        #expect(text(0x051F_0000) == "mov z0.b, p15/z, #0")
        #expect(high.scalableReads.containsPredicate(15))
    }

    @Test func cpyImmediateFoldsItsShiftAndSignExtends() {
        #expect(text(0x0510_1000) == "mov z0.b, p0/z, #-128")
        #expect(text(0x0550_2020) == "mov z0.h, p0/z, #256")
        #expect(text(0x0550_6020) == "mov z0.h, p0/m, #256")
        #expect(decode(0x0550_2020).operands[2] == .immediate(value: 256, width: 16))
        #expect(decode(0x0510_2000).mnemonic == .undefined, "lsl #8 at a byte element")
    }
}
