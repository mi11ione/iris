// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates `Features`: raw-value stability, the arm64e preset, set algebra,
/// and the LDRAA/LDRAB tier gate as its observable effect.
@Suite("Features / option set and decode gating")
struct FeaturesTests {
    @Test func rawValueRoundTrips() {
        for raw: UInt64 in [0, 1, 2, 0x8000_0000_0000_0000, UInt64.max] {
            #expect(Features(rawValue: raw).rawValue == raw)
        }
    }

    @Test func pointerAuthenticationIsBitZero() {
        #expect(Features.pointerAuthentication.rawValue == 1)
    }

    @Test func arm64ePresetEqualsPointerAuthentication() {
        #expect(Features.arm64e == .pointerAuthentication)
    }

    @Test func baseIsTheEmptySet() {
        #expect(Features.base == [])
        #expect(Features.base.isEmpty)
        #expect(Features.base.rawValue == 0)
        #expect(decode(0xF820_0400, features: .base).isUndefined)
    }

    @Test func setAlgebraBehavesAsOptionSet() {
        var f: Features = []
        #expect(f.isEmpty)
        #expect(!f.contains(.pointerAuthentication))
        f.insert(.pointerAuthentication)
        #expect(f.contains(.pointerAuthentication))
        #expect(f == .arm64e)
        f.remove(.pointerAuthentication)
        #expect(f.isEmpty)
    }

    @Test func equalFeatureSetsHashEqual() {
        let a: Features = .arm64e
        let b: Features = .pointerAuthentication
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }

    @Test func emptyFeaturesGateTheARM64ELoadTier() {
        let word: UInt32 = 0xF820_0400
        let plain = decode(word)
        #expect(plain.isUndefined)
        #expect(plain.encoding == word)
        let authed = decode(word, features: .arm64e)
        #expect(authed.mnemonic == .ldraa)
        #expect(authed.category == .loadsAndStores)
    }

    @Test func baseISAPACEncodingsDecodeWithoutTheFlag() {
        let plain = decode(0xD65F_0BFF)
        #expect(plain.mnemonic == .retaa)
        #expect(plain.category == .branchesExceptionSystem)
    }
}

/// Validates op0-slab routing through the public surface.
@Suite("Dispatch / op0 routing and category attribution")
struct DispatchRoutingTests {
    private static let op0Witnesses: [(op0: UInt32, word: UInt32, category: Category)] = [
        (0x0, 0x0020_1000, .amx),
        (0x1, 0x0200_0000, .undefined),
        (0x2, 0x0400_0000, .sve),
        (0x3, 0x0600_0000, .undefined),
        (0x4, 0x8800_7C00, .loadsAndStores),
        (0x5, 0xAA00_03E0, .dataProcessingRegister),
        (0x6, 0x0C00_0000, .simdAndFP),
        (0x7, 0x0E20_1C00, .simdAndFP),
        (0x8, 0x9100_0400, .dataProcessingImmediate),
        (0x9, 0xD282_8020, .dataProcessingImmediate),
        (0xA, 0x1400_0001, .branchesExceptionSystem),
        (0xB, 0x1600_0000, .branchesExceptionSystem),
        (0xC, 0xF940_0021, .loadsAndStores),
        (0xD, 0x9B00_7C20, .dataProcessingRegister),
        (0xE, 0x3DC0_0000, .simdAndFP),
        (0xF, 0x1E20_1000, .simdAndFP),
    ]

    @Test func everyOp0PartitionAttributesToItsFamilyCategory() {
        for row in Self.op0Witnesses {
            #expect((row.word >> 25) & 0xF == row.op0, "op0 mismatch in table for 0x\(String(row.word, radix: 16))")
            let instruction = decode(row.word)
            #expect(instruction.category == row.category,
                    "op0=\(row.op0) word 0x\(String(row.word, radix: 16)) expected \(row.category), got \(instruction.category)")
        }
    }

    @Test func reservedTierDecodesUndefinedWithWordPreserved() {
        for op0: UInt32 in [1, 3] {
            let word = op0 << 25
            let instruction = decode(word, at: 0x1_0000_8000)
            #expect(instruction.isUndefined, "op0=\(op0) must be UNDEFINED")
            #expect(instruction.mnemonic == .undefined)
            #expect(instruction.encoding == word)
            #expect(instruction.address == 0x1_0000_8000)
            #expect(instruction.operands.isEmpty)
        }
    }

    @Test func udfIsInterceptedBeforeAMXAtOp0Zero() {
        let udf = decode(0x0000_002A)
        #expect(udf.mnemonic == .udf)
        #expect(udf.category == .branchesExceptionSystem)
        #expect(udf.branchClass == .exception)
        #expect(Array(udf.operands) == [.unsignedImmediate(value: 42, width: 16)])
        let amx = decode(0x0020_1000)
        #expect(amx.category == .amx)
        let neither = decode(0x0100_0000)
        #expect(neither.isUndefined)
    }

    @Test func addressFlowsThroughDispatchToTheRecord() {
        let instruction = decode(0xD503_201F, at: 0xFFFF_0000_1234_5678)
        #expect(instruction.address == 0xFFFF_0000_1234_5678)
        #expect(instruction.mnemonic == .nop)
    }

    @Test func aliasResolutionAppliesThroughTierZeroDecode() {
        #expect(decode(0xD282_8020).mnemonic == .mov)
        #expect(decode(0xAA00_03E0).mnemonic == .mov)
    }
}
