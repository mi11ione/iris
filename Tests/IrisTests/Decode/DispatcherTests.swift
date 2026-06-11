// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates Features — the option set carrying instruction-set
/// extensions through decode: raw-value stability, the arm64e preset,
/// set algebra, and the observable decode effect of the
/// pointer-authentication flag (the LDRAA/LDRAB tier gate).
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
        // LDRAA x0, [x0, #8] — unallocated on plain ARM64; the
        // pointer-authentication flag admits it.
        let word: UInt32 = 0xF820_0400
        let plain = decode(word)
        #expect(plain.isUndefined)
        #expect(plain.encoding == word)
        let authed = decode(word, features: .arm64e)
        #expect(authed.mnemonic == .ldraa)
        #expect(authed.category == .loadsAndStores)
    }

    @Test func baseISAPACEncodingsDecodeWithoutTheFlag() {
        // RETAA exists on the base ISA — the flag must not gate it.
        let plain = decode(0xD65F_0BFF)
        #expect(plain.mnemonic == .retaa)
        #expect(plain.category == .branchesExceptionSystem)
    }
}

/// Validates the dispatcher's op0-slab routing through the public
/// surface: every op0 partition attributes decoded words to its family
/// category, the reserved tier decodes UNDEFINED, UDF is intercepted
/// before AMX at op0=0, and alias resolution applies through tier-0.
@Suite("Dispatch / op0 routing and category attribution")
struct DispatchRoutingTests {
    /// One decodable witness word per op0 ∈ 0...15 with its expected
    /// category. op0 6/E are the V=1 SIMD/FP load/store partitions
    /// (delegated to the SIMD/FP family); 1/2/3 are the architecturally
    /// reserved tier (no decoder — honest UNDEFINED).
    private static let op0Witnesses: [(op0: UInt32, word: UInt32, category: Category)] = [
        (0x0, 0x0020_1000, .amx), //                 amx ldx
        (0x1, 0x0200_0000, .undefined), //           reserved tier
        (0x2, 0x0400_0000, .undefined), //           reserved tier
        (0x3, 0x0600_0000, .undefined), //           reserved tier
        (0x4, 0x8800_7C00, .loadsAndStores), //      stxr
        (0x5, 0xAA00_03E0, .dataProcessingRegister), // orr (mov alias)
        (0x6, 0x0C00_0000, .simdAndFP), //           st4 (V=1 multi-structure)
        (0x7, 0x0E20_1C00, .simdAndFP), //           and v0.8b
        (0x8, 0x9100_0400, .dataProcessingImmediate), // add x0, x0, #1
        (0x9, 0xD282_8020, .dataProcessingImmediate), // movz (mov alias)
        (0xA, 0x1400_0001, .branchesExceptionSystem), // b
        (0xB, 0x1600_0000, .branchesExceptionSystem), // b (imm26 high half)
        (0xC, 0xF940_0021, .loadsAndStores), //      ldr x1, [x1]
        (0xD, 0x9B00_7C20, .dataProcessingRegister), // madd
        (0xE, 0x3DC0_0000, .simdAndFP), //           ldr q0 (V=1 unsigned offset)
        (0xF, 0x1E20_1000, .simdAndFP), //           fmov s0, #imm
    ]

    @Test func everyOp0PartitionAttributesToItsFamilyCategory() {
        for row in Self.op0Witnesses {
            // Table integrity: the witness word really lives in its op0 slab.
            #expect((row.word >> 25) & 0xF == row.op0, "op0 mismatch in table for 0x\(String(row.word, radix: 16))")
            let instruction = decode(row.word)
            #expect(instruction.category == row.category,
                    "op0=\(row.op0) word 0x\(String(row.word, radix: 16)) expected \(row.category), got \(instruction.category)")
        }
    }

    @Test func reservedTierDecodesUndefinedWithWordPreserved() {
        for op0: UInt32 in 1 ... 3 {
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
        // bits[31:16] == 0 → UDF #imm16, owned by the dispatcher.
        let udf = decode(0x0000_002A)
        #expect(udf.mnemonic == .udf)
        #expect(udf.category == .branchesExceptionSystem)
        #expect(udf.branchClass == .exception)
        #expect(Array(udf.operands) == [.unsignedImmediate(value: 42, width: 16)])
        // bits[31:16] != 0 at op0=0 routes to the AMX decoder instead.
        let amx = decode(0x0020_1000)
        #expect(amx.category == .amx)
        // op0=0, non-UDF, non-AMX → UNDEFINED.
        let neither = decode(0x0100_0000)
        #expect(neither.isUndefined)
    }

    @Test func addressFlowsThroughDispatchToTheRecord() {
        let instruction = decode(0xD503_201F, at: 0xFFFF_0000_1234_5678)
        #expect(instruction.address == 0xFFFF_0000_1234_5678)
        #expect(instruction.mnemonic == .nop)
    }

    @Test func aliasResolutionAppliesThroughTierZeroDecode() {
        // MOVZ x0, #5121 prefers the MOV alias; ORR x0, xzr, x0 likewise.
        #expect(decode(0xD282_8020).mnemonic == .mov)
        #expect(decode(0xAA00_03E0).mnemonic == .mov)
    }
}
