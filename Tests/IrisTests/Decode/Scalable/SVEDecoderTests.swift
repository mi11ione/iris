// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func sveEncoding(topBits: UInt32, bit24: Bool, low: UInt32 = 0) -> UInt32 {
    (topBits << 29) | 0x0400_0000 | (bit24 ? 0x0100_0000 : 0) | (low & 0x00FF_FFFF)
}

private let sveClassificationBits: [(topBits: UInt32, bit24: Bool, owner: String)] = [
    (0b000, false, "0x04 — SVE integer"),
    (0b000, true, "0x05 — SVE permute"),
    (0b001, false, "0x24 — SVE integer compare"),
    (0b001, true, "0x25 — SVE predicate"),
    (0b010, false, "0x44 — SVE2 integer"),
    (0b010, true, "0x45 — SVE2 integer"),
    (0b011, false, "0x64 — SVE floating-point"),
    (0b011, true, "0x65 — SVE floating-point"),
    (0b100, false, "0x84 — SVE memory (bit31=1)"),
    (0b100, true, "0x85 — SVE memory"),
    (0b101, false, "0xA4 — SVE memory"),
    (0b101, true, "0xA5 — SVE memory"),
    (0b110, false, "0xC4 — SVE memory"),
    (0b110, true, "0xC5 — SVE memory"),
    (0b111, false, "0xE4 — SVE memory"),
    (0b111, true, "0xE5 — SVE memory"),
]

/// Validates that the SVE tier owns the whole of `op0=0b0010`.
@Suite("SVEDecoder / the tier owns the whole of op0=2")
struct SVEDecoderRegistrationTests {
    @Test func everyClassificationBitCombinationIsScalable() {
        for row in sveClassificationBits {
            let encoding = sveEncoding(topBits: row.topBits, bit24: row.bit24)
            #expect(Iris.decode(encoding).category == .sve, "\(row.owner)")
        }
    }

    @Test func classificationIgnoresTheLowTwentyFourBits() {
        for row in sveClassificationBits {
            for low: UInt32 in [0x000000, 0x000001, 0x0FFFFF, 0xFFFFFF] {
                let encoding = sveEncoding(topBits: row.topBits, bit24: row.bit24, low: low)
                #expect(Iris.decode(encoding).category == .sve,
                        "\(row.owner): low bits \(String(low, radix: 16)) left the tier")
            }
        }
    }

    @Test func aWordOutsideTheTierIsNotScalable() {
        for encoding: UInt32 in [0x1400_0000, 0x8B02_0020, 0xD503_47FF, 0xF900_0000] {
            #expect((encoding >> 25) & 0xF != 0b0010, "fixture must be a non-op0=2 word")
            #expect(Iris.decode(encoding).category != .sve,
                    "0x\(String(encoding, radix: 16))")
        }
    }
}

/// Validates that an SVE encoding decoding to nothing produces a well-formed
/// UNDEFINED record.
@Suite("SVEDecoder / well-formed UNDEFINED for every unclaimed encoding")
struct SVEDecoderDecodeTests {
    private static let undefinedWitnesses: [(topBits: UInt32, bit24: Bool, low: UInt32)] = [
        (0b000, false, 0x008400),
        (0b000, true, 0x040000),
        (0b001, false, 0xC02000),
        (0b001, true, 0x10A020),
        (0b010, false, 0x000400),
        (0b010, true, 0x020020),
        (0b011, false, 0x123456),
        (0b011, true, 0x123456),
        (0b100, false, 0x00C010),
        (0b100, true, 0x000000),
        (0b101, false, 0x008000),
        (0b101, true, 0x1F0000),
        (0b110, false, 0x00E010),
        (0b110, true, 0x00A000),
        (0b111, false, 0x000000),
        (0b111, true, 0x000000),
    ]

    @Test func everySubRegionProducesAWellFormedUndefinedRecord() {
        for row in Self.undefinedWitnesses {
            let encoding = sveEncoding(topBits: row.topBits, bit24: row.bit24, low: row.low)
            let draft = Iris.decode(encoding, at: 0x1_0000_8000)
            #expect(draft.category == .sve)
            #expect(draft.mnemonic == .undefined)
            #expect(draft.encoding == encoding, "raw encoding must be preserved")
            #expect(draft.address == 0x1_0000_8000)
            #expect(draft.operands.isEmpty)
            #expect(draft.semanticReads == .empty)
            #expect(draft.semanticWrites == .empty)
            #expect(draft.scalableReads == .empty)
            #expect(draft.scalableWrites == .empty)
            #expect(draft.scalableEffect == .none)
            #expect(draft.branchClass == .none)
            #expect(draft.memoryAccess == .none)
            #expect(draft.flagEffect == .none)
        }
    }

    @Test func aClaimedEncodingReachesItsGroupDecoder() {
        let draft = Iris.decode(0x2518_E3E0, at: 0x1_0000_8000)
        #expect(draft.mnemonic == .ptrue)
        #expect(draft.category == .sve)
        #expect(draft.address == 0x1_0000_8000)

        let prefix = Iris.decode(0x0420_BC20, at: 0)
        #expect(prefix.mnemonic == .movprfx)
        #expect(prefix.category == .sve)
    }

    @Test func decodePreservesTheAddressItIsGiven() {
        for address: UInt64 in [0, 0x4000, 0x1_0000_8000, UInt64.max & ~3] {
            let draft = Iris.decode(0x04A0_0000, at: address)
            #expect(draft.address == address)
        }
    }
}
