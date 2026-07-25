// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// An `op0=0b0010` (SVE tier) encoding with the given classification bits.
/// `topBits` is `bits[31:29]`; `bit24` selects the sub-region within the
/// `bits[31:29]` groups that split on it. The low 24 bits are free — the
/// classification must not depend on them.
private func sveEncoding(topBits: UInt32, bit24: Bool, low: UInt32 = 0) -> UInt32 {
    (topBits << 29) | 0x0400_0000 | (bit24 ? 0x0100_0000 : 0) | (low & 0x00FF_FFFF)
}

/// The complete SVE classification-bit space: every combination of
/// `bits[31:29]` (8 values) × `bit24` (2 values), annotated with the group
/// that owns it in the SVE encoding-space map. The annotation is
/// documentation — which decoder a word reaches is an internal routing
/// detail, and what the tier guarantees to a caller is that every one of
/// these 16 cells decodes into the scalable category.
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

/// Validates that the SVE tier owns the whole of `op0=0b0010`. Sub-dispatch
/// inside the tier is an implementation detail; what a caller can hold the
/// decoder to is that every word in the tier comes back categorized `.sve`,
/// whichever group claims it and whether or not the specific word is
/// allocated.
@Suite("SVEDecoder / the tier owns the whole of op0=2")
struct SVEDecoderRegistrationTests {
    @Test func everyClassificationBitCombinationIsScalable() {
        for row in sveClassificationBits {
            let encoding = sveEncoding(topBits: row.topBits, bit24: row.bit24)
            #expect(Iris.decode(encoding).category == .sve, "\(row.owner)")
        }
    }

    @Test func classificationIgnoresTheLowTwentyFourBits() {
        // Only bits[31:29] and bit24 select the owning group; the operand
        // payload must not move a word out of the tier, or the same
        // instruction form would land in different families depending on its
        // registers.
        for row in sveClassificationBits {
            for low: UInt32 in [0x000000, 0x000001, 0x0FFFFF, 0xFFFFFF] {
                let encoding = sveEncoding(topBits: row.topBits, bit24: row.bit24, low: low)
                #expect(Iris.decode(encoding).category == .sve,
                        "\(row.owner): low bits \(String(low, radix: 16)) left the tier")
            }
        }
    }

    @Test func aWordOutsideTheTierIsNotScalable() {
        // op0 is what puts a word in the tier: anything else belongs to
        // another family whatever its low bits look like.
        for encoding: UInt32 in [0x1400_0000, 0x8B02_0020, 0xD503_47FF, 0xF900_0000] {
            #expect((encoding >> 25) & 0xF != 0b0010, "fixture must be a non-op0=2 word")
            #expect(Iris.decode(encoding).category != .sve,
                    "0x\(String(encoding, radix: 16))")
        }
    }
}

/// Validates that an SVE encoding which decodes to nothing produces a
/// well-formed UNDEFINED record: correctly categorized as `.sve`, raw encoding
/// preserved bit-for-bit, and no register, operand, or scalable state
/// invented. Every compute and memory top byte has a decoder that owns a slice
/// of it (2s.2-2s.5), so each witness is a reserved hole *inside* an owning
/// decoder's scope — the integer/predicate holes at 0x04/0x05/0x24/0x25/0x44/
/// 0x45, the floating-point holes at 0x64/0x65, and the permute/memory/crypto
/// holes at 0x05 and every bit31=1 top byte — and the owning decoder must
/// reject it to the identical well-formed record.
@Suite("SVEDecoder / well-formed UNDEFINED for every unclaimed encoding")
struct SVEDecoderDecodeTests {
    /// One reserved-hole payload per sub-region, each verified against the
    /// reference assembler as an invalid encoding.
    private static let undefinedWitnesses: [(topBits: UInt32, bit24: Bool, low: UInt32)] = [
        (0b000, false, 0x008400), // predicated shift with a zero tsz (2s.3 hole)
        (0b000, true, 0x040000), // permute reserved class (2s.5 hole, 0x0504_0000)
        (0b001, false, 0xC02000), // wide compare at doubleword (2s.3 hole)
        (0b001, true, 0x10A020), // reserved signed-compare opcode (2s.3 hole)
        (0b010, false, 0x000400), // dot product at byte (2s.3 hole)
        (0b010, true, 0x020020), // widening arith at byte (2s.3 hole)
        (0b011, false, 0x123456), // floating-point (2s.4 hole)
        (0b011, true, 0x123456),
        (0b100, false, 0x00C010), // 32-bit gather reserved (2s.5 hole, 0x8400_C010)
        (0b100, true, 0x000000), // LDR/gather-column hole (2s.5 hole, 0x8500_0000)
        (0b101, false, 0x008000), // contiguous-load reserved (2s.5 hole, 0xA400_8000)
        (0b101, true, 0x1F0000), // contiguous-load reserved (2s.5 hole, 0xA51F_0000)
        (0b110, false, 0x00E010), // 64-bit gather reserved (2s.5 hole, 0xC400_E010)
        (0b110, true, 0x00A000), // 64-bit gather reserved (2s.5 hole, 0xC500_A000)
        (0b111, false, 0x000000), // store structured nregs=0 (2s.5 hole, 0xE400_0000)
        (0b111, true, 0x000000), // store column hole (2s.5 hole, 0xE500_0000)
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
        // The predicate & control group spans two of the tier's regions, so a
        // word is claimed from either side and decodes into a real record.
        let draft = Iris.decode(0x2518_E3E0, at: 0x1_0000_8000)
        #expect(draft.mnemonic == .ptrue)
        #expect(draft.category == .sve)
        #expect(draft.address == 0x1_0000_8000)

        // …and it works from the other region the group spans, too.
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
