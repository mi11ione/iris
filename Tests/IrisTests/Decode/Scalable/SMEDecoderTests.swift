// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// An SME-region encoding — `op0=0b0000` (bits[28:25]) with bit31 set, which is
/// exactly the SME region. `topBits` is `bits[31:29]`; bit23 and bit24 are the
/// secondary selectors.
private func smeEncoding(
    topBits: UInt32, bit24: Bool = false, bit23: Bool = false, low: UInt32 = 0,
) -> UInt32 {
    (topBits << 29)
        | (bit24 ? 0x0100_0000 : 0)
        | (bit23 ? 0x0080_0000 : 0)
        | (low & 0x007F_FFFF)
}

/// The SME leaf table over the four `bits[31:29]` groups the region admits
/// (bit31 = 1), with their secondary bit23 / bit24 selectors, annotated with
/// the group that owns each leaf in the SME encoding-space map. The annotation
/// is documentation — which decoder a word reaches is internal, and what the
/// tier guarantees a caller is that every leaf decodes into the SME category.
private let smeLeafTable: [(topBits: UInt32, bit24: Bool, bit23: Bool, owner: String)] = [
    (0b100, false, true, "0x80/81 bit23=1 — FMOPA/FMOPS (core)"),
    (0b100, false, false, "0x80/81 bit23=0 — TMOP/MOP4 (SME2)"),
    (0b101, false, true, "0xA0/A1 bit23=1 — SMOPA/UMOPA (core)"),
    (0b101, false, false, "0xA0/A1 bit23=0 — multi-Z memory (SME2)"),
    (0b110, true, false, "0xC1 — SME2 multi-vector arithmetic"),
    (0b110, false, false, "0xC0 — MOVA/ZERO/LUTI"),
    (0b111, false, false, "0xE0/E1 — ZA load/store"),
    (0b111, true, true, "0xE0/E1 — ZA load/store regardless of bit23/24"),
]

/// Validates that the SME region is reached through the `op0=0` slot. That slot
/// is multi-family — UDF, Apple AMX and SME all live there — so what a caller
/// can hold the dispatcher to is that each word lands in its own category, not
/// that any one family owns the tier.
@Suite("SMEDecoder / the op0=0 slot is shared and correctly split")
struct SMEDecoderRegistrationTests {
    @Test func theOp0ZeroSlotSplitsBetweenItsFamilies() {
        // Registering SME directly at op0=0 would strand AMX and UDF; all three
        // must keep their own attribution.
        #expect(Iris.decode(0x8080_0000).category == .sme)
        #expect(Iris.decode(0x0020_1000).category == .amx)
        #expect(Iris.decode(0x0000_1234).category == .branchesExceptionSystem)
    }

    @Test func onlyBitThirtyOneSetIsTheSMERegion() {
        // The region is op0=0 ∧ bit31=1. A bit31-clear word in the same tier is
        // not SME, whatever its secondary selectors say.
        for topBits: UInt32 in 0b000 ... 0b011 {
            let bit31Clear = smeEncoding(topBits: topBits)
            #expect(Iris.decode(bit31Clear).category != .sme,
                    "0x\(String(bit31Clear, radix: 16))")
        }
    }
}

/// Validates SME sub-dispatch as a caller sees it: every leaf group in the
/// region decodes into the SME category with the raw encoding and address
/// preserved and no state invented — never a trap, never a foreign category —
/// and the classification never depends on the operand payload.
@Suite("SMEDecoder / every leaf group is well formed")
struct SMEDecoderDecodeTests {
    @Test func everyLeafGroupProducesAWellFormedRecord() {
        for row in smeLeafTable {
            let encoding = smeEncoding(
                topBits: row.topBits, bit24: row.bit24, bit23: row.bit23, low: 0x123456,
            )
            let draft = Iris.decode(encoding, at: 0x1_0000_8000)
            #expect(draft.category == .sme, "\(row.owner)")
            #expect(draft.encoding == encoding, "raw encoding must be preserved")
            #expect(draft.address == 0x1_0000_8000)
        }
    }

    @Test func classificationIgnoresTheOperandPayload() {
        // The payload holds register and immediate fields; it must not move a
        // word out of the region, or the same instruction form would land in a
        // different family depending on its registers.
        for row in smeLeafTable {
            for low: UInt32 in [0, 1, 0x7FFFFF] {
                let encoding = smeEncoding(
                    topBits: row.topBits, bit24: row.bit24, bit23: row.bit23, low: low,
                )
                #expect(Iris.decode(encoding).category == .sme,
                        "\(row.owner): payload \(String(low, radix: 16)) left the region")
            }
        }
    }

    @Test func zaLoadStoreIgnoresBothSecondarySelectors() {
        // bits[31:29]=111 is a single region: neither bit23 nor bit24 splits it.
        for bit24 in [false, true] {
            for bit23 in [false, true] {
                let encoding = smeEncoding(topBits: 0b111, bit24: bit24, bit23: bit23)
                #expect(Iris.decode(encoding).category == .sme)
            }
        }
    }
}
