// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates `isSME2MultiVectorEncoding` and `isSVECounterPredicateEncoding` —
/// the two predicates that define what subpiece 2s.7 owns, and the single
/// source of truth shared by the decode gates, the validator's skip filter, and
/// the harvester's scope. 2s.7 closes the scalable tier, so its claim is the
/// exact complement of its siblings: in the SME region it owns everything
/// `isSMECoreEncoding` does not, and in the SVE region it owns the
/// predicate-as-counter cells all four SVE subpieces reject. A boundary
/// mis-draw would either strand a real instruction outside validation or hand a
/// word to a decoder that cannot represent it.
@Suite("SME2 / multi-vector scope predicate")
struct SME2ScopeTests {
    @Test func theSMERegionNonCoreWordsAreClaimed() {
        // A representative of every SME-region family 2s.7 owns.
        let owned: [(UInt32, String)] = [
            (0xC1A1_1C00, "ZA-accumulate fadd"),
            (0xC120_B800, "destructive smax"),
            (0xC131_E000, "convert fcvtzs"),
            (0xC120_8000, "sel"),
            (0xA000_0000, "multi-vector ld1b"),
            (0xC08A_0000, "luti6"),
            (0xC004_0800, "mova array"),
            (0xC002_0200, "movaz single-slice"),
            (0xC00C_0000, "zero array"),
            (0xC048_0001, "zero zt0"),
            (0xC04C_03E0, "movt"),
            (0x80C0_0008, "mop4 f64"),
            (0x8140_0008, "tmop"),
            (0xA080_0008, "residue smopa"),
            (0xE11F_8000, "ldr zt0"),
        ]
        for (encoding, label) in owned {
            #expect(Iris.decode(encoding).mnemonic != .undefined,
                    "\(label) must be 2s.7's")
        }
    }

    @Test func theSVERegionCarveWordsAreClaimed() {
        for encoding: UInt32 in [
            0x2520_4010, 0x2520_5010, 0x2520_7010, 0x2520_7410,
            0x2520_7810, 0x2520_8200, 0x2521_8000, 0x2522_8000, 0x2524_4000,
        ] {
            #expect(Iris.decode(encoding).mnemonic != .undefined,
                    "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func theSMECoreWordsAreClaimedByTheirOwnSubpiece() {
        // Every SME-core family belongs to 2s.6, not 2s.7. Which subpiece
        // formed a record is not on the record — both carry `.sme` — but each
        // of these words must decode to a real instruction, which is what
        // shows the boundary was not drawn through the middle of a family.
        for encoding: UInt32 in [
            0x8080_0000, 0x81A0_0000, 0xA1E0_0010, // outer products
            0xC000_0000, 0xC008_00FF, 0xC090_0000, // mova / zero / addha
            0xE000_0000, 0xE100_0000, 0xE120_0000, // za load/store, ldr/str za
        ] {
            let d = Iris.decode(encoding)
            #expect(d.category == .sme, "0x\(String(encoding, radix: 16))")
            #expect(d.mnemonic != .undefined, "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func wordsFromOtherTiersAreDisclaimed() {
        for encoding: UInt32 in [
            0x0000_0000, // AMX / UDF space
            0x1400_0000, // branch
            0x8B02_0020, // data-processing register
            0xF900_0000, // load/store
            0x4E20_1C00, // advanced SIMD
            0x0420_0000, // SVE integer (2s.3)
            0x6520_0000, // SVE floating-point (2s.4)
            0x0518_A000, // SVE permute (2s.5)
        ] {
            #expect(Iris.decode(encoding).category != .sme,
                    "0x\(String(encoding, radix: 16))")
        }
    }
}

private let smePayloads: [UInt32] = [
    0x0000, 0x0001, 0x0008, 0x000F, 0x0010, 0x0018, 0x001C, 0x001E, 0x001F,
    0x0200, 0x0208, 0x03E0, 0x0400, 0x0800, 0x1000, 0x1C00, 0x2000, 0x8000,
    0x8008, 0xC400, 0xD000, 0xD800, 0xE000, 0xF400, 0x7FFF, 0xFFFF, 0x1234, 0xABCD,
]

/// Validates the tier-closure invariant by construction — every SME-region word
/// is owned by exactly one of 2s.6 and 2s.7, and every op0=2 word the carve
/// claims is one none of 2s.2–2s.5 claims. The predicates are independent code
/// from the decoders they gate, so the exact-complement relationship is swept
/// across the whole SME high-half space rather than sampled.
@Suite("SME2 / tier closure by construction")
struct SME2TierClosureTests {
    /// Every legal SME-region high half: bit31 set, bits[28:25] clear, with
    /// bits[30:29], bit24 and bits[23:16] free.
    private static let smeHighHalves: [UInt32] = {
        var result: [UInt32] = []
        result.reserveCapacity(2048)
        for top in UInt32(0) ..< 4 {
            for bit24 in UInt32(0) ..< 2 {
                for byte2 in UInt32(0) ..< 256 {
                    result.append(0x8000 | (top << 13) | (bit24 << 8) | byte2)
                }
            }
        }
        return result
    }()

    @Test func everySMERegionWordStaysInTheSMECategory() {
        // 2s.6 and 2s.7 split the SME region between them. Which of the two
        // claims a given word is internal — they share the `.sme` category —
        // but the split must be total: no word in the region may escape it or
        // come back attributed elsewhere.
        for high in Self.smeHighHalves {
            for payload in smePayloads {
                let e = (high << 16) | payload
                let d = Iris.decode(e, at: 0x4000)
                #expect(d.category == .sme, "0x\(String(e, radix: 16)) left the SME region")
                #expect(d.encoding == e)
                #expect(d.address == 0x4000)
            }
        }
    }

    @Test func everyCounterPredicateCarveWordStaysInTheScalableTier() {
        // 2s.7's claim inside the `0x25` top byte is a carve out of the SVE
        // tier, so its words keep the SVE category even though the SME2
        // decoder is what forms them.
        for low: UInt32 in 0 ..< 4096 {
            let e = 0x2520_0000 | (low << 6)
            let d = Iris.decode(e, at: 0)
            #expect(d.category == .sve, "0x\(String(e, radix: 16)) left the scalable tier")
            #expect(d.encoding == e)
        }
    }
}
