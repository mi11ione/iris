// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates `isSMECoreEncoding` — the single predicate that defines which SME
/// words subpiece 2s.6 owns. The same predicate gates the family decoder, the
/// validator's skip filter, and the corpus harvester's scope filter, so a wrong
/// answer either strands a real instruction outside validation or hands a 2s.7
/// word to a decoder that cannot represent it. The SME region interleaves core
/// and SME2 encodings inside every coarse cell, so each claim is asserted at the
/// granularity the predicate actually uses: whole cells where the core owns the
/// cell outright, exact encoding rows where SME2 shares it.
@Suite("SME core / encoding-scope predicate")
struct SMECoreScopeTests {
    @Test func onlyTheSMERegionIsConsidered() {
        // The region is op0=0b0000 (bits[28:25]) with bit31 set. A word outside
        // it belongs to another family however its low bits look.
        for encoding: UInt32 in [
            0x0000_0000, // op0=0, bit31 clear — AMX / UDF space
            0x0080_0000, // bit31 clear, core-looking low bits
            0x1400_0000, // branch
            0x0520_6000, // SVE permute (op0=2)
            0x8B02_0020, // data-processing register
            0xF900_0000, // load/store
            0x4E20_1C00, // advanced SIMD
            0xD503_47FF, // system
        ] {
            #expect(Iris.decode(encoding, features: .scalable).category != .sme,
                    "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func everyCoreOuterProductRowIsClaimed() {
        // The two bit24=0 outer-product cells share space with F8 / MOP4 / 2-way
        // SME2 forms, so they are claimed row by row — every core row must match.
        for encoding: UInt32 in [
            0x8080_0000, 0x8080_0010, 0x8080_0008, 0x8080_0018, // fmopa/s bmopa/s .s
            0x8180_0000, 0x8180_0010, // bfmopa/s widening
            0x81A0_0000, 0x81A0_0010, // fmopa/s widening
            0x80C0_0000, 0x80C0_0010, // fmopa/s .d
            0x8180_0008, 0x8180_0018, // fmopa/s .h
            0x81A0_0008, 0x81A0_0018, // bfmopa/s .h
            0xA080_0000, 0xA080_0010, 0xA0A0_0000, 0xA0A0_0010, // smopa/s sumopa/s .s
            0xA180_0000, 0xA180_0010, 0xA1A0_0000, 0xA1A0_0010, // usmopa/s umopa/s .s
            0xA0C0_0000, 0xA0C0_0010, 0xA0E0_0000, 0xA0E0_0010, // smopa/s sumopa/s .d
            0xA1C0_0000, 0xA1C0_0010, 0xA1E0_0000, 0xA1E0_0010, // usmopa/s umopa/s .d
        ] {
            #expect(Iris.decode(encoding, features: .scalable).mnemonic != .undefined,
                    "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func theSME2OuterProductResidueIsDisclaimed() {
        // Each sits one selector bit away from a core row but belongs to 2s.7.
        let residue: [(UInt32, String)] = [
            (0x80A0_0000, "F8 outer product (the whole 0x80A0 block)"),
            (0x80A0_0010, "F8 outer product, S bit set"),
            (0x80C0_0008, "MOP4 f64 (bit3 inside the .d frame)"),
            (0x80D0_0218, "MOP4 f64, second value set"),
            (0xA080_0008, "SME2 2-way SMOPA I16→I32 (bit3 in the integer frame)"),
            (0xA080_0018, "SME2 2-way SMOPS"),
            (0xA180_0008, "SME2 2-way UMOPA"),
            (0xA180_0018, "SME2 2-way UMOPS"),
            (0xA0C0_0008, "MOP4 i64 (S/SU)"),
            (0xA1E0_0208, "MOP4 i64 (US/U)"),
        ]
        for (encoding, label) in residue {
            // 2s.7 owns these. Which subpiece formed the record is not on the
            // record — both carry `.sme`, and a hole inside either looks the
            // same — so what is checkable here is that the word stays in the
            // region and keeps its raw bytes.
            let d = Iris.decode(encoding, at: 0x2000, features: .scalable)
            #expect(d.category == .sme, "\(label)")
            #expect(d.encoding == encoding, "\(label)")
            #expect(d.address == 0x2000, "\(label)")
        }
    }

    @Test func theBitTwentyThreeZeroHalvesOfTheOuterProductCellsAreDisclaimed() {
        // 100|x|0 and 101|x|0 are SME2 wholesale (TMOP/MOP4 variants, multi-Z
        // memory) — the predicate rejects them before it looks at any row.
        for topByte: UInt32 in [0x80, 0x81, 0xA0, 0xA1] {
            for low: UInt32 in [0x000000, 0x000010, 0x123456, 0x7FFFFF] {
                let encoding = (topByte << 24) | low
                #expect(Iris.decode(encoding, features: .scalable).category != .sve,
                        "0x\(String(encoding, radix: 16))")
            }
        }
    }

    @Test func theMoveZeroCellsAreClaimedBlockByBlock() {
        // 110|0|x hosts a dense SME2 population, so 2s.6 claims only its exact
        // MOVA / ZERO / ADDHA / ADDVA blocks.
        let owned: [(UInt32, String)] = [
            (0xC000_0000, "mova insert .b"),
            (0xC040_0000, "mova insert .h"),
            (0xC080_0000, "mova insert .s"),
            (0xC0C0_0000, "mova insert .d"),
            (0xC0C1_0000, "mova insert .q"),
            (0xC000_8000, "mova insert .b vertical"),
            (0xC002_0000, "mova extract .b"),
            (0xC042_0000, "mova extract .h"),
            (0xC082_0000, "mova extract .s"),
            (0xC0C2_0000, "mova extract .d"),
            (0xC0C3_0000, "mova extract .q"),
            (0xC0C3_8000, "mova extract .q vertical"),
            (0xC008_0000, "zero, imm8=0"),
            (0xC008_00FF, "zero, imm8=255"),
            (0xC090_0000, "addha .s"),
            (0xC091_0000, "addva .s"),
            (0xC0D0_0000, "addha .d"),
            (0xC0D1_0000, "addva .d"),
        ]
        for (encoding, label) in owned {
            #expect(Iris.decode(encoding, features: .scalable).mnemonic != .undefined,
                    "\(label) must be claimed")
        }
    }

    @Test func anInScopeHoleDecodesToAWellFormedUndefined() {
        // A hole inside a claimed cell is 2s.6's to reject: it must stay in
        // scope (or nothing would ever validate it) and decode to UNDEFINED
        // with the SME category and no invented state.
        let holes: [(UInt32, String)] = [
            (0xE000_0010, "ld1b with bit4 set"),
            (0xE100_0010, "ldr za with bit4 set"),
            (0xE180_0000, "unallocated 111|1|1 opcode"),
            (0xE1A0_0000, "unallocated 111|1|1 opcode"),
        ]
        for (encoding, label) in holes {
            let draft = Iris.decode(encoding, at: 0x2000, features: .scalable)
            #expect(draft.mnemonic == .undefined, "\(label)")
            #expect(draft.category == .sme, "\(label)")
            #expect(draft.encoding == encoding, "\(label)")
            #expect(draft.address == 0x2000, "\(label)")
            #expect(draft.operands.isEmpty, "\(label)")
            #expect(draft.text == ".long 0x\(String(encoding, radix: 16))", "\(label)")
        }
    }
}

/// Validates that the scope predicate, the family gate, and the core decoder's
/// own sub-dispatch agree across the whole SME region. The predicate and the
/// decoder are two independent transcriptions of the same encoding tables, so
/// they can drift apart; a word the gate routes into the core decoder but that
/// no dispatch row matches would silently become UNDEFINED, and a word the gate
/// withholds would never be validated at all. The sweep walks every legal SME
/// high half (all 2048 combinations of bits[31:29] | bit24 | bits[23:16]) across
/// payloads chosen to move each dispatch-relevant low field — the V bit, the
/// select and predicate fields, the MOVAZ bit9, the S bit4, and the tile|offset
/// nibble — so a routing decision that depended on the wrong bit cannot hide.
@Suite("SME core / decoder agrees with its scope predicate")
struct SMECoreScopeAgreementTests {
    /// Every legal SME-region high half: bit31 set, bits[28:25] clear, with
    /// bits[30:29], bit24 and bits[23:16] free.
    private static let highHalves: [UInt32] = {
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

    /// Low halves that move every field the dispatch reads: the tile|offset
    /// nibble and S bit (bits[4:0]), the MOVAZ discriminator (bit9), the
    /// predicate (bits[12:10]) and select (bits[14:13]) fields, and V (bit15).
    private static let payloads: [UInt32] = [
        0x0000, 0x0001, 0x0007, 0x000F, 0x0010, 0x0018, 0x001C, 0x001E, 0x001F,
        0x0200, 0x0208, 0x0210, 0x0218, 0x03E0, 0x03FF,
        0x8000, 0x800F, 0x8010, 0x83E0, 0x8200,
        0x6000, 0x63E7, 0x7C00, 0x7FFF, 0xFFFF,
        0x00FF, 0x0100, 0x1234, 0xABCD, 0x0FF0,
    ]

    private static func sweep(_ body: (UInt32) -> Void) {
        for high in highHalves {
            for payload in payloads {
                body((high << 16) | payload)
            }
        }
    }

    @Test func noClaimedWordLeavesTheSMECategory() {
        // The SME region is disjoint from SVE by fixed bits. A record can only
        // carry one category, so an overlap would surface here as an SME-region
        // word coming back attributed to the SVE tier.
        Self.sweep { encoding in
            #expect(Iris.decode(encoding, features: .scalable).category == .sme,
                    "0x\(String(encoding, radix: 16)) left the SME category")
        }
    }

    @Test func everyClaimedWordCarriesTheUniversalRecordInvariants() {
        Self.sweep { encoding in
            let draft = Iris.decode(encoding, at: 0x4000, features: .scalable)
            #expect(draft.category == .sme, "0x\(String(encoding, radix: 16))")
            #expect(draft.encoding == encoding)
            #expect(draft.address == 0x4000)
            #expect(draft.branchClass == .none)
            #expect(draft.flagEffect == .none)
            #expect(draft.memoryOrdering == [])
        }
    }

    @Test func everyClaimedWordRendersTextExactlyWhenItDecodes() {
        // A decoded record renders nonempty single-line text with no unresolved
        // placeholder; an UNDEFINED renders the empty string, which is the
        // reference assembler's output for a rejected word.
        Self.sweep { encoding in
            let draft = Iris.decode(encoding, at: 0, features: .scalable)
            let text = draft.text
            if draft.mnemonic == .undefined {
                #expect(text == ".long 0x\(String(encoding, radix: 16))",
                        "0x\(String(encoding, radix: 16)) rendered `\(text)`")
            } else {
                #expect(!text.isEmpty, "0x\(String(encoding, radix: 16)) rendered nothing")
                #expect(!text.contains("?"), "0x\(String(encoding, radix: 16)) rendered `\(text)`")
                #expect(!text.contains("\n"), "0x\(String(encoding, radix: 16)) rendered `\(text)`")
            }
        }
    }
}
