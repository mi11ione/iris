// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates `isSMECoreEncoding`, the predicate defining which SME words 2s.6
/// owns and the one gating the decoder, the skip filter and the harvester.
@Suite("SME core / encoding-scope predicate")
struct SMECoreScopeTests {
    @Test func onlyTheSMERegionIsConsidered() {
        for encoding: UInt32 in [
            0x0000_0000,
            0x0080_0000,
            0x1400_0000,
            0x0520_6000,
            0x8B02_0020,
            0xF900_0000,
            0x4E20_1C00,
            0xD503_47FF,
        ] {
            #expect(Iris.decode(encoding).category != .sme,
                    "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func everyCoreOuterProductRowIsClaimed() {
        for encoding: UInt32 in [
            0x8080_0000, 0x8080_0010, 0x8080_0008, 0x8080_0018,
            0x8180_0000, 0x8180_0010,
            0x81A0_0000, 0x81A0_0010,
            0x80C0_0000, 0x80C0_0010,
            0x8180_0008, 0x8180_0018,
            0x81A0_0008, 0x81A0_0018,
            0xA080_0000, 0xA080_0010, 0xA0A0_0000, 0xA0A0_0010,
            0xA180_0000, 0xA180_0010, 0xA1A0_0000, 0xA1A0_0010,
            0xA0C0_0000, 0xA0C0_0010, 0xA0E0_0000, 0xA0E0_0010,
            0xA1C0_0000, 0xA1C0_0010, 0xA1E0_0000, 0xA1E0_0010,
        ] {
            #expect(Iris.decode(encoding).mnemonic != .undefined,
                    "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func theSME2OuterProductResidueIsDisclaimed() {
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
            let d = Iris.decode(encoding, at: 0x2000)
            #expect(d.category == .sme, "\(label)")
            #expect(d.encoding == encoding, "\(label)")
            #expect(d.address == 0x2000, "\(label)")
        }
    }

    @Test func theBitTwentyThreeZeroHalvesOfTheOuterProductCellsAreDisclaimed() {
        for topByte: UInt32 in [0x80, 0x81, 0xA0, 0xA1] {
            for low: UInt32 in [0x000000, 0x000010, 0x123456, 0x7FFFFF] {
                let encoding = (topByte << 24) | low
                #expect(Iris.decode(encoding).category != .sve,
                        "0x\(String(encoding, radix: 16))")
            }
        }
    }

    @Test func theMoveZeroCellsAreClaimedBlockByBlock() {
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
            #expect(Iris.decode(encoding).mnemonic != .undefined,
                    "\(label) must be claimed")
        }
    }

    @Test func anInScopeHoleDecodesToAWellFormedUndefined() {
        let holes: [(UInt32, String)] = [
            (0xE000_0010, "ld1b with bit4 set"),
            (0xE100_0010, "ldr za with bit4 set"),
            (0xE180_0000, "unallocated 111|1|1 opcode"),
            (0xE1A0_0000, "unallocated 111|1|1 opcode"),
        ]
        for (encoding, label) in holes {
            let draft = Iris.decode(encoding, at: 0x2000)
            #expect(draft.mnemonic == .undefined, "\(label)")
            #expect(draft.category == .sme, "\(label)")
            #expect(draft.encoding == encoding, "\(label)")
            #expect(draft.address == 0x2000, "\(label)")
            #expect(draft.operands.isEmpty, "\(label)")
            #expect(draft.text == ".long 0x\(String(encoding, radix: 16))", "\(label)")
        }
    }
}

/// Validates that the scope predicate, the family gate and the core decoder's
/// sub-dispatch agree across the whole SME region.
@Suite("SME core / decoder agrees with its scope predicate")
struct SMECoreScopeAgreementTests {
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
        Self.sweep { encoding in
            #expect(Iris.decode(encoding).category == .sme,
                    "0x\(String(encoding, radix: 16)) left the SME category")
        }
    }

    @Test func everyClaimedWordCarriesTheUniversalRecordInvariants() {
        Self.sweep { encoding in
            let draft = Iris.decode(encoding, at: 0x4000)
            #expect(draft.category == .sme, "0x\(String(encoding, radix: 16))")
            #expect(draft.encoding == encoding)
            #expect(draft.address == 0x4000)
            #expect(draft.branchClass == .none)
            #expect(draft.flagEffect == .none)
            #expect(draft.memoryOrdering == [])
        }
    }

    @Test func everyClaimedWordRendersTextExactlyWhenItDecodes() {
        Self.sweep { encoding in
            let draft = Iris.decode(encoding, at: 0)
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
