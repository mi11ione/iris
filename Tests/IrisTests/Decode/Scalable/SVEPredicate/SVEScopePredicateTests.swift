// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates `isSVEPredicateControlEncoding`, the predicate defining which SVE
/// words the predicate & control decoder owns and the one consulted by the.
@Suite("SVE predicate & control / encoding-scope predicate")
struct SVEScopePredicateTests {
    @Test func onlyTheScalableTierIsConsidered() {
        for encoding: UInt32 in [
            0x0000_0000,
            0x1400_0000,
            0x8B02_0020,
            0xF900_0000,
            0x4E20_1C00,
            0x2400_0000 | 0x0200_0000,
        ] {
            #expect(Iris.decode(encoding).category != .sve,
                    "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func everyOwnedGroupIsClaimed() {
        let owned: [(UInt32, String)] = [
            (0x2518_E000, "ptrue"),
            (0x2518_E400, "pfalse"),
            (0x2550_C000, "ptest"),
            (0x2503_4820, "predicate logical"),
            (0x2510_4443, "brka"),
            (0x2518_4443, "brkn"),
            (0x2504_C443, "brkpa"),
            (0x2558_C043, "pfirst"),
            (0x2519_C443, "pnext"),
            (0x2518_F043, "rdffr"),
            (0x2528_9040, "wrffr"),
            (0x252C_9000, "setffr"),
            (0x2520_8443, "cntp"),
            (0x256C_8043, "incp vector"),
            (0x256C_8843, "incp scalar"),
            (0x2525_04C7, "whilelt"),
            (0x2525_30C7, "whilewr"),
            (0x25A5_20C0, "ctermeq"),
            (0x0420_E3E0, "cntb"),
            (0x0420_F3E1, "sqincb"),
            (0x0460_C3E2, "sqinch vector"),
            (0x0421_50A2, "addvl"),
            (0x04BF_5020, "rdvl"),
            (0x0423_4020, "index"),
            (0x0420_BC20, "movprfx unpredicated"),
            (0x0450_2C20, "movprfx predicated"),
        ]
        for (encoding, label) in owned {
            #expect(Iris.decode(encoding).mnemonic != .undefined,
                    "\(label) must be claimed")
        }
    }

    @Test func theCtermSlotIsClaimedOnlyWithItsHighBitSet() {
        #expect(Iris.decode(0x25A5_20C0).mnemonic != .undefined)
        #expect(Iris.decode(0x2565_20C0).mnemonic == .undefined,
                "bit 23 clear is unallocated space")
    }

    @Test func theMovprfxUnpredicatedSlotNeedsBothLowOpcodeBits() {
        #expect(Iris.decode(0x0420_BC20).mnemonic == .movprfx)
        #expect(Iris.decode(0x0420_B820).mnemonic != .movprfx)
        #expect(Iris.decode(0x0420_B420).mnemonic != .movprfx)
    }

    @Test func theArchitecturalHolesStayInScopeAndDecodeToUndefined() {
        let holes: [(UInt32, String)] = [
            (0x2543_4A30, "unallocated predicate-logical slot"),
            (0x2550_4453, "brkas with a merging qualifier"),
            (0x2559_F003, "rdffrs unpredicated"),
            (0x2518_C043, "pfirst with a size field"),
            (0x0430_C3E2, "byte-element vector count"),
            (0x256E_8043, "unallocated predicate-count op"),
            (0x04FF_5020, "rdvl with the pl bit set"),
        ]
        for (encoding, label) in holes {
            let draft = Iris.decode(encoding, at: 0)
            #expect(draft.mnemonic == .undefined, "\(label) must decode to UNDEFINED")
            #expect(draft.category == .sve, "\(label) must stay categorized as SVE")
        }
    }
}

/// Validates that the predicate & control decoder is total over both regions
/// it spans and never invents an instruction for a word it does not own.
@Suite("SVE predicate & control / decoder agrees with its scope predicate")
struct SVEPredicateControlScopeAgreementTests {
    private static let payloads: [UInt32] = [0x000, 0x1FF]

    private static func sweep(topByte: UInt32, _ body: (UInt32) -> Void) {
        for dispatch in UInt32(0) ..< (1 << 15) {
            for payload in payloads {
                body((topByte << 24) | (dispatch << 9) | payload)
            }
        }
    }

    @Test func everyOwnedWordCarriesTheScalableCategoryAndItsRawEncoding() {
        for topByte: UInt32 in [0x04, 0x25] {
            Self.sweep(topByte: topByte) { encoding in
                let draft = Iris.decode(encoding, at: 0x4000)
                #expect(draft.category == .sve)
                #expect(draft.encoding == encoding)
                #expect(draft.address == 0x4000)
                #expect(draft.branchClass == .none)
                #expect(draft.memoryAccess == .none)
                #expect(draft.memoryOrdering == [])
            }
        }
    }
}
