// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates `isSVEFloatingPointEncoding`, the predicate defining which SVE
/// words the floating-point decoder owns and the one consulted by the family.
@Suite("SVE floating-point / encoding-scope predicate")
struct SVEFloatingPointScopeTests {
    @Test func onlyTheScalableTierIsConsidered() {
        for encoding: UInt32 in [
            0x0000_0000,
            0x1400_0000,
            0x8B02_0020,
            0xF900_0000,
            0x4E20_1C00,
            0x7500_0000,
        ] {
            #expect(Iris.decode(encoding).category != .sve,
                    "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func neighbouringGroupsThatShareTheEncodingSpaceAreDisclaimed() {
        let foreign: [(UInt32, String)] = [
            (0x0400_0000, "add predicated — integer (2s.3)"),
            (0x0422_0020, "add unpredicated — integer (2s.3)"),
            (0x0456_A820, "abs /m — integer unary (2s.3)"),
            (0x2538_C000, "dup immediate — integer (2s.3), one bit below fdup"),
            (0x0510_0000, "cpy immediate — integer (2s.3), bit15 below fcpy"),
            (0x2518_E000, "ptrue — predicate initialise (2s.2)"),
            (0x2510_4020, "brka — predicate partition (2s.2)"),
            (0x0420_BC20, "movprfx unpredicated (2s.2), the ftssel neighbour"),
            (0x0420_E3E0, "cntb — element count (2s.2)"),
            (0x0522_6000, "zip1 — permute (2s.5)"),
            (0xA400_4000, "ld1b — memory (2s.5)"),
            (0x8400_4000, "ld1b gather — memory (2s.5)"),
            (0xE400_4000, "st1b — memory (2s.5)"),
        ]
        for (encoding, label) in foreign {
            #expect(Iris.decode(encoding).mnemonic != .undefined,
                    "\(label) must decode in its own group")
        }
    }

    @Test func theArchitecturalHolesStayInScopeAndDecodeToUndefined() {
        let holes: [(UInt32, String)] = [
            (0x654B_8000, "reserved predicated-binary opcode 1011"),
            (0x650D_8000, "fdiv at the reserved sz=00"),
            (0x6580_1000, "reserved unpredicated-3op opcode 100"),
            (0x6400_0000, "fcmla vector at the reserved sz=00"),
            (0x6518_2000, "fadda at the reserved sz=00"),
            (0x6510_2000, "compare-with-zero at the reserved sz=00"),
        ]
        for (encoding, label) in holes {
            let draft = Iris.decode(encoding, at: 0)
            #expect(draft.mnemonic == .undefined, "\(label) must decode to UNDEFINED")
            #expect(draft.category == .sve, "\(label) must stay categorized as SVE")
            #expect(draft.operands.isEmpty, "\(label) must carry no operands")
        }
    }
}

/// Validates that the family gate, the scope predicate and the decoder agree
/// over the whole dispatch-relevant space.
@Suite("SVE floating-point / decoder agrees with its scope predicate")
struct SVEFloatingPointScopeAgreementTests {
    private static let payloads: [UInt32] = [0x000, 0x3FF, 0x2AA, 0x155]
    private static let ownedTopBytes: [UInt32] = [0x64, 0x65]
    private static let carveOutTopBytes: [UInt32] = [0x04, 0x05, 0x25]

    private static func sweep(topByte: UInt32, _ body: (UInt32) -> Void) {
        for dispatch in UInt32(0) ..< (1 << 14) {
            for payload in payloads {
                body((topByte << 24) | (dispatch << 10) | payload)
            }
        }
    }

    @Test func everyOwnedWordCarriesTheScalableCategoryAndItsRawEncoding() {
        for topByte in Self.ownedTopBytes {
            Self.sweep(topByte: topByte) { encoding in
                let draft = Iris.decode(encoding, at: 0x4000)
                #expect(draft.category == .sve)
                #expect(draft.encoding == encoding)
                #expect(draft.address == 0x4000)
                #expect(draft.branchClass == .none)
                #expect(draft.memoryAccess == .none)
                #expect(draft.memoryOrdering == [])
                #expect(draft.flagEffect == .none)
            }
        }
    }

    @Test func everyOwnedWordRendersTextExactlyWhenItDecodes() {
        for topByte in Self.ownedTopBytes {
            Self.sweep(topByte: topByte) { encoding in
                let draft = Iris.decode(encoding, at: 0)
                let text = draft.text
                if draft.mnemonic == .undefined {
                    #expect(text == ".long 0x\(String(encoding, radix: 16))",
                            "0x\(String(encoding, radix: 16)) rendered `\(text)`")
                } else {
                    #expect(!text.isEmpty, "0x\(String(encoding, radix: 16)) rendered nothing")
                    #expect(!text.contains("?"), "0x\(String(encoding, radix: 16)) rendered `\(text)`")
                }
            }
        }
    }
}
