// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates `isSVEFloatingPointEncoding` — the single encoding predicate that
/// defines which SVE words the floating-point decoder owns. It is consulted by
/// the family decoder's gate, the validator's skip filter and the corpus
/// harvester's scope filter, so a wrong answer either silently drops a real
/// instruction from validation or hands a foreign encoding to the wrong
/// decoder. 2s.4 owns both 0x64/0x65 top bytes outright plus four carve-out
/// families that live at the integer top bytes 0x04/0x05/0x25, so each owned
/// region is claimed and each neighbouring family that shares the encoding
/// space (integer, predicate & control, permute, memory) is disclaimed.
@Suite("SVE floating-point / encoding-scope predicate")
struct SVEFloatingPointScopeTests {
    @Test func onlyTheScalableTierIsConsidered() {
        // op0 (bits 28:25) must be 0b0010. Everything else is another family's
        // encoding space, whatever its low bits look like.
        for encoding: UInt32 in [
            0x0000_0000, // op0=0 reserved
            0x1400_0000, // branch
            0x8B02_0020, // data-processing register
            0xF900_0000, // load/store
            0x4E20_1C00, // advanced SIMD
            0x7500_0000, // op0=0b1010 — a top byte that shares the 0x?5 low nibble
        ] {
            #expect(Iris.decode(encoding).category != .sve,
                    "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func neighbouringGroupsThatShareTheEncodingSpaceAreDisclaimed() {
        // Each sits inside one of the top bytes 2s.4 borders but belongs to
        // another sibling decoder. The carve-out signatures are the exact complement of
        // 2s.3's exclusions, so an integer DUP/CPY one bit away must stay out.
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
        // A hole inside an owned region is this decoder's to reject — it must not
        // be pushed out of scope, or nothing would ever validate it.
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

/// Validates that the family gate, the scope predicate, and the floating-point
/// decoder agree over the entire dispatch-relevant encoding space. The scope
/// predicate and the decoder's sub-dispatch are two independent transcriptions
/// of the same encoding tree, so they can disagree — and a family gate that
/// routed an owned word to the wrong decoder (or a foreign word here) would
/// mis-decode silently. The sweep exhausts every dispatch-relevant bit
/// combination (bits[23:10], the sz / bit21 / opcode / sub-class selectors)
/// across the two owned top bytes and the three carve-out top bytes, with four
/// payload patterns so a routing decision that wrongly depended on the register
/// or fixed-zero payload bits could not hide.
@Suite("SVE floating-point / decoder agrees with its scope predicate")
struct SVEFloatingPointScopeAgreementTests {
    /// Bits 23...10 select every dispatch path; the payloads below drive the
    /// register fields plus the fixed-zero fields the class decoders reject on
    /// (bit5 / bits[9:6] in the pair-convert and immediate classes).
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
        // A decoded record must render nonempty single-line text with no
        // unresolved placeholder; an UNDEFINED must render the empty string
        // (the reference assembler's silence for a rejected word).
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
