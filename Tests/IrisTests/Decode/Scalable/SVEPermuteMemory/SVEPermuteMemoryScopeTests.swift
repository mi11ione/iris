// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates `isSVEPermuteMemoryCryptoEncoding`, the predicate defining which
/// SVE words the permute/memory/crypto decoder owns and the one consulted by.
@Suite("SVE permute/memory/crypto / encoding-scope predicate")
struct SVEPermuteMemoryScopeTests {
    @Test func onlyTheScalableTierIsConsidered() {
        for encoding: UInt32 in [
            0x0000_0000,
            0x1400_0000,
            0x8B02_0020,
            0xF900_0000,
            0x4E20_1C00,
            0x8000_0000,
            0xD000_0000,
        ] {
            #expect(Iris.decode(encoding).category != .sve,
                    "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func theWholeMemoryRegionIsClaimed() {
        for topByte: UInt32 in [0x84, 0x85, 0xA4, 0xA5, 0xC4, 0xC5, 0xE4, 0xE5] {
            for low: UInt32 in [0x000000, 0x004000, 0x123456, 0xFFFFFF] {
                let encoding = (topByte << 24) | low
                #expect(Iris.decode(encoding).category == .sve,
                        "0x\(String(encoding, radix: 16)) memory must be scalable")
            }
        }
    }

    @Test func everyComputeCarveOutIsClaimed() {
        let owned: [(UInt32, String)] = [
            (0x0520_6000, "zip1 vector permute (0x05)"),
            (0x0520_C000, "sel→mov permute (0x05)"),
            (0x0524_3800, "insr from GPR (0x05)"),
            (0x0521_8000, "compact predicated (0x05)"),
            (0x0520_A000, "lasta to GPR (0x05)"),
            (0x0538_3800, "rev vector (0x05)"),
            (0x0531_4000, "punpkhi predicate (0x05)"),
            (0x052A_3800, "pmov vector-to-pred (0x05)"),
            (0x4400_E000, "zipq1 quadword permute (0x44)"),
            (0x4400_F800, "tblq quadword table (0x44)"),
            (0x4522_E000, "aese crypto (0x45)"),
            (0x4520_F800, "pmull multi-vector (0x45)"),
            (0x4520_B000, "luti2 (0x45)"),
            (0x4520_F400, "rax1 (0x45)"),
        ]
        for (encoding, label) in owned {
            #expect(Iris.decode(encoding).mnemonic != .undefined,
                    "\(label) must be claimed")
        }
    }

    @Test func theArchitecturalHolesStayInScopeAndDecodeToUndefined() {
        let holes: [(UInt32, String)] = [
            (0x0504_0000, "permute reserved class (0x05)"),
            (0x4400_F000, "quadword reserved opcode (0x44)"),
            (0x4520_E020, "crypto reserved (0x45)"),
            (0x8400_C010, "32-bit gather reserved (0x84)"),
            (0xA400_8000, "contiguous-load reserved (0xA4)"),
            (0xC400_E010, "64-bit gather reserved (0xC4)"),
            (0xE400_0000, "store structured nregs=0 (0xE4)"),
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
@Suite("SVE permute/memory/crypto / decoder agrees with its scope predicate")
struct SVEPermuteMemoryScopeAgreementTests {
    private static let payloads: [UInt32] = [0x000, 0x3FF, 0x2AA, 0x155]
    private static let computeTopBytes: [UInt32] = [0x05, 0x44, 0x45]
    private static let memoryTopBytes: [UInt32] = [0x84, 0x85, 0xA4, 0xA5, 0xC4, 0xC5, 0xE4, 0xE5]

    private static func sweep(topByte: UInt32, _ body: (UInt32) -> Void) {
        for dispatch in UInt32(0) ..< (1 << 14) {
            for payload in payloads {
                body((topByte << 24) | (dispatch << 10) | payload)
            }
        }
    }

    @Test func everyOwnedWordCarriesTheScalableCategoryAndItsRawEncoding() {
        for topByte in Self.memoryTopBytes + Self.computeTopBytes {
            Self.sweep(topByte: topByte) { encoding in
                let draft = Iris.decode(encoding, at: 0x4000)
                #expect(draft.category == .sve)
                #expect(draft.encoding == encoding)
                #expect(draft.address == 0x4000)
            }
        }
    }

    @Test func everyOwnedWordRendersTextExactlyWhenItDecodes() {
        for topByte in Self.memoryTopBytes + Self.computeTopBytes {
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
