// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates `isSVEPermuteMemoryCryptoEncoding` — the single encoding predicate
/// that defines which SVE words the permute/memory/crypto decoder owns. It is
/// consulted by the family decoder's gate, the validator's skip filter and the
/// corpus harvester's scope filter, so a wrong answer either silently drops a
/// real instruction from validation or hands a foreign encoding to the wrong
/// decoder. 2s.5 owns the entire memory region (bit31=1) outright plus three
/// complement carve-outs at the shared compute top bytes 0x05 (permute), 0x44
/// (quadword permute), and 0x45 (crypto / LUT), so each owned region is claimed
/// and each sibling that shares the encoding space (integer, predicate,
/// floating-point) is disclaimed.
@Suite("SVE permute/memory/crypto / encoding-scope predicate")
struct SVEPermuteMemoryScopeTests {
    @Test func onlyTheScalableTierIsConsidered() {
        // op0 (bits 28:25) must be 0b0010. Everything else is another family's
        // encoding space, whatever its low bits look like. (bit31=1 alone is
        // not enough — an op0≠2 word with bit31 set belongs elsewhere.)
        for encoding: UInt32 in [
            0x0000_0000, // op0=0 reserved / SME
            0x1400_0000, // branch
            0x8B02_0020, // data-processing register
            0xF900_0000, // load/store
            0x4E20_1C00, // advanced SIMD
            0x8000_0000, // op0=0 bit31=1 — SME, not SVE memory
            0xD000_0000, // op0=0 tier, bit31=1
        ] {
            #expect(Iris.decode(encoding, features: .scalable).category != .sve,
                    "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func theWholeMemoryRegionIsClaimed() {
        // Every bit31=1 op0=2 word is 2s.5's — no sibling claims the memory
        // region, so the predicate returns true for all eight memory top bytes
        // regardless of the low bits.
        for topByte: UInt32 in [0x84, 0x85, 0xA4, 0xA5, 0xC4, 0xC5, 0xE4, 0xE5] {
            for low: UInt32 in [0x000000, 0x004000, 0x123456, 0xFFFFFF] {
                let encoding = (topByte << 24) | low
                #expect(Iris.decode(encoding, features: .scalable).category == .sve,
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
            #expect(Iris.decode(encoding, features: .scalable).mnemonic != .undefined,
                    "\(label) must be claimed")
        }
    }

    @Test func theArchitecturalHolesStayInScopeAndDecodeToUndefined() {
        // A hole inside an owned region is this decoder's to reject — it must not
        // be pushed out of scope, or nothing would ever validate it.
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
            let draft = Iris.decode(encoding, at: 0, features: .scalable)
            #expect(draft.mnemonic == .undefined, "\(label) must decode to UNDEFINED")
            #expect(draft.category == .sve, "\(label) must stay categorized as SVE")
            #expect(draft.operands.isEmpty, "\(label) must carry no operands")
        }
    }
}

/// Validates that the family gate, the scope predicate, and the permute/memory/
/// crypto decoder agree over the entire dispatch-relevant encoding space. The
/// scope predicate and the decoder's sub-dispatch are two independent
/// transcriptions of the same encoding tree, so they can disagree — and a
/// family gate that routed an owned word to the wrong decoder (or a foreign
/// word here) would mis-decode silently. The sweep exhausts every
/// dispatch-relevant bit combination (bits[23:10] — the sz / nregs / class /
/// opcode / Rm selectors) across all eleven owned top bytes, with four payload
/// patterns so a routing decision that wrongly depended on the register or
/// fixed-zero payload bits (bit9 for PMOV, bit4 for prefetch, bit0 for PMULL)
/// could not hide.
@Suite("SVE permute/memory/crypto / decoder agrees with its scope predicate")
struct SVEPermuteMemoryScopeAgreementTests {
    /// bits[23:10] select every dispatch path; the payloads drive the register
    /// fields plus the fixed-zero bits the class decoders reject on.
    private static let payloads: [UInt32] = [0x000, 0x3FF, 0x2AA, 0x155]
    /// The three compute carve-out top bytes (words here may belong to a
    /// sibling) and the eight memory top bytes (every word is 2s.5's).
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
                let draft = Iris.decode(encoding, at: 0x4000, features: .scalable)
                #expect(draft.category == .sve)
                #expect(draft.encoding == encoding)
                #expect(draft.address == 0x4000)
            }
        }
    }

    @Test func everyOwnedWordRendersTextExactlyWhenItDecodes() {
        // A decoded record must render nonempty single-line text with no
        // unresolved placeholder; an UNDEFINED must render the empty string (the
        // reference assembler's silence for a rejected word).
        for topByte in Self.memoryTopBytes + Self.computeTopBytes {
            Self.sweep(topByte: topByte) { encoding in
                let draft = Iris.decode(encoding, at: 0, features: .scalable)
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
