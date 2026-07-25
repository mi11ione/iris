// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates `isSVEIntegerEncoding` — the single encoding predicate that
/// defines which SVE words the integer decoder owns. It is consulted by the
/// family decoder's gate, the validator's skip filter and the corpus
/// harvester's scope filter, so a wrong answer either silently drops a real
/// instruction from validation or hands a foreign encoding to the wrong
/// decoder. 2s.3 spans six top bytes interleaved with four sibling decoders,
/// so each in-scope group is claimed and each neighbouring family that shares
/// the encoding space (predicate & control, floating-point, permute, crypto,
/// counter forms, memory) is disclaimed.
@Suite("SVE integer / encoding-scope predicate")
struct SVEIntegerScopeTests {
    @Test func onlyTheScalableTierIsConsidered() {
        // op0 (bits 28:25) must be 0b0010. Everything else is another family's
        // encoding space, whatever its low bits look like — observable as a
        // decode that lands outside the scalable category entirely.
        for encoding: UInt32 in [
            0x0000_0000, // op0=0 reserved
            0x1400_0000, // branch
            0x8B02_0020, // data-processing register
            0xF900_0000, // load/store
            0x4E20_1C00, // advanced SIMD
            0x1520_C000, // wide-immediate bits under a branch top byte
        ] {
            #expect(Iris.decode(encoding, features: .scalable).category != .sve,
                    "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func everyOwnedGroupIsClaimed() {
        let owned: [(UInt32, String)] = [
            (0x0400_0000, "add predicated (G1)"),
            (0x0494_0443, "sdiv predicated (G1)"),
            (0x0400_8100, "asr immediate (G2)"),
            (0x0490_8020, "asr register (G2)"),
            (0x0418_8020, "asr wide (G2)"),
            (0x0456_A820, "abs /m (G3)"),
            (0x0446_A820, "abs /z (G3, SVE2p2)"),
            (0x0482_4020, "mla (G4)"),
            (0x0481_C040, "mad (G4)"),
            (0x0400_2443, "saddv (G5)"),
            (0x0405_2443, "addqv quadword (G5)"),
            (0x0422_0020, "add unpredicated (G6)"),
            (0x0422_3020, "and unpredicated (G6)"),
            (0x0422_6020, "mul unpredicated (G6)"),
            (0x0428_9020, "asr unpredicated immediate (G6)"),
            (0x04A0_8000, "asr unpredicated wide (G6)"),
            (0x0422_A020, "adr (G6)"),
            (0x0421_3840, "eor3 (G17)"),
            (0x042F_3420, "xar (G17)"),
            (0x2402_0020, "cmphs vector (G7)"),
            (0x2402_2020, "cmpeq wide (G7)"),
            (0x2420_0020, "cmphs immediate (G7)"),
            (0x2510_8020, "cmpeq signed immediate (G7)"),
            (0x2520_C000, "add wide-immediate (G10)"),
            (0x2530_C000, "mul wide-immediate (G10)"),
            (0x2538_C000, "dup immediate (G8)"),
            (0x0520_3800, "dup scalar (G8)"),
            (0x0521_2000, "dup indexed (G8)"),
            (0x0528_A000, "cpy scalar (G8)"),
            (0x0520_8000, "cpy simd (G8)"),
            (0x0510_0000, "cpy immediate (G8)"),
            (0x0502_0000, "orr bitwise-immediate (G9)"),
            (0x05C0_0000, "dupm (G9)"),
            (0x4402_8020, "srshl saturating-predicated (G11)"),
            (0x4482_4020, "smlalb (G12)"),
            (0x4482_1020, "cdot (G13)"),
            (0x4500_D820, "cadd (G13)"),
            (0x4482_0020, "sdot (G18)"),
            (0x4402_C020, "sclamp (G19)"),
            (0x4408_A020, "sqabs (G20)"),
            (0x44C2_D020, "mlapt (G21)"),
            (0x44A2_0020, "sdot indexed"),
            (0x4542_0020, "saddlb (G16)"),
            (0x4502_6820, "pmullb .q (G16)"),
            (0x4502_9020, "eorbt (G16)"),
            (0x4522_8020, "match (G16)"),
            (0x45A2_C020, "histcnt (G16)"),
            (0x4508_E020, "ssra (G15)"),
            (0x4508_F420, "sli (G15)"),
            (0x4508_A020, "sshllb (G15)"),
            (0x4528_4020, "sqxtnb (G14)"),
            (0x4528_1020, "shrnb (G14)"),
            (0x4562_6020, "addhnb (G14)"),
            (0x4531_4040, "sqcvtn multi-vector (G14)"),
            (0x45A8_0040, "sqshrn multi-vector (G14)"),
        ]
        for (encoding, label) in owned {
            // In scope and claimed: the word decodes to a real scalable
            // instruction rather than falling through to the tier's UNDEFINED.
            let d = Iris.decode(encoding, features: .scalable)
            #expect(d.category == .sve, "\(label) must be scalable")
            #expect(d.mnemonic != .undefined, "\(label) must be claimed")
        }
    }

    @Test func neighbouringGroupsThatShareTheEncodingSpaceAreDisclaimed() {
        // Each of these sits inside one of 2s.3's six top bytes but belongs to
        // another sibling decoder. A too-wide predicate would pull it here and force a
        // wrong UNDEFINED (or worse, a mis-decode); the scope gate keeps it out.
        let foreign: [(UInt32, String)] = [
            (0x2510_4020, "brka — predicate partition (2s.2)"),
            (0x2518_E000, "ptrue — predicate initialise (2s.2)"),
            (0x2520_7010, "pext — predicate-as-counter (2s.7)"),
            (0x0420_E3E0, "cntb — element count (2s.2)"),
            (0x0460_E101, "cnth — element count (2s.2)"),
            (0x0421_50A2, "addvl — stack adjust (2s.2)"),
            (0x0423_4020, "index — series generate (2s.2)"),
            (0x04A4_4020, "index .s — series generate (2s.2)"),
            (0x0420_BC20, "movprfx unpredicated (2s.2)"),
            (0x0450_2C20, "movprfx predicated (2s.2)"),
            (0x045C_A820, "fabs — FP unary (2s.4)"),
            (0x045D_A820, "fneg — FP unary (2s.4)"),
            (0x0460_B000, "ftssel/fexpa region (2s.4)"),
            (0x2579_C000, "fdup/fmov immediate region (2s.4)"),
            (0x0570_C000, "fcpy immediate region (2s.4)"),
            (0x6500_0000, "bfadd — FP top byte (2s.4)"),
            (0x0522_6000, "zip1 — permute (2s.5)"),
            (0x0522_3020, "tbl — permute (2s.5)"),
            (0x4402_E020, "zipq1 — quadword permute (2s.5)"),
            (0x4402_E820, "uzpq1 — quadword permute (2s.5)"),
            (0x4522_E400, "aesd — SVE2 crypto (2s.5)"),
            (0xA400_4000, "ld1b — memory (2s.5)"),
            (0x8400_4000, "ld1b gather — memory (2s.5)"),
            (0xE400_4000, "st1b — memory (2s.5)"),
        ]
        for (encoding, label) in foreign {
            // Out of scope, and the sibling that owns it decodes it: a
            // too-wide integer predicate would have claimed the word and
            // forced it to UNDEFINED. The sibling's exact mnemonic is pinned
            // by that group's own decode suite.
            #expect(Iris.decode(encoding, features: .scalable).mnemonic != .undefined,
                    "\(label) must decode in its own group")
        }
    }

    @Test func theArchitecturalHolesStayInScopeAndDecodeToUndefined() {
        // A hole inside an owned group is this decoder's to reject — it must not
        // be pushed out of scope, or nothing would ever validate it.
        let holes: [(UInt32, String)] = [
            (0x0402_0443, "reserved predicated-arith opcode"),
            (0x0414_0443, "sdiv at a byte element"),
            (0x0404_0443, "addpt at a byte element"),
            (0x0410_A020, "sxtb at a byte element"),
            (0x045F_A820, "reserved predicated-unary opcode"),
            (0x04C0_2443, "saddv at a doubleword element"),
            (0x0404_2443, "reserved quadword-reduction opcode"),
            (0x0400_8000, "predicated shift with a zero tsz"),
            (0x04D8_8020, "wide shift at a doubleword element"),
            (0x0422_0820, "addpt unpredicated at a byte element"),
            (0x04A1_3840, "reserved ternary opcode"),
            (0x0420_3420, "xar with a zero tsz"),
            (0x24C2_2020, "wide compare at a doubleword element"),
            (0x2510_A020, "reserved signed-immediate-compare opcode"),
            (0x2530_8000, "wide-immediate b14 reserved hole"),
            (0x2528_E000, "smax immediate with the shift bit"),
            (0x2538_E000, "dup immediate byte with lsl #8"),
            (0x0510_2000, "cpy immediate byte with lsl #8"),
            (0x0520_2000, "dup indexed with a zero tsz"),
            (0x0500_07E0, "reserved bitmask immediate"),
            (0x4400_8020, "reserved saturating-predicated opcode"),
            (0x4402_0820, "sqdmlalbt at a byte element"),
            (0x4442_1020, "cdot at a halfword element"),
            (0x4402_7820, "usdot at a byte element"),
            (0x4402_D020, "mlapt at a byte element"),
            (0x4402_7C20, "reserved 0x44 sub-dispatch slot"),
            (0x4582_6820, "pmullb at the reserved sz=10"),
            (0x4502_0020, "widening arith at a byte destination"),
            (0x4542_2020, "reserved widening-arith opcode"),
            (0x4542_9820, "matmul at the reserved sz=01"),
            (0x4500_E020, "accumulate shift with a zero tsz"),
            (0x4528_5820, "reserved saturating-extract opcode"),
            (0x4520_4020, "saturating extract with a zero tsz"),
            (0x4522_6020, "narrow-high at a byte source"),
            (0x4531_5840, "reserved multi-vector-extract opcode"),
            (0x45A8_1840, "reserved multi-vector-shift opcode"),
            (0x4422_1820, "usdot indexed at a halfword destination"),
            (0x44A2_5020, "reserved indexed-complex opcode"),
            (0x44A2_FC20, "reserved indexed-multiply opcode"),
            (0x4422_C020, "smullb indexed at a halfword destination"),
        ]
        for (encoding, label) in holes {
            let draft = Iris.decode(encoding, at: 0, features: .scalable)
            #expect(draft.mnemonic == .undefined, "\(label) must decode to UNDEFINED")
            #expect(draft.category == .sve, "\(label) must stay categorized as SVE")
            #expect(draft.operands.isEmpty, "\(label) must carry no operands")
        }
    }
}

/// Validates that every word in the six top bytes 2s.3 shares with its
/// siblings decodes to a well-formed scalable record. The sweep exhausts every
/// dispatch-relevant bit combination in all six top bytes with two register/
/// payload patterns, so a routing decision that wrongly depended on payload
/// bits could not hide: a word that escaped its owner would surface here as a
/// mis-categorized record, a lost raw encoding, or text the renderer could not
/// form.
@Suite("SVE integer / every word in the shared top bytes is well formed")
struct SVEIntegerScopeAgreementTests {
    /// Bits 23...9 select every dispatch path in all six regions; the payload
    /// bits below are register/immediate fields. Both payload patterns are
    /// swept so a routing decision reading them would be caught.
    private static let payloads: [UInt32] = [0x000, 0x1FF]
    private static let topBytes: [UInt32] = [0x04, 0x05, 0x24, 0x25, 0x44, 0x45]

    private static func sweep(topByte: UInt32, _ body: (UInt32) -> Void) {
        for dispatch in UInt32(0) ..< (1 << 15) {
            for payload in payloads {
                body((topByte << 24) | (dispatch << 9) | payload)
            }
        }
    }

    @Test func everyWordCarriesTheScalableCategoryAndItsRawEncoding() {
        // The whole of op0=2 belongs to the scalable tier, so every swept word
        // — claimed by 2s.3 or by one of the siblings sharing these top bytes,
        // or a reserved hole none of them claims — comes back categorized as
        // SVE with its raw word and address intact and no base-ISA attribute
        // invented.
        for topByte in Self.topBytes {
            Self.sweep(topByte: topByte) { encoding in
                let draft = Iris.decode(encoding, at: 0x4000, features: .scalable)
                #expect(draft.category == .sve)
                #expect(draft.encoding == encoding)
                #expect(draft.address == 0x4000)
                #expect(draft.branchClass == .none)
                #expect(draft.memoryAccess == .none)
                #expect(draft.memoryOrdering == [])
            }
        }
    }

    @Test func everyWordRendersTextExactlyWhenItDecodes() {
        // A decoded record must render nonempty single-line text with no `?`
        // placeholder; a hole renders the `.long` data directive that every
        // UNDEFINED record shares.
        for topByte in Self.topBytes {
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
