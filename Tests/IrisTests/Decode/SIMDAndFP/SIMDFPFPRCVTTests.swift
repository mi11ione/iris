// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisValidation
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

/// Validates the scalar floating-point / integer conversion group exhaustively
/// over (sf, ftype, rmode, opcode), including the FEAT_FPRCVT rows whose two
/// operands are both SIMD&FP scalars of differing size.
@Suite("SIMD/FP / scalar FP-integer conversion and FEAT_FPRCVT")
struct SIMDFPFPRCVTTests {
    static let allocatedForms: [(word: UInt32, text: String)] = [
        (0x1E20_0058, "fcvtns w24, s2"),
        (0x1E21_0058, "fcvtnu w24, s2"),
        (0x1E22_0058, "scvtf s24, w2"),
        (0x1E23_0058, "ucvtf s24, w2"),
        (0x1E24_0058, "fcvtas w24, s2"),
        (0x1E25_0058, "fcvtau w24, s2"),
        (0x1E26_0058, "fmov w24, s2"),
        (0x1E27_0058, "fmov s24, w2"),
        (0x1E28_0058, "fcvtps w24, s2"),
        (0x1E29_0058, "fcvtpu w24, s2"),
        (0x1E30_0058, "fcvtms w24, s2"),
        (0x1E31_0058, "fcvtmu w24, s2"),
        (0x1E38_0058, "fcvtzs w24, s2"),
        (0x1E39_0058, "fcvtzu w24, s2"),
        (0x1E60_0058, "fcvtns w24, d2"),
        (0x1E61_0058, "fcvtnu w24, d2"),
        (0x1E62_0058, "scvtf d24, w2"),
        (0x1E63_0058, "ucvtf d24, w2"),
        (0x1E64_0058, "fcvtas w24, d2"),
        (0x1E65_0058, "fcvtau w24, d2"),
        (0x1E68_0058, "fcvtps w24, d2"),
        (0x1E69_0058, "fcvtpu w24, d2"),
        (0x1E6A_0058, "fcvtns s24, d2"),
        (0x1E6B_0058, "fcvtnu s24, d2"),
        (0x1E70_0058, "fcvtms w24, d2"),
        (0x1E71_0058, "fcvtmu w24, d2"),
        (0x1E72_0058, "fcvtps s24, d2"),
        (0x1E73_0058, "fcvtpu s24, d2"),
        (0x1E74_0058, "fcvtms s24, d2"),
        (0x1E75_0058, "fcvtmu s24, d2"),
        (0x1E76_0058, "fcvtzs s24, d2"),
        (0x1E77_0058, "fcvtzu s24, d2"),
        (0x1E78_0058, "fcvtzs w24, d2"),
        (0x1E79_0058, "fcvtzu w24, d2"),
        (0x1E7A_0058, "fcvtas s24, d2"),
        (0x1E7B_0058, "fcvtau s24, d2"),
        (0x1E7C_0058, "scvtf d24, s2"),
        (0x1E7D_0058, "ucvtf d24, s2"),
        (0x1E7E_0058, "fjcvtzs w24, d2"),
        (0x1EE0_0058, "fcvtns w24, h2"),
        (0x1EE1_0058, "fcvtnu w24, h2"),
        (0x1EE2_0058, "scvtf h24, w2"),
        (0x1EE3_0058, "ucvtf h24, w2"),
        (0x1EE4_0058, "fcvtas w24, h2"),
        (0x1EE5_0058, "fcvtau w24, h2"),
        (0x1EE6_0058, "fmov w24, h2"),
        (0x1EE7_0058, "fmov h24, w2"),
        (0x1EE8_0058, "fcvtps w24, h2"),
        (0x1EE9_0058, "fcvtpu w24, h2"),
        (0x1EEA_0058, "fcvtns s24, h2"),
        (0x1EEB_0058, "fcvtnu s24, h2"),
        (0x1EF0_0058, "fcvtms w24, h2"),
        (0x1EF1_0058, "fcvtmu w24, h2"),
        (0x1EF2_0058, "fcvtps s24, h2"),
        (0x1EF3_0058, "fcvtpu s24, h2"),
        (0x1EF4_0058, "fcvtms s24, h2"),
        (0x1EF5_0058, "fcvtmu s24, h2"),
        (0x1EF6_0058, "fcvtzs s24, h2"),
        (0x1EF7_0058, "fcvtzu s24, h2"),
        (0x1EF8_0058, "fcvtzs w24, h2"),
        (0x1EF9_0058, "fcvtzu w24, h2"),
        (0x1EFA_0058, "fcvtas s24, h2"),
        (0x1EFB_0058, "fcvtau s24, h2"),
        (0x1EFC_0058, "scvtf h24, s2"),
        (0x1EFD_0058, "ucvtf h24, s2"),
        (0x9E20_0058, "fcvtns x24, s2"),
        (0x9E21_0058, "fcvtnu x24, s2"),
        (0x9E22_0058, "scvtf s24, x2"),
        (0x9E23_0058, "ucvtf s24, x2"),
        (0x9E24_0058, "fcvtas x24, s2"),
        (0x9E25_0058, "fcvtau x24, s2"),
        (0x9E28_0058, "fcvtps x24, s2"),
        (0x9E29_0058, "fcvtpu x24, s2"),
        (0x9E2A_0058, "fcvtns d24, s2"),
        (0x9E2B_0058, "fcvtnu d24, s2"),
        (0x9E30_0058, "fcvtms x24, s2"),
        (0x9E31_0058, "fcvtmu x24, s2"),
        (0x9E32_0058, "fcvtps d24, s2"),
        (0x9E33_0058, "fcvtpu d24, s2"),
        (0x9E34_0058, "fcvtms d24, s2"),
        (0x9E35_0058, "fcvtmu d24, s2"),
        (0x9E36_0058, "fcvtzs d24, s2"),
        (0x9E37_0058, "fcvtzu d24, s2"),
        (0x9E38_0058, "fcvtzs x24, s2"),
        (0x9E39_0058, "fcvtzu x24, s2"),
        (0x9E3A_0058, "fcvtas d24, s2"),
        (0x9E3B_0058, "fcvtau d24, s2"),
        (0x9E3C_0058, "scvtf s24, d2"),
        (0x9E3D_0058, "ucvtf s24, d2"),
        (0x9E60_0058, "fcvtns x24, d2"),
        (0x9E61_0058, "fcvtnu x24, d2"),
        (0x9E62_0058, "scvtf d24, x2"),
        (0x9E63_0058, "ucvtf d24, x2"),
        (0x9E64_0058, "fcvtas x24, d2"),
        (0x9E65_0058, "fcvtau x24, d2"),
        (0x9E66_0058, "fmov x24, d2"),
        (0x9E67_0058, "fmov d24, x2"),
        (0x9E68_0058, "fcvtps x24, d2"),
        (0x9E69_0058, "fcvtpu x24, d2"),
        (0x9E70_0058, "fcvtms x24, d2"),
        (0x9E71_0058, "fcvtmu x24, d2"),
        (0x9E78_0058, "fcvtzs x24, d2"),
        (0x9E79_0058, "fcvtzu x24, d2"),
        (0x9EAE_0058, "fmov x24, v2.d[1]"),
        (0x9EAF_0058, "fmov v24.d[1], x2"),
        (0x9EE0_0058, "fcvtns x24, h2"),
        (0x9EE1_0058, "fcvtnu x24, h2"),
        (0x9EE2_0058, "scvtf h24, x2"),
        (0x9EE3_0058, "ucvtf h24, x2"),
        (0x9EE4_0058, "fcvtas x24, h2"),
        (0x9EE5_0058, "fcvtau x24, h2"),
        (0x9EE6_0058, "fmov x24, h2"),
        (0x9EE7_0058, "fmov h24, x2"),
        (0x9EE8_0058, "fcvtps x24, h2"),
        (0x9EE9_0058, "fcvtpu x24, h2"),
        (0x9EEA_0058, "fcvtns d24, h2"),
        (0x9EEB_0058, "fcvtnu d24, h2"),
        (0x9EF0_0058, "fcvtms x24, h2"),
        (0x9EF1_0058, "fcvtmu x24, h2"),
        (0x9EF2_0058, "fcvtps d24, h2"),
        (0x9EF3_0058, "fcvtpu d24, h2"),
        (0x9EF4_0058, "fcvtms d24, h2"),
        (0x9EF5_0058, "fcvtmu d24, h2"),
        (0x9EF6_0058, "fcvtzs d24, h2"),
        (0x9EF7_0058, "fcvtzu d24, h2"),
        (0x9EF8_0058, "fcvtzs x24, h2"),
        (0x9EF9_0058, "fcvtzu x24, h2"),
        (0x9EFA_0058, "fcvtas d24, h2"),
        (0x9EFB_0058, "fcvtau d24, h2"),
        (0x9EFC_0058, "scvtf h24, d2"),
        (0x9EFD_0058, "ucvtf h24, d2"),
    ]

    @Test func everyAllocatedFormDecodesToItsHarvestedText() {
        for row in Self.allocatedForms {
            let d = decode(row.word)
            #expect(d.text == row.text, "0x\(String(row.word, radix: 16))")
            #expect(d.category == .simdAndFP)
            #expect(d.operands.count == 2)
            #expect(d.memoryAccess == .none)
            #expect(d.flagEffect == .none)
        }
        #expect(Self.allocatedForms.count == 131)
    }

    @Test func everyUnallocatedTupleInTheGroupIsUndefined() {
        var allocated: Set<UInt32> = []
        for row in Self.allocatedForms {
            allocated.insert(row.word)
        }
        var undefinedSeen = 0
        for sf: UInt32 in 0 ... 1 {
            for ftype: UInt32 in 0 ... 3 {
                for rmode: UInt32 in 0 ... 3 {
                    for opcode: UInt32 in 0 ... 7 {
                        let word: UInt32 = (sf << 31) | 0x1E20_0000 | (ftype << 22)
                            | (rmode << 19) | (opcode << 16) | (2 << 5) | 24
                        if allocated.contains(word) { continue }
                        #expect(decode(word).isUndefined, "0x\(String(word, radix: 16))")
                        undefinedSeen += 1
                    }
                }
            }
        }
        #expect(undefinedSeen == 256 - Self.allocatedForms.count)
    }

    @Test func equalWidthConversionRowsAreUndefined() {
        for word: UInt32 in [0x1E2A_0058, 0x9E6A_0058, 0x1E3C_0058, 0x9E7C_0058] {
            #expect(decode(word).isUndefined, "0x\(String(word, radix: 16))")
        }
    }

    @Test func reservedFtypeRejectsTheConversionRows() {
        for word: UInt32 in [0x1EAA_0058, 0x9EAA_0058, 0x1EBC_0058] {
            #expect(decode(word).isUndefined, "0x\(String(word, radix: 16))")
        }
    }

    @Test func fprcvtRowsReadAndWriteSIMDRegistersOnly() {
        let d = decode(0x1E6A_0058)
        #expect(d.semanticReads.contains(.simd(2)))
        #expect(d.semanticWrites.contains(.simd(24)))
        #expect(SIMDFPSemanticChecker.verify(d) == nil)
        let up = decode(0x9E3C_0058)
        #expect(up.text == "scvtf s24, d2")
        #expect(up.semanticReads.contains(.simd(2)))
        #expect(up.semanticWrites.contains(.simd(24)))
    }

    @Test func everyAllocatedFormPassesTheSemanticChecker() {
        for row in Self.allocatedForms {
            #expect(SIMDFPSemanticChecker.verify(decode(row.word)) == nil,
                    "0x\(String(row.word, radix: 16))")
        }
    }
}
