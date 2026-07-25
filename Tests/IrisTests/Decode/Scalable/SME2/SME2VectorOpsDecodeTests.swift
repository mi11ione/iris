// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ e: UInt32) -> Instruction {
    Iris.decode(e, at: 0, features: .scalable)
}

private func text(_ e: UInt32) -> String {
    decode(e).text
}

/// Assert a representative encoding decodes to its mnemonic, is semantically
/// consistent, and renders nonempty placeholder-free text.
private func expectFamily(_ e: UInt32, _ m: Mnemonic, _ label: String) {
    let d = decode(e)
    #expect(d.mnemonic == m, "\(label) 0x\(String(e, radix: 16))")
    #expect(d.category == .sme, "\(label)")
    let t = text(e)
    #expect(!t.isEmpty && !t.contains("?") && !t.contains("\n"), "\(label) -> \(t)")
}

/// Every `(mask, value)` row of `destructiveSpec`, paired with its mnemonic.
private let destructives: [(UInt32, Mnemonic)] = [
    (0xC120_B800, .smax),
    (0xC120_B801, .umax),
    (0xC120_B820, .smin),
    (0xC120_B821, .umin),
    (0xC120_B900, .bfmax),
    (0xC120_B901, .bfmin),
    (0xC120_B920, .bfmaxnm),
    (0xC120_B921, .bfminnm),
    (0xC120_B980, .bfscale),
    (0xC120_BA20, .srshl),
    (0xC120_BA21, .urshl),
    (0xC120_BC00, .sqdmulh),
    (0xC160_B800, .smax),
    (0xC160_B801, .umax),
    (0xC160_B820, .smin),
    (0xC160_B821, .umin),
    (0xC160_B900, .fmax),
    (0xC160_B901, .fmin),
    (0xC160_B920, .fmaxnm),
    (0xC160_B921, .fminnm),
    (0xC160_B940, .famax),
    (0xC160_B941, .famin),
    (0xC160_B980, .fscale),
    (0xC160_BA20, .srshl),
    (0xC160_BA21, .urshl),
    (0xC160_BC00, .sqdmulh),
    (0xC1A0_B800, .smax),
    (0xC1A0_B801, .umax),
    (0xC1A0_B820, .smin),
    (0xC1A0_B821, .umin),
    (0xC1A0_B900, .fmax),
    (0xC1A0_B901, .fmin),
    (0xC1A0_B920, .fmaxnm),
    (0xC1A0_B921, .fminnm),
    (0xC1A0_B940, .famax),
    (0xC1A0_B941, .famin),
    (0xC1A0_B980, .fscale),
    (0xC1A0_BA20, .srshl),
    (0xC1A0_BA21, .urshl),
    (0xC1A0_BC00, .sqdmulh),
    (0xC1E0_B800, .smax),
    (0xC1E0_B801, .umax),
    (0xC1E0_B820, .smin),
    (0xC1E0_B821, .umin),
    (0xC1E0_B900, .fmax),
    (0xC1E0_B901, .fmin),
    (0xC1E0_B920, .fmaxnm),
    (0xC1E0_B921, .fminnm),
    (0xC1E0_B940, .famax),
    (0xC1E0_B941, .famin),
    (0xC1E0_B980, .fscale),
    (0xC1E0_BA20, .srshl),
    (0xC1E0_BA21, .urshl),
    (0xC1E0_BC00, .sqdmulh),
    (0xC120_A800, .smax),
    (0xC120_A801, .umax),
    (0xC120_A820, .smin),
    (0xC120_A821, .umin),
    (0xC120_A900, .bfmax),
    (0xC120_A901, .bfmin),
    (0xC120_A920, .bfmaxnm),
    (0xC120_A921, .bfminnm),
    (0xC120_A980, .bfscale),
    (0xC120_AA20, .srshl),
    (0xC120_AA21, .urshl),
    (0xC120_AB00, .add),
    (0xC120_AC00, .sqdmulh),
    (0xC160_A800, .smax),
    (0xC160_A801, .umax),
    (0xC160_A820, .smin),
    (0xC160_A821, .umin),
    (0xC160_A900, .fmax),
    (0xC160_A901, .fmin),
    (0xC160_A920, .fmaxnm),
    (0xC160_A921, .fminnm),
    (0xC160_A980, .fscale),
    (0xC160_AA20, .srshl),
    (0xC160_AA21, .urshl),
    (0xC160_AB00, .add),
    (0xC160_AC00, .sqdmulh),
    (0xC1A0_A800, .smax),
    (0xC1A0_A801, .umax),
    (0xC1A0_A820, .smin),
    (0xC1A0_A821, .umin),
    (0xC1A0_A900, .fmax),
    (0xC1A0_A901, .fmin),
    (0xC1A0_A920, .fmaxnm),
    (0xC1A0_A921, .fminnm),
    (0xC1A0_A980, .fscale),
    (0xC1A0_AA20, .srshl),
    (0xC1A0_AA21, .urshl),
    (0xC1A0_AB00, .add),
    (0xC1A0_AC00, .sqdmulh),
    (0xC1E0_A800, .smax),
    (0xC1E0_A801, .umax),
    (0xC1E0_A820, .smin),
    (0xC1E0_A821, .umin),
    (0xC1E0_A900, .fmax),
    (0xC1E0_A901, .fmin),
    (0xC1E0_A920, .fmaxnm),
    (0xC1E0_A921, .fminnm),
    (0xC1E0_A980, .fscale),
    (0xC1E0_AA20, .srshl),
    (0xC1E0_AA21, .urshl),
    (0xC1E0_AB00, .add),
    (0xC1E0_AC00, .sqdmulh),
    (0xC120_B000, .smax),
    (0xC120_B001, .umax),
    (0xC120_B020, .smin),
    (0xC120_B021, .umin),
    (0xC120_B100, .bfmax),
    (0xC120_B101, .bfmin),
    (0xC120_B120, .bfmaxnm),
    (0xC120_B121, .bfminnm),
    (0xC120_B180, .bfscale),
    (0xC120_B220, .srshl),
    (0xC120_B221, .urshl),
    (0xC120_B400, .sqdmulh),
    (0xC160_B000, .smax),
    (0xC160_B001, .umax),
    (0xC160_B020, .smin),
    (0xC160_B021, .umin),
    (0xC160_B100, .fmax),
    (0xC160_B101, .fmin),
    (0xC160_B120, .fmaxnm),
    (0xC160_B121, .fminnm),
    (0xC160_B140, .famax),
    (0xC160_B141, .famin),
    (0xC160_B180, .fscale),
    (0xC160_B220, .srshl),
    (0xC160_B221, .urshl),
    (0xC160_B400, .sqdmulh),
    (0xC1A0_B000, .smax),
    (0xC1A0_B001, .umax),
    (0xC1A0_B020, .smin),
    (0xC1A0_B021, .umin),
    (0xC1A0_B100, .fmax),
    (0xC1A0_B101, .fmin),
    (0xC1A0_B120, .fmaxnm),
    (0xC1A0_B121, .fminnm),
    (0xC1A0_B140, .famax),
    (0xC1A0_B141, .famin),
    (0xC1A0_B180, .fscale),
    (0xC1A0_B220, .srshl),
    (0xC1A0_B221, .urshl),
    (0xC1A0_B400, .sqdmulh),
    (0xC1E0_B000, .smax),
    (0xC1E0_B001, .umax),
    (0xC1E0_B020, .smin),
    (0xC1E0_B021, .umin),
    (0xC1E0_B100, .fmax),
    (0xC1E0_B101, .fmin),
    (0xC1E0_B120, .fmaxnm),
    (0xC1E0_B121, .fminnm),
    (0xC1E0_B140, .famax),
    (0xC1E0_B141, .famin),
    (0xC1E0_B180, .fscale),
    (0xC1E0_B220, .srshl),
    (0xC1E0_B221, .urshl),
    (0xC1E0_B400, .sqdmulh),
    (0xC120_A000, .smax),
    (0xC120_A001, .umax),
    (0xC120_A020, .smin),
    (0xC120_A021, .umin),
    (0xC120_A100, .bfmax),
    (0xC120_A101, .bfmin),
    (0xC120_A120, .bfmaxnm),
    (0xC120_A121, .bfminnm),
    (0xC120_A180, .bfscale),
    (0xC120_A220, .srshl),
    (0xC120_A221, .urshl),
    (0xC120_A300, .add),
    (0xC120_A400, .sqdmulh),
    (0xC160_A000, .smax),
    (0xC160_A001, .umax),
    (0xC160_A020, .smin),
    (0xC160_A021, .umin),
    (0xC160_A100, .fmax),
    (0xC160_A101, .fmin),
    (0xC160_A120, .fmaxnm),
    (0xC160_A121, .fminnm),
    (0xC160_A180, .fscale),
    (0xC160_A220, .srshl),
    (0xC160_A221, .urshl),
    (0xC160_A300, .add),
    (0xC160_A400, .sqdmulh),
    (0xC1A0_A000, .smax),
    (0xC1A0_A001, .umax),
    (0xC1A0_A020, .smin),
    (0xC1A0_A021, .umin),
    (0xC1A0_A100, .fmax),
    (0xC1A0_A101, .fmin),
    (0xC1A0_A120, .fmaxnm),
    (0xC1A0_A121, .fminnm),
    (0xC1A0_A180, .fscale),
    (0xC1A0_A220, .srshl),
    (0xC1A0_A221, .urshl),
    (0xC1A0_A300, .add),
    (0xC1A0_A400, .sqdmulh),
    (0xC1E0_A000, .smax),
    (0xC1E0_A001, .umax),
    (0xC1E0_A020, .smin),
    (0xC1E0_A021, .umin),
    (0xC1E0_A100, .fmax),
    (0xC1E0_A101, .fmin),
    (0xC1E0_A120, .fmaxnm),
    (0xC1E0_A121, .fminnm),
    (0xC1E0_A180, .fscale),
    (0xC1E0_A220, .srshl),
    (0xC1E0_A221, .urshl),
    (0xC1E0_A300, .add),
    (0xC1E0_A400, .sqdmulh),
]

/// Every `(mask, value)` row of `convertSpec`, paired with its mnemonic.
private let converts: [(UInt32, Mnemonic)] = [
    (0xC131_E000, .fcvtzs),
    (0xC131_E020, .fcvtzu),
    (0xC132_E000, .scvtf),
    (0xC132_E020, .ucvtf),
    (0xC1B8_E000, .frintn),
    (0xC1B9_E000, .frintp),
    (0xC1BA_E000, .frintm),
    (0xC1BC_E000, .frinta),
    (0xC121_E000, .fcvtzs),
    (0xC121_E020, .fcvtzu),
    (0xC122_E000, .scvtf),
    (0xC122_E020, .ucvtf),
    (0xC1A8_E000, .frintn),
    (0xC1A9_E000, .frintp),
    (0xC1AA_E000, .frintm),
    (0xC1AC_E000, .frinta),
    (0xC133_E000, .sqcvt),
    (0xC133_E020, .uqcvt),
    (0xC133_E040, .sqcvtn),
    (0xC133_E060, .uqcvtn),
    (0xC134_E000, .fcvt),
    (0xC134_E020, .fcvtn),
    (0xC173_E000, .sqcvtu),
    (0xC173_E040, .sqcvtun),
    (0xC1B3_E000, .sqcvt),
    (0xC1B3_E020, .uqcvt),
    (0xC1B3_E040, .sqcvtn),
    (0xC1B3_E060, .uqcvtn),
    (0xC1F3_E000, .sqcvtu),
    (0xC1F3_E040, .sqcvtun),
    (0xC121_E400, .bfmul),
    (0xC161_E400, .fmul),
    (0xC1A1_E400, .fmul),
    (0xC1E1_E400, .fmul),
    (0xC126_E000, .f1cvt),
    (0xC126_E001, .f1cvtl),
    (0xC166_E000, .bf1cvt),
    (0xC166_E001, .bf1cvtl),
    (0xC1A0_E000, .fcvt),
    (0xC1A0_E001, .fcvtl),
    (0xC1A6_E000, .f2cvt),
    (0xC1A6_E001, .f2cvtl),
    (0xC1E6_E000, .bf2cvt),
    (0xC1E6_E001, .bf2cvtl),
    (0xC120_E000, .fcvt),
    (0xC120_E020, .fcvtn),
    (0xC123_E000, .sqcvt),
    (0xC123_E020, .uqcvt),
    (0xC124_E000, .fcvt),
    (0xC160_E000, .bfcvt),
    (0xC160_E020, .bfcvtn),
    (0xC163_E000, .sqcvtu),
    (0xC164_E000, .bfcvt),
    (0xC121_E800, .bfmul),
    (0xC161_E800, .fmul),
    (0xC1A1_E800, .fmul),
    (0xC1E1_E800, .fmul),
    (0xC120_E400, .bfmul),
    (0xC120_E800, .bfmul),
    (0xC160_E400, .fmul),
    (0xC160_E800, .fmul),
    (0xC1A0_E400, .fmul),
    (0xC1A0_E800, .fmul),
    (0xC1E0_E400, .fmul),
    (0xC1E0_E800, .fmul),
]

/// Validates the SME2 non-ZA multi-vector families (the `{Zd}`-targeting side of
/// the `0xC1` cell): SEL, the destructive elementwise ops, the clamp family, the
/// 2-way/4-way saturating narrowing shifts, the ZIP/UZP/SUNPK/UUNPK permutes,
/// the convert/FMUL/FRINT group, and the `0xC1` LUTI6 no-ZT0 form. The two big
/// generated tables (destructive, convert) are driven row-for-row; the other
/// families are asserted by representative.
@Suite("SME2 / vector-ops decode")
struct SME2VectorOpsDecodeTests {
    @Test func everyDestructiveRowResolvesAndIsConsistent() {
        for (e, m) in destructives {
            let d = decode(e)
            #expect(d.mnemonic == m, "0x\(String(e, radix: 16))")
            let t = text(e)
            #expect(!t.isEmpty && !t.contains("?"), "0x\(String(e, radix: 16)) -> \(t)")
        }
    }

    @Test func everyConvertRowResolvesAndIsConsistent() {
        for (e, m) in converts {
            let d = decode(e)
            #expect(d.mnemonic == m, "0x\(String(e, radix: 16))")
            let t = text(e)
            #expect(!t.isEmpty && !t.contains("?"), "0x\(String(e, radix: 16)) -> \(t)")
        }
    }

    @Test func theDestructiveDestinationIsTiedToItsFirstSource() {
        // `{Zdn}, {Zdn}, Zm` (zzv single broadcast) and `{Zdn}, {Zdn}, {Zm}`
        // (zzw multi) — the destination register re-appears as source one.
        #expect(text(0xC120_A300) == "add { z0.b, z1.b }, { z0.b, z1.b }, z0.b")
        #expect(text(0xC120_B800) == "smax { z0.b - z3.b }, { z0.b - z3.b }, { z0.b - z3.b }")
    }

    @Test func selDecodesItsPredicateGovernedSelect() {
        expectFamily(0xC120_8000, .sel, "sel 2-way")
        expectFamily(0xC121_8000, .sel, "sel 4-way")
        #expect(text(0xC120_8000) == "sel { z0.b, z1.b }, pn8, { z0.b, z1.b }, { z0.b, z1.b }")
    }

    @Test func theClampFamilyDecodesEveryVariantAndWidth() {
        expectFamily(0xC120_C400, .sclamp, "sclamp 2x")
        expectFamily(0xC120_C401, .uclamp, "uclamp 2x")
        expectFamily(0xC160_C000, .fclamp, "fclamp 2x .h")
        expectFamily(0xC120_C000, .bfclamp, "bfclamp 2x size0")
        expectFamily(0xC120_CC00, .sclamp, "sclamp 4x")
        expectFamily(0xC120_CC01, .uclamp, "uclamp 4x")
        expectFamily(0xC160_C800, .fclamp, "fclamp 4x .h")
        expectFamily(0xC120_C800, .bfclamp, "bfclamp 4x size0")
        #expect(text(0xC120_C400) == "sclamp { z0.b, z1.b }, z0.b, z0.b")
    }

    @Test func theSaturatingNarrowShiftsDecodeBothWidths() {
        // 4-way (tsize:imm5 shift field) and 2-way (imm4 shift field). tsize=01
        // gives `.b<-.s` (shift 64-field), tsize>=10 gives `.h<-.d` (shift
        // 128-field); op:U picks the signed/unsigned/signed-to-unsigned variant
        // and its narrowing twin.
        expectFamily(0xC160_D800, .sqrshr, "sqrshr 4x .b<-.s")
        expectFamily(0xC160_DC00, .sqrshrn, "sqrshrn 4x")
        expectFamily(0xC160_D820, .uqrshr, "uqrshr 4x")
        expectFamily(0xC160_DC20, .uqrshrn, "uqrshrn 4x")
        expectFamily(0xC160_D840, .sqrshru, "sqrshru 4x")
        expectFamily(0xC160_DC40, .sqrshrun, "sqrshrun 4x")
        expectFamily(0xC1A0_D800, .sqrshr, "sqrshr 4x .h<-.d (tsize>=2)")
        expectFamily(0xC1E0_D400, .sqrshr, "sqrshr 2x .h<-.s")
        expectFamily(0xC1E0_D420, .uqrshr, "uqrshr 2x")
        expectFamily(0xC1F0_D400, .sqrshru, "sqrshru 2x")
    }

    @Test func theNarrowShiftReservedFormsAreClaimedHoles() {
        // 4-way tsize=00 is reserved; the op=1,U=1 opcode is unallocated.
        for e: UInt32 in [0xC120_D800, 0xC160_DC60] {
            #expect(decode(e).mnemonic == .undefined, "0x\(String(e, radix: 16))")
            #expect(text(e) == ".long 0x\(String(e, radix: 16))", "0x\(String(e, radix: 16))")
        }
    }

    @Test func thePermuteFamilyDecodesZipUzpUnpackAtBothWidths() {
        expectFamily(0xC120_D000, .zip, "zip 2x")
        expectFamily(0xC120_D001, .uzp, "uzp 2x")
        expectFamily(0xC120_D400, .zip, "zip 2x .q")
        expectFamily(0xC136_E000, .zip, "zip 4x .b")
        expectFamily(0xC137_E000, .zip, "zip 4x .q (bit16, size00)")
        expectFamily(0xC1B6_E000, .zip, "zip 4x .s")
        expectFamily(0xC136_E002, .uzp, "uzp 4x")
        expectFamily(0xC165_E000, .sunpk, "sunpk 2x .h<-.b")
        expectFamily(0xC1A5_E000, .sunpk, "sunpk 2x .s<-.h")
        expectFamily(0xC1E5_E000, .sunpk, "sunpk 2x .d<-.s")
        expectFamily(0xC165_E001, .uunpk, "uunpk 2x")
        expectFamily(0xC175_E000, .sunpk, "sunpk 4x .h<-.b")
        expectFamily(0xC1F5_E000, .sunpk, "sunpk 4x .d<-.s")
        expectFamily(0xC175_E001, .uunpk, "uunpk 4x")
        #expect(text(0xC120_D000) == "zip { z0.b, z1.b }, z0.b, z0.b")
    }

    @Test func theConvertShapesRenderNarrowWidenSameAndFmul() {
        // narrow (`Zd, {Zn}`), widen (`{Zd}, Zn`), same (`{Zd}, {Zn}`) and the
        // FMUL broadcast/multi second source.
        #expect(text(0xC120_E000) == "fcvt z0.h, { z0.s, z1.s }")
        #expect(text(0xC126_E000) == "f1cvt { z0.h, z1.h }, z0.b")
        #expect(text(0xC121_E000) == "fcvtzs { z0.s, z1.s }, { z0.s, z1.s }")
        #expect(text(0xC160_E800) == "fmul { z0.h, z1.h }, { z0.h, z1.h }, z0.h")
        #expect(text(0xC161_E400) == "fmul { z0.h - z3.h }, { z0.h - z3.h }, { z0.h - z3.h }")
    }

    @Test func theLuti6NoZT0FormDecodesItsTablePairAndIndexedSource() {
        expectFamily(0xC120_F400, .luti6, "luti6 consecutive")
        expectFamily(0xC120_FC00, .luti6, "luti6 strided")
        #expect(text(0xC120_F400) == "luti6 { z0.h - z3.h }, { z0.h, z1.h }, { z0, z1 }[0]")
    }

    @Test func anUnallocatedWordInEachVectorOpsGroupIsAClaimedHole() {
        // 101 destructive, 110 clamp/narrow/permute and 111 convert each reject
        // a word matching none of their tables.
        for e: UInt32 in [0xC100_A00C, 0xC100_C00C, 0xC100_E00C] {
            let d = decode(e)
            #expect(d.mnemonic == .undefined, "0x\(String(e, radix: 16))")
            #expect(text(e) == ".long 0x\(String(e, radix: 16))", "0x\(String(e, radix: 16))")
        }
    }
}
