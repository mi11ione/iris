// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisValidation
import Testing

private func decode(_ e: UInt32) -> Instruction {
    Iris.decode(e, at: 0)
}

private func text(_ e: UInt32) -> String {
    decode(e).text
}

private let accumulates: [(UInt32, Mnemonic)] = [
    (0xC1A1_1C00, .fadd),
    (0xC1A1_1C08, .fsub),
    (0xC1A1_1C10, .add),
    (0xC1A1_1C18, .sub),
    (0xC1A5_1C00, .fadd),
    (0xC1A5_1C08, .fsub),
    (0xC1E1_1C00, .fadd),
    (0xC1E1_1C08, .fsub),
    (0xC1E1_1C10, .add),
    (0xC1E1_1C18, .sub),
    (0xC1E5_1C00, .bfadd),
    (0xC1E5_1C08, .bfsub),
    (0xC1A1_0000, .smlall),
    (0xC1A1_0004, .usmlall),
    (0xC1A1_0008, .smlsll),
    (0xC1A1_0010, .umlall),
    (0xC1A1_0018, .umlsll),
    (0xC1A1_0020, .fmlall),
    (0xC1E1_0000, .smlall),
    (0xC1E1_0008, .smlsll),
    (0xC1E1_0010, .umlall),
    (0xC1E1_0018, .umlsll),
    (0xC1A0_1C00, .fadd),
    (0xC1A0_1C08, .fsub),
    (0xC1A0_1C10, .add),
    (0xC1A0_1C18, .sub),
    (0xC1A4_1C00, .fadd),
    (0xC1A4_1C08, .fsub),
    (0xC1E0_1C00, .fadd),
    (0xC1E0_1C08, .fsub),
    (0xC1E0_1C10, .add),
    (0xC1E0_1C18, .sub),
    (0xC1E4_1C00, .bfadd),
    (0xC1E4_1C08, .bfsub),
    (0xC1A1_0800, .fmlal),
    (0xC1A1_0808, .fmlsl),
    (0xC1A1_0810, .bfmlal),
    (0xC1A1_0818, .bfmlsl),
    (0xC1A1_0820, .fmlal),
    (0xC1E1_0800, .smlal),
    (0xC1E1_0808, .smlsl),
    (0xC1E1_0810, .umlal),
    (0xC1E1_0818, .umlsl),
    (0xC1A0_0000, .smlall),
    (0xC1A0_0004, .usmlall),
    (0xC1A0_0008, .smlsll),
    (0xC1A0_0010, .umlall),
    (0xC1A0_0018, .umlsll),
    (0xC1A0_0020, .fmlall),
    (0xC1E0_0000, .smlall),
    (0xC1E0_0008, .smlsll),
    (0xC1E0_0010, .umlall),
    (0xC1E0_0018, .umlsll),
    (0xC1A1_1000, .fdot),
    (0xC1A1_1008, .fmla),
    (0xC1A1_1010, .bfdot),
    (0xC1A1_1018, .fmls),
    (0xC1A1_1020, .fdot),
    (0xC1A1_1030, .fdot),
    (0xC1A1_1400, .sdot),
    (0xC1A1_1408, .usdot),
    (0xC1A1_1410, .udot),
    (0xC1A1_1800, .fmla),
    (0xC1A1_1808, .fmls),
    (0xC1A1_1810, .add),
    (0xC1A1_1818, .sub),
    (0xC1E1_1008, .bfmla),
    (0xC1E1_1018, .bfmls),
    (0xC1E1_1400, .sdot),
    (0xC1E1_1408, .sdot),
    (0xC1E1_1410, .udot),
    (0xC1E1_1418, .udot),
    (0xC1E1_1800, .fmla),
    (0xC1E1_1808, .fmls),
    (0xC1E1_1810, .add),
    (0xC1E1_1818, .sub),
    (0xC1A0_0800, .fmlal),
    (0xC1A0_0808, .fmlsl),
    (0xC1A0_0810, .bfmlal),
    (0xC1A0_0818, .bfmlsl),
    (0xC1A0_0820, .fmlal),
    (0xC1E0_0800, .smlal),
    (0xC1E0_0808, .smlsl),
    (0xC1E0_0810, .umlal),
    (0xC1E0_0818, .umlsl),
    (0xC120_0000, .smlall),
    (0xC120_0002, .fmlall),
    (0xC120_0004, .usmlall),
    (0xC120_0008, .smlsll),
    (0xC120_0010, .umlall),
    (0xC120_0014, .sumlall),
    (0xC120_0018, .umlsll),
    (0xC130_0000, .smlall),
    (0xC130_0002, .fmlall),
    (0xC130_0004, .usmlall),
    (0xC130_0008, .smlsll),
    (0xC130_0010, .umlall),
    (0xC130_0014, .sumlall),
    (0xC130_0018, .umlsll),
    (0xC160_0000, .smlall),
    (0xC160_0008, .smlsll),
    (0xC160_0010, .umlall),
    (0xC160_0018, .umlsll),
    (0xC170_0000, .smlall),
    (0xC170_0008, .smlsll),
    (0xC170_0010, .umlall),
    (0xC170_0018, .umlsll),
    (0xC1A0_1000, .fdot),
    (0xC1A0_1008, .fmla),
    (0xC1A0_1010, .bfdot),
    (0xC1A0_1018, .fmls),
    (0xC1A0_1020, .fdot),
    (0xC1A0_1030, .fdot),
    (0xC1A0_1400, .sdot),
    (0xC1A0_1408, .usdot),
    (0xC1A0_1410, .udot),
    (0xC1A0_1800, .fmla),
    (0xC1A0_1808, .fmls),
    (0xC1A0_1810, .add),
    (0xC1A0_1818, .sub),
    (0xC1E0_1008, .bfmla),
    (0xC1E0_1018, .bfmls),
    (0xC1E0_1400, .sdot),
    (0xC1E0_1408, .sdot),
    (0xC1E0_1410, .udot),
    (0xC1E0_1418, .udot),
    (0xC1E0_1800, .fmla),
    (0xC1E0_1808, .fmls),
    (0xC1E0_1810, .add),
    (0xC1E0_1818, .sub),
    (0xC190_8000, .smlall),
    (0xC190_8008, .smlsll),
    (0xC190_8010, .umlall),
    (0xC190_8018, .umlsll),
    (0xC1D0_8000, .fmla),
    (0xC1D0_8008, .sdot),
    (0xC1D0_8010, .fmls),
    (0xC1D0_8018, .udot),
    (0xC1D0_8808, .svdot),
    (0xC1D0_8818, .uvdot),
    (0xC120_0400, .smlall),
    (0xC120_0404, .usmlall),
    (0xC120_0408, .smlsll),
    (0xC120_0410, .umlall),
    (0xC120_0418, .umlsll),
    (0xC120_0800, .fmlal),
    (0xC120_0804, .fmlal),
    (0xC120_0808, .fmlsl),
    (0xC120_0810, .bfmlal),
    (0xC120_0818, .bfmlsl),
    (0xC130_0400, .fmlall),
    (0xC130_0800, .fmlal),
    (0xC130_0804, .fmlal),
    (0xC130_0808, .fmlsl),
    (0xC130_0810, .bfmlal),
    (0xC130_0818, .bfmlsl),
    (0xC160_0400, .smlall),
    (0xC160_0408, .smlsll),
    (0xC160_0410, .umlall),
    (0xC160_0418, .umlsll),
    (0xC160_0800, .smlal),
    (0xC160_0808, .smlsl),
    (0xC160_0810, .umlal),
    (0xC160_0818, .umlsl),
    (0xC170_0800, .smlal),
    (0xC170_0808, .smlsl),
    (0xC170_0810, .umlal),
    (0xC170_0818, .umlsl),
    (0xC110_8000, .smlall),
    (0xC110_8008, .smlsll),
    (0xC110_8010, .umlall),
    (0xC110_8018, .umlsll),
    (0xC110_8020, .usmlall),
    (0xC110_8030, .sumlall),
    (0xC110_8040, .fmlall),
    (0xC150_8000, .fmla),
    (0xC150_8008, .fdot),
    (0xC150_8010, .fmls),
    (0xC150_8020, .svdot),
    (0xC150_8028, .usvdot),
    (0xC150_8030, .uvdot),
    (0xC150_8038, .suvdot),
    (0xC150_9000, .sdot),
    (0xC150_9008, .fdot),
    (0xC150_9010, .udot),
    (0xC150_9018, .bfdot),
    (0xC150_9020, .sdot),
    (0xC150_9028, .usdot),
    (0xC150_9030, .udot),
    (0xC150_9038, .sudot),
    (0xC190_9000, .fmlal),
    (0xC190_9008, .fmlsl),
    (0xC190_9010, .bfmlal),
    (0xC190_9018, .bfmlsl),
    (0xC1D0_9000, .smlal),
    (0xC1D0_9008, .smlsl),
    (0xC1D0_9010, .umlal),
    (0xC1D0_9018, .umlsl),
    (0xC190_0000, .smlall),
    (0xC190_0008, .smlsll),
    (0xC190_0010, .umlall),
    (0xC190_0018, .umlsll),
    (0xC1D0_0000, .fmla),
    (0xC1D0_0008, .sdot),
    (0xC1D0_0010, .fmls),
    (0xC1D0_0018, .udot),
    (0xC120_0C00, .fmlal),
    (0xC120_0C08, .fmlsl),
    (0xC120_0C10, .bfmlal),
    (0xC120_0C18, .bfmlsl),
    (0xC120_1000, .fdot),
    (0xC120_1008, .fdot),
    (0xC120_1010, .bfdot),
    (0xC120_1018, .fdot),
    (0xC120_1400, .sdot),
    (0xC120_1408, .usdot),
    (0xC120_1410, .udot),
    (0xC120_1418, .sudot),
    (0xC120_1800, .fmla),
    (0xC120_1808, .fmls),
    (0xC120_1810, .add),
    (0xC120_1818, .sub),
    (0xC120_1C00, .fmla),
    (0xC120_1C08, .fmls),
    (0xC130_0C00, .fmlal),
    (0xC130_1000, .fdot),
    (0xC130_1008, .fdot),
    (0xC130_1010, .bfdot),
    (0xC130_1018, .fdot),
    (0xC130_1400, .sdot),
    (0xC130_1408, .usdot),
    (0xC130_1410, .udot),
    (0xC130_1418, .sudot),
    (0xC130_1800, .fmla),
    (0xC130_1808, .fmls),
    (0xC130_1810, .add),
    (0xC130_1818, .sub),
    (0xC130_1C00, .fmla),
    (0xC130_1C08, .fmls),
    (0xC160_0C00, .smlal),
    (0xC160_0C08, .smlsl),
    (0xC160_0C10, .umlal),
    (0xC160_0C18, .umlsl),
    (0xC160_1400, .sdot),
    (0xC160_1408, .sdot),
    (0xC160_1410, .udot),
    (0xC160_1418, .udot),
    (0xC160_1800, .fmla),
    (0xC160_1808, .fmls),
    (0xC160_1810, .add),
    (0xC160_1818, .sub),
    (0xC160_1C00, .bfmla),
    (0xC160_1C08, .bfmls),
    (0xC170_1400, .sdot),
    (0xC170_1408, .sdot),
    (0xC170_1410, .udot),
    (0xC170_1418, .udot),
    (0xC170_1800, .fmla),
    (0xC170_1808, .fmls),
    (0xC170_1810, .add),
    (0xC170_1818, .sub),
    (0xC170_1C00, .bfmla),
    (0xC170_1C08, .bfmls),
    (0xC110_0000, .smlall),
    (0xC110_0008, .smlsll),
    (0xC110_0010, .umlall),
    (0xC110_0018, .umlsll),
    (0xC110_0020, .usmlall),
    (0xC110_0030, .sumlall),
    (0xC150_0000, .fmla),
    (0xC150_0008, .fvdot),
    (0xC150_0010, .fmls),
    (0xC150_0018, .bfvdot),
    (0xC150_0020, .svdot),
    (0xC150_0030, .uvdot),
    (0xC150_0038, .fdot),
    (0xC150_1000, .sdot),
    (0xC150_1008, .fdot),
    (0xC150_1010, .udot),
    (0xC150_1018, .bfdot),
    (0xC150_1020, .sdot),
    (0xC150_1028, .usdot),
    (0xC150_1030, .udot),
    (0xC150_1038, .sudot),
    (0xC190_0020, .fmlall),
    (0xC190_1000, .fmlal),
    (0xC190_1008, .fmlsl),
    (0xC190_1010, .bfmlal),
    (0xC190_1018, .bfmlsl),
    (0xC1D0_1000, .smlal),
    (0xC1D0_1008, .smlsl),
    (0xC1D0_1010, .umlal),
    (0xC1D0_1018, .umlsl),
    (0xC110_9000, .fmla),
    (0xC110_9010, .fmls),
    (0xC110_9020, .bfmla),
    (0xC110_9030, .bfmls),
    (0xC110_9040, .fdot),
    (0xC190_9020, .fmlal),
    (0xC1D0_0800, .fvdotb),
    (0xC1D0_0810, .fvdott),
    (0xC180_0000, .smlall),
    (0xC180_0008, .smlsll),
    (0xC180_0010, .umlall),
    (0xC180_0018, .umlsll),
    (0xC110_1000, .fmla),
    (0xC110_1010, .fmls),
    (0xC110_1020, .bfmla),
    (0xC110_1030, .bfmls),
    (0xC190_1030, .fmlal),
    (0xC1D0_0020, .fdot),
    (0xC1D0_1020, .fvdot),
    (0xC100_0000, .smlall),
    (0xC100_0004, .usmlall),
    (0xC100_0008, .smlsll),
    (0xC100_0010, .umlall),
    (0xC100_0014, .sumlall),
    (0xC100_0018, .umlsll),
    (0xC140_0000, .fmlall),
    (0xC180_1000, .fmlal),
    (0xC180_1008, .fmlsl),
    (0xC180_1010, .bfmlal),
    (0xC180_1018, .bfmlsl),
    (0xC1C0_1000, .smlal),
    (0xC1C0_1008, .smlsl),
    (0xC1C0_1010, .umlal),
    (0xC1C0_1018, .umlsl),
    (0xC1C0_0000, .fmlal),
]

/// Validates the SME2 multi-vector ZA-accumulate decoder.
@Suite("SME2 / ZA-accumulate decode")
struct SME2ArithmeticDecodeTests {
    @Test func everyAccumulateRowResolvesToItsMnemonic() {
        for (e, m) in accumulates {
            #expect(decode(e).mnemonic == m, "0x\(String(e, radix: 16))")
            #expect(decode(e).category == .sme, "0x\(String(e, radix: 16))")
        }
    }

    @Test func everyAccumulateRowIsSemanticallyConsistentAndRendersCleanly() {
        for (e, _) in accumulates {
            let d = decode(e)
            #expect(SME2SemanticChecker.verify(draft: d) == nil, "0x\(String(e, radix: 16))")
            let t = text(e)
            #expect(!t.isEmpty, "0x\(String(e, radix: 16)) rendered nothing")
            #expect(!t.contains("?"), "0x\(String(e, radix: 16)) -> \(t)")
            #expect(!t.contains("\n"), "0x\(String(e, radix: 16))")
        }
    }

    @Test func everyAccumulateReadsAndWritesTheWholeZAArrayUnderStreaming() {
        for (e, _) in accumulates {
            let d = decode(e)
            #expect(!d.scalableReads.zaMask.isEmpty, "0x\(String(e, radix: 16))")
            #expect(!d.scalableWrites.zaMask.isEmpty, "0x\(String(e, radix: 16))")
            #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite], "0x\(String(e, radix: 16))")
            #expect(d.memoryAccess == .none, "0x\(String(e, radix: 16))")
            #expect(d.flagEffect == .none, "0x\(String(e, radix: 16))")
        }
    }

    @Test func theSourceShapesRenderTheirCanonicalOperandForms() {
        #expect(text(0xC1A0_1C10) == "add za.s[w8, 0, vgx2], { z0.s, z1.s }")
        #expect(text(0xC1A1_1C10) == "add za.s[w8, 0, vgx4], { z0.s - z3.s }")
        #expect(text(0xC1A1_0000) == "smlall za.s[w8, 0:3, vgx4], { z0.b - z3.b }, { z0.b - z3.b }")
        #expect(text(0xC120_0400) == "smlall za.s[w8, 0:3], z0.b, z0.b")
        #expect(text(0xC120_0800) == "fmlal za.s[w8, 0:1, vgx2], { z0.h, z1.h }, z0.h")
        #expect(text(0xC150_0000) == "fmla za.s[w8, 0, vgx2], { z0.s, z1.s }, z0.s[0]")
        #expect(text(0xC180_0000) == "smlall za.d[w8, 0:3], z0.h, z0.h[0]")
    }

    @Test func theSelectRegisterAndSliceOffsetTrackTheirFields() {
        let e: UInt32 = 0xC1A0_1C10 | (3 << 13) | 2 | (5 << 6)
        #expect(text(e) == "add za.s[w11, 2, vgx2], { z10.s, z11.s }", "0x\(String(e, radix: 16))")
    }

    @Test func aWordInTheAccumulateGroupThatMatchesNoRowIsAClaimedHole() {
        for e: UInt32 in [0xC100_000C, 0xC100_001C] {
            let d = decode(e)
            #expect(d.mnemonic == .undefined, "0x\(String(e, radix: 16))")
            #expect(d.category == .sme)
            #expect(text(e) == ".long 0x\(String(e, radix: 16))")
        }
    }

    @Test func aWordInTheSelGroupThatIsNotSelIsAClaimedHole() {
        let d = decode(0xC120_8020)
        #expect(d.mnemonic == .undefined)
        #expect(text(0xC120_8020) == ".long 0xc1208020")
    }

    @Test func theNonAccumulateGroupsRouteToTheirVectorOpsDecoders() {
        #expect(decode(0xC120_B800).mnemonic == .smax)
        #expect(decode(0xC120_C400).mnemonic == .sclamp)
        #expect(decode(0xC131_E000).mnemonic == .fcvtzs)
        #expect(decode(0xC120_8000).mnemonic == .sel)
    }
}
