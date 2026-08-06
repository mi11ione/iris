// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ e: UInt32) -> Instruction {
    Iris.decode(e, at: 0)
}

private func text(_ e: UInt32) -> String {
    decode(e).text
}

private func expectFamily(_ e: UInt32, _ m: Mnemonic, _ label: String) {
    let d = decode(e)
    #expect(d.mnemonic == m, "\(label) 0x\(String(e, radix: 16))")
    #expect(d.category == .sme, "\(label)")
    let t = text(e)
    #expect(!t.isEmpty && !t.contains("?") && !t.contains("\n"), "\(label) -> \(t)")
}

private let lutis: [(UInt32, Mnemonic)] = [
    (0xC08A_0000, .luti6),
    (0xC08A_4000, .luti4),
    (0xC08A_5000, .luti4),
    (0xC08A_6000, .luti4),
    (0xC08A_9000, .luti4),
    (0xC08A_A000, .luti4),
    (0xC08B_0000, .luti4),
    (0xC08C_4000, .luti2),
    (0xC08C_5000, .luti2),
    (0xC08C_6000, .luti2),
    (0xC08C_8000, .luti2),
    (0xC08C_9000, .luti2),
    (0xC08C_A000, .luti2),
    (0xC09A_0000, .luti6),
    (0xC09A_4000, .luti4),
    (0xC09A_5000, .luti4),
    (0xC09A_9000, .luti4),
    (0xC09B_0000, .luti4),
    (0xC09C_4000, .luti2),
    (0xC09C_5000, .luti2),
    (0xC09C_8000, .luti2),
    (0xC09C_9000, .luti2),
    (0xC0C8_4000, .luti6),
    (0xC0CA_0000, .luti4),
    (0xC0CA_1000, .luti4),
    (0xC0CA_2000, .luti4),
    (0xC0CC_0000, .luti2),
    (0xC0CC_1000, .luti2),
    (0xC0CC_2000, .luti2),
]

/// Validates the SME2 move/lookup decoders.
@Suite("SME2 / move-lookup decode")
struct SME2MoveLookupDecodeTests {
    @Test func everyLutiRowResolvesAndIsConsistent() {
        for (e, m) in lutis {
            let d = decode(e)
            #expect(d.mnemonic == m, "0x\(String(e, radix: 16))")
            let t = text(e)
            #expect(!t.isEmpty && !t.contains("?"), "0x\(String(e, radix: 16)) -> \(t)")
            #expect(d.scalableReads.containsZT0, "0x\(String(e, radix: 16)) LUTI reads ZT0")
        }
    }

    @Test func theMovaArrayFormsMoveBetweenAZADVectorAndAList() {
        #expect(text(0xC004_0800) == "mov za.d[w8, 0, vgx2], { z0.d, z1.d }")
        #expect(text(0xC004_0C00) == "mov za.d[w8, 0, vgx4], { z0.d - z3.d }")
        #expect(text(0xC006_0800) == "mov { z0.d, z1.d }, za.d[w8, 0, vgx2]")
        #expect(text(0xC006_0A00) == "movaz { z0.d, z1.d }, za.d[w8, 0, vgx2]")
        #expect(text(0xC006_0C00) == "mov { z0.d - z3.d }, za.d[w8, 0, vgx4]")
        #expect(text(0xC006_0E00) == "movaz { z0.d - z3.d }, za.d[w8, 0, vgx4]")
    }

    @Test func theMovaTileSliceFormsCoverSingleSliceAndMultiDirections() {
        expectFamily(0xC002_0200, .movaz, "movaz single .b")
        expectFamily(0xC042_0200, .movaz, "movaz single .h")
        expectFamily(0xC082_0200, .movaz, "movaz single .s")
        expectFamily(0xC0C2_0200, .movaz, "movaz single .d")
        expectFamily(0xC0C3_0200, .movaz, "movaz single .q")
        expectFamily(0xC004_0000, .mov, "mov multi write vgx2")
        expectFamily(0xC006_0000, .mov, "mov multi read vgx2")
        expectFamily(0xC006_0200, .movaz, "movaz multi read vgx2")
        expectFamily(0xC004_0400, .mov, "mov multi write vgx4")
        expectFamily(0xC006_0400, .mov, "mov multi read vgx4")
        #expect(text(0xC002_0200) == "movaz z0.b, za0h.b[w12, 0]")
        #expect(text(0xC004_0400) == "mov za0h.b[w12, 0:3], { z0.b - z3.b }")
    }

    @Test func theZeroArrayFormsRenderEveryGroupAndRangeShape() {
        #expect(text(0xC00C_0000) == "zero za.d[w8, 0, vgx2]")
        #expect(text(0xC00E_0000) == "zero za.d[w8, 0, vgx4]")
        #expect(text(0xC00C_8000) == "zero za.d[w8, 0:1]")
        #expect(text(0xC00D_0000) == "zero za.d[w8, 0:1, vgx2]")
        #expect(text(0xC00D_8000) == "zero za.d[w8, 0:1, vgx4]")
        #expect(text(0xC00E_8000) == "zero za.d[w8, 0:3]")
        #expect(text(0xC00F_0000) == "zero za.d[w8, 0:3, vgx2]")
        #expect(text(0xC00F_8000) == "zero za.d[w8, 0:3, vgx4]")
    }

    @Test func theZeroZT0FormRendersItsBracedList() {
        #expect(text(0xC048_0001) == "zero { zt0 }")
        let d = decode(0xC048_0001)
        #expect(d.scalableWrites.containsZT0)
        #expect(!d.scalableEffect.contains(.readsStreamingMode), "ZERO ZT0 is non-streaming-safe")
    }

    @Test func theMovtFormsMoveBetweenAGprOrVectorAndZT0() {
        #expect(text(0xC04C_03E0) == "movt x0, zt0[0]")
        #expect(text(0xC04C_33E5) == "movt x5, zt0[24]")
        #expect(text(0xC04E_03E0) == "movt zt0[0], x0")
        #expect(text(0xC04F_03E0) == "movt zt0, z0")
        #expect(text(0xC04F_13E0) == "movt zt0[1, mul vl], z0")
    }

    @Test func theLutiLookupsRenderTheirZeroTableSource() {
        expectFamily(0xC0CA_0000, .luti4, "luti4 single .b")
        expectFamily(0xC0CC_0000, .luti2, "luti2 single .b")
        expectFamily(0xC0C8_4000, .luti6, "luti6 single .b")
        expectFamily(0xC08A_4000, .luti4, "luti4 multi .b")
        expectFamily(0xC08C_4000, .luti2, "luti2 multi .b")
        expectFamily(0xC08A_0000, .luti6, "luti6 multi .b")
        expectFamily(0xC08B_0000, .luti4, "luti4 lutv2")
    }

    @Test func reservedBitsInTheMovaTileSliceFormsRejectToAHole() {
        for e: UInt32 in [0xC004_0008, 0xC006_0100, 0xC004_0440, 0xC006_0001, 0xC004_0404] {
            #expect(decode(e).mnemonic != .mov, "0x\(String(e, radix: 16)) slipped a reserved bit")
        }
    }

    @Test func anUnallocatedMoveLookupWordIsAClaimedHole() {
        for e: UInt32 in [0xC00C_1000, 0xC048_0000, 0xC04C_0000, 0xC0CA_0400] {
            let d = decode(e)
            #expect(d.mnemonic == .undefined, "0x\(String(e, radix: 16))")
            #expect(text(e) == ".long 0x\(String(e, radix: 16))", "0x\(String(e, radix: 16))")
        }
    }
}
