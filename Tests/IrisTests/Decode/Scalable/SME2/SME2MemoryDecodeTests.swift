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

/// Validates the SME2 multi-vector contiguous load/store decoder (cell
/// `101|x|0`) and the ZT0 fill/spill patterns (`LDR`/`STR ZT0`). The whole
/// 128-iclass memory family shares one parameterized layout — strided vs
/// consecutive, immediate vs scalar offset, load vs store, 2-way vs 4-way,
/// element size, and the non-temporal bit — so the element/form matrix and the
/// structural reserved-bit holes are both swept.
@Suite("SME2 / multi-vector memory decode")
struct SME2MemoryDecodeTests {
    @Test func theElementFormMatrixSelectsTheRightMnemonic() {
        // msz (bits[14:13]) picks the element; O (store) and N (non-temporal)
        // pick the ld1/st1/ldnt1/stnt1 spelling.
        let matrix: [(UInt32, Mnemonic)] = [
            (0xA000_0000, .ld1b), (0xA000_2000, .ld1h), (0xA000_4000, .ld1w), (0xA000_6000, .ld1d),
            (0xA000_0001, .ldnt1b), (0xA000_2001, .ldnt1h), (0xA000_4001, .ldnt1w), (0xA000_6001, .ldnt1d),
            (0xA020_0000, .st1b), (0xA020_2000, .st1h), (0xA020_4000, .st1w), (0xA020_6000, .st1d),
            (0xA020_0001, .stnt1b), (0xA020_2001, .stnt1h), (0xA020_4001, .stnt1w), (0xA020_6001, .stnt1d),
        ]
        for (e, m) in matrix {
            expectFamily(e, m, "matrix")
        }
    }

    @Test func aLoadRendersItsZeroingCounterAndScalarIndex() {
        // The consecutive scalar-offset load: a 2-vector list, a `/z` counter
        // predicate, and a `[Xn, Xm{, lsl #msz}]` address.
        #expect(text(0xA000_0000) == "ld1b { z0.b, z1.b }, pn8/z, [x0, x0]")
        #expect(text(0xA000_2000) == "ld1h { z0.h, z1.h }, pn8/z, [x0, x0, lsl #1]")
        #expect(text(0xA000_6000) == "ld1d { z0.d, z1.d }, pn8/z, [x0, x0, lsl #3]")
    }

    @Test func aStoreDropsTheZeroingFromItsCounter() {
        // Store predicates are bare `pn` (no `/z`); the list is a read.
        #expect(text(0xA020_0000) == "st1b { z0.b, z1.b }, pn8, [x0, x0]")
        let d = decode(0xA020_0000)
        #expect(d.memoryAccess == .store)
        #expect(d.semanticWrites.isEmpty, "a store does not write its list")
    }

    @Test func theFourWayFormRendersAConsecutiveRange() {
        #expect(text(0xA000_8000) == "ld1b { z0.b - z3.b }, pn8/z, [x0, x0]")
    }

    @Test func theImmediateFormRendersAMulVLDisplacement() {
        // Q (bit22) selects the `[Xn{, #imm, mul vl}]` form; the imm4 field is
        // sign-extended and scaled by the vector count.
        #expect(text(0xA040_0000) == "ld1b { z0.b, z1.b }, pn8/z, [x0]")
        #expect(text(0xA045_0000) == "ld1b { z0.b, z1.b }, pn8/z, [x0, #10, mul vl]")
        #expect(text(0xA04F_0000) == "ld1b { z0.b, z1.b }, pn8/z, [x0, #-2, mul vl]")
    }

    @Test func theStridedFormNamesEverySteppedMember() {
        // K (bit24) makes the group strided: a pair is {Zk, Zk+8}, a quad steps
        // by four; the first register is `16*T + t`.
        #expect(text(0xA100_0000) == "ld1b { z0.b, z8.b }, pn8/z, [x0, x0]")
        expectFamily(0xA100_8000, .ld1b, "strided quad")
        expectFamily(0xA100_0008, .ldnt1b, "strided non-temporal")
    }

    @Test func theFirstRegisterFieldFollowsTheGroupWidthAndLayout() {
        // Consecutive pair (bits[4:1]), consecutive quad (bits[4:2]), strided
        // pair/quad (T at bit4, t at the low bits).
        #expect(text(0xA000_0006) == "ld1b { z6.b, z7.b }, pn8/z, [x0, x0]")
        #expect(text(0xA000_8008) == "ld1b { z8.b - z11.b }, pn8/z, [x0, x0]")
        expectFamily(0xA100_0012, .ld1b, "strided pair first")
        expectFamily(0xA100_8011, .ld1b, "strided quad first")
    }

    @Test func theScalarIndexPrintsXZRForRegisterThirtyOne() {
        // Rm=31 is a real XZR index here (unlike 2s.6's tile loads, where 31
        // means "no index"), so it is printed rather than dropped.
        #expect(text(0xA01F_0000) == "ld1b { z0.b, z1.b }, pn8/z, [x0, xzr]")
        // Rn=31 is the stack pointer as base.
        #expect(text(0xA000_03E0) == "ld1b { z0.b, z1.b }, pn8/z, [sp, x0]")
    }

    @Test func theNonTemporalFormsCarryTheNonTemporalEffect() {
        for e: UInt32 in [0xA000_0001, 0xA100_0008, 0xA020_0001] {
            #expect(decode(e).scalableEffect.contains(.nonTemporal), "0x\(String(e, radix: 16))")
        }
        #expect(!decode(0xA000_0000).scalableEffect.contains(.nonTemporal))
    }

    @Test func theStructuralZeroBitsRejectToAHole() {
        // The immediate form reserves bit20; a 4-way strided word reserves bit2;
        // a 4-way consecutive word reserves bit1. A set reserved bit is a
        // claimed hole, not an instruction.
        for e: UInt32 in [0xA050_0000, 0xA100_8004, 0xA000_8002] {
            let d = decode(e)
            #expect(d.mnemonic == .undefined, "0x\(String(e, radix: 16))")
            #expect(text(e) == ".long 0x\(String(e, radix: 16))", "0x\(String(e, radix: 16))")
        }
    }

    @Test func theZT0FillSpillPatternsDecodeLdrAndStr() {
        #expect(text(0xE11F_8000) == "ldr zt0, [x0]")
        #expect(text(0xE13F_8000) == "str zt0, [x0]")
        #expect(text(0xE11F_80A0) == "ldr zt0, [x5]")
        #expect(text(0xE11F_83E0) == "ldr zt0, [sp]")
        let load = decode(0xE11F_8000)
        #expect(load.memoryAccess == .load)
        #expect(load.scalableWrites.containsZT0)
        #expect(!load.scalableEffect.contains(.readsStreamingMode), "ZT0 fill/spill is non-streaming-safe")
        let store = decode(0xE13F_8000)
        #expect(store.memoryAccess == .store)
        #expect(store.scalableReads.containsZT0)
    }
}
