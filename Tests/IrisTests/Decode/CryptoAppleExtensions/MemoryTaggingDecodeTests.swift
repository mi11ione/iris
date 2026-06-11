// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the MTE decoder across all three encoding tiers:
/// DPI (ADDG, SUBG), DPR (IRG, GMI, SUBP, SUBPS), and L/S (LDG,
/// STG, ST2G, STZG, STZ2G, LDGM, STGM, STZGM). Includes per-tier
/// row-prefix validation and the strict (opc1, op2) dispatch table
/// for L/S MTE that distinguishes LDG / STG / STZGM / etc.
@Suite("CryptoAppleExtensions / MemoryTaggingDecode")
struct MemoryTaggingDecodeTests {
    @Test func addgDecodes() {
        // ADDG sp, x2, #32, #3 = 0x91820C5F.
        let d = decode(0x9182_0C5F, at: 0)
        #expect(d.mnemonic == .addg)
        #expect(d.category == .memoryTagging)
        #expect(d.flagEffect == FlagEffect.none)
        // uimm6 = 0b000010, scaled × 16 = 32; uimm4 = 0b0011 = 3.
        #expect(d.operands.count == 4)
        #expect(d.operands[2] == .unsignedImmediate(value: 32, width: 10))
        #expect(d.operands[3] == .unsignedImmediate(value: 3, width: 4))
    }

    @Test func subgDecodes() {
        // SUBG sp, x2, #32, #3 = 0xD1820C5F (bit 30 = 1).
        let d = decode(0xD182_0C5F, at: 0)
        #expect(d.mnemonic == .subg)
        #expect(d.category == .memoryTagging)
    }

    @Test func addgWithUimm6Zero() {
        // ADDG x0, x1, #0, #0 = 0x91800020.
        let d = decode(0x9180_0020, at: 0)
        #expect(d.mnemonic == .addg)
        #expect(d.operands[2] == .unsignedImmediate(value: 0, width: 10))
        #expect(d.operands[3] == .unsignedImmediate(value: 0, width: 4))
    }

    @Test func addgWithMaxImmediates() {
        // ADDG x0, x1, #1008, #15 = 0x91BF3C20 (uimm6=0x3F → 0x3F×16=1008).
        let d = decode(0x91BF_3C20, at: 0)
        #expect(d.mnemonic == .addg)
        #expect(d.operands[2] == .unsignedImmediate(value: 1008, width: 10))
        #expect(d.operands[3] == .unsignedImmediate(value: 15, width: 4))
    }

    @Test func dpiReadsRnAndWritesRd() {
        let d = decode(0x9180_0020, at: 0)
        // Rn = x1, Rd = x0 (both SP-allowed, but here X0/X1 are GPR).
        #expect(d.semanticReads.contains(.x(1)) == true)
        #expect(d.semanticWrites.contains(.x(0)) == true)
    }

    @Test func dpiWrongRowPrefixReturnsNil() {
        // Wrong top bits — not ADDG/SUBG row.
        #expect(decode(0x9100_0000, at: 0).category != .memoryTagging)
    }

    @Test func dpiWithBit22SetIsRejected() {
        // bits[23:22] must be 10 (ADDG/SUBG row constant). With bit 22 = 1,
        // bits[23:22] = 11, reserved.
        #expect(decode(0x91C3_0000, at: 0).category != .memoryTagging)
    }

    @Test func dpiWithSEqualOneIsRejected() {
        // S (bit 29) must be 0. With S = 1, the encoding is reserved.
        #expect(decode(0xB180_0000, at: 0).category != .memoryTagging)
    }

    @Test func dpiWithBits15_14NonZeroDecodesAsAddg() {
        // op3 = bits[15:14] nonzero is "potentially undefined" per the ARM ARM:
        // llvm-mc decodes it as addg with that warning, and the oracle
        // policy decodes potentially-undefined encodings, so addg is emitted.
        let d = decode(0x9180_4000, at: 0)
        #expect(d.mnemonic == .addg)
    }

    @Test func subpDecodes() {
        // SUBP x0, x1, x2 = 0x9AC20020.
        let d = decode(0x9AC2_0020, at: 0)
        #expect(d.mnemonic == .subp)
        #expect(d.category == .memoryTagging)
        #expect(d.flagEffect == FlagEffect.none)
    }

    @Test func subpsDecodes() {
        // SUBPS x0, x1, x2 = 0xBAC20020 (S=1).
        let d = decode(0xBAC2_0020, at: 0)
        #expect(d.mnemonic == .subps)
        #expect(d.flagEffect == .nzcv) // SUBPS sets NZCV.
    }

    @Test func irgDecodes() {
        // IRG x0, x1, x2 = 0x9AC21020.
        let d = decode(0x9AC2_1020, at: 0)
        #expect(d.mnemonic == .irg)
        #expect(d.category == .memoryTagging)
        #expect(d.operands.count == 3)
    }

    @Test func gmiDecodes() {
        // GMI x0, x1, x2 = 0x9AC21420.
        let d = decode(0x9AC2_1420, at: 0)
        #expect(d.mnemonic == .gmi)
        #expect(d.flagEffect == FlagEffect.none)
    }

    @Test func irgWithSEqualOneReturnsNil() {
        // IRG requires S=0; S=1 with the same opc6 is reserved.
        let d = decode(0xBAC2_1020, at: 0)
        #expect(d.category != .memoryTagging)
    }

    @Test func gmiWithSEqualOneReturnsNil() {
        let d = decode(0xBAC2_1420, at: 0)
        #expect(d.category != .memoryTagging)
    }

    @Test func dprWrongRowPrefixReturnsNil() {
        // Wrong top bits — not MTE-DPR row.
        #expect(decode(0x0AC2_0020, at: 0).category != .memoryTagging)
        // sf=0:
        #expect(decode(0x1AC2_0020, at: 0).category != .memoryTagging)
    }

    @Test func dprOpc6OutsideMTESubspaceReturnsNil() {
        // opc6 = 0b000010 (UDIV) is in CRC32/DIV territory, not MTE.
        let d = decode(0x9AC2_0820, at: 0)
        #expect(d.category != .memoryTagging)
    }

    @Test func stzgmDecodes() {
        // STZGM x0, [x1] = 0xD9200020 (opc1=00, op2=00, imm9=0).
        let d = decode(0xD920_0020, at: 0)
        #expect(d.mnemonic == .stzgm)
        #expect(d.category == .memoryTagging)
        #expect(d.memoryAccess == .store)
    }

    @Test func stgmDecodes() {
        // STGM x0, [x1] = 0xD9A00020 (opc1=10).
        let d = decode(0xD9A0_0020, at: 0)
        #expect(d.mnemonic == .stgm)
        #expect(d.memoryAccess == .store)
    }

    @Test func ldgmDecodes() {
        // LDGM x0, [x1] = 0xD9E00020 (opc1=11).
        let d = decode(0xD9E0_0020, at: 0)
        #expect(d.mnemonic == .ldgm)
        #expect(d.memoryAccess == .load)
    }

    @Test func bulkWithNonZeroImmReturnsNil() {
        // STZGM with imm9 != 0 is reserved.
        let withImm: UInt32 = 0xD920_0020 | (0x1 << 12)
        #expect(decode(withImm, at: 0).category != .memoryTagging)
        // STGM with imm9 != 0 is reserved.
        let stgmImm: UInt32 = 0xD9A0_0020 | (0x1 << 12)
        #expect(decode(stgmImm, at: 0).category != .memoryTagging)
        // LDGM with imm9 != 0 is reserved.
        let ldgmImm: UInt32 = 0xD9E0_0020 | (0x1 << 12)
        #expect(decode(ldgmImm, at: 0).category != .memoryTagging)
    }

    @Test func ldgSignedOffsetDecodes() {
        // LDG x0, [x1, #0] = 0xD9600020 (opc1=01, op2=00).
        let d = decode(0xD960_0020, at: 0)
        #expect(d.mnemonic == .ldg)
        #expect(d.memoryAccess == .load)
    }

    @Test func ldgAcceptsAnySimm9() {
        // LDG with simm9 = 1 (offset 16) = 0xD9601020.
        let d = decode(0xD960_1020, at: 0)
        #expect(d.mnemonic == .ldg)
    }

    @Test func ldgWithNegativeSimm9() {
        // LDG x0, [x1, #-16] — simm9 = 0x1FF (= -1) × 16 = -16. Verify
        // sign-extension + ×16 scaling and the negative-immediate
        // canonical rendering, not just the mnemonic.
        // imm9 = bits[20:12] = 111_111_111 = 0x1FF (= -1); with Rn=1, Rt=0
        // the full encoding is 0xD97F_F020. The previous 0xD96F_F020
        // encoding had bit 20 = 0 → imm9 = 0xFF (positive 255) which
        // sign-extended to +255 × 16 = +4080, not -16.
        let d = decode(0xD97F_F020, at: 0)
        #expect(d.mnemonic == .ldg)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(1)), displacement: -16)))
        let canonical = d.text
        #expect(canonical == "ldg x0, [x1, #-16]")
    }

    @Test func stgSignedOffsetDecodes() {
        // STG x0, [x1] = 0xD9200820 (opc1=00, op2=10).
        let d = decode(0xD920_0820, at: 0)
        #expect(d.mnemonic == .stg)
        #expect(d.memoryAccess == .store)
    }

    @Test func stgPostIndexDecodes() {
        // STG x0, [x1], #0 = 0xD9200420 (op2=01).
        let d = decode(0xD920_0420, at: 0)
        #expect(d.mnemonic == .stg)
    }

    @Test func stgPreIndexDecodes() {
        // STG x0, [x1, #0]! = 0xD9200C20 (op2=11).
        let d = decode(0xD920_0C20, at: 0)
        #expect(d.mnemonic == .stg)
    }

    @Test func stzgAllAddressingModes() {
        // STZG signed-offset (op2=10).
        let signedOff = decode(0xD960_0820, at: 0)
        #expect(signedOff.mnemonic == .stzg)
        // STZG post-index (op2=01).
        let postIdx = decode(0xD960_0420, at: 0)
        #expect(postIdx.mnemonic == .stzg)
        // STZG pre-index (op2=11).
        let preIdx = decode(0xD960_0C20, at: 0)
        #expect(preIdx.mnemonic == .stzg)
    }

    @Test func st2gAllAddressingModes() {
        let signedOff = decode(0xD9A0_0820, at: 0)
        #expect(signedOff.mnemonic == .st2g)
        let postIdx = decode(0xD9A0_0420, at: 0)
        #expect(postIdx.mnemonic == .st2g)
        let preIdx = decode(0xD9A0_0C20, at: 0)
        #expect(preIdx.mnemonic == .st2g)
    }

    @Test func stz2gAllAddressingModes() {
        let signedOff = decode(0xD9E0_0820, at: 0)
        #expect(signedOff.mnemonic == .stz2g)
        let postIdx = decode(0xD9E0_0420, at: 0)
        #expect(postIdx.mnemonic == .stz2g)
        let preIdx = decode(0xD9E0_0C20, at: 0)
        #expect(preIdx.mnemonic == .stz2g)
    }

    @Test func lsWrongRowPrefixReturnsNil() {
        // Wrong top byte (not 0xD9):
        #expect(decode(0xD820_0820, at: 0).category != .memoryTagging)
        // bit 21 = 0 (LRCPC2 territory):
        #expect(decode(0xD900_0820, at: 0).category != .memoryTagging)
    }

    @Test func postIndexWritesBackRn() {
        // STG with post-index updates Rn.
        let d = decode(0xD920_0420, at: 0)
        #expect(d.semanticWrites.contains(.x(1)) == true)
    }

    @Test func preIndexWritesBackRn() {
        let d = decode(0xD920_0C20, at: 0)
        #expect(d.semanticWrites.contains(.x(1)) == true)
    }

    @Test func signedOffsetDoesNotWriteBackRn() {
        let d = decode(0xD920_0820, at: 0)
        #expect(d.semanticWrites.contains(.x(1)) == false)
    }

    @Test func loadIsReadModifyWriteOfRt() {
        // LDG x0, [x1] is read-modify-write of Rt: the loaded tag is inserted
        // into Xt's tag field, preserving the other bits (ARM ARM
        // `X[t]<59:56> = tag`), so Rt (x0) is BOTH read and written; the base
        // Rn (x1) is read.
        let d = decode(0xD960_0020, at: 0)
        #expect(d.semanticReads.contains(.x(0)) == true)
        #expect(d.semanticReads.contains(.x(1)) == true)
        #expect(d.semanticWrites.contains(.x(0)) == true)
    }

    @Test func storeReadsRtAndRn() {
        // STG x0, [x1] — Rt=0 and Rn=1 both read.
        let d = decode(0xD920_0820, at: 0)
        #expect(d.semanticReads.contains(.x(0)) == true)
        #expect(d.semanticReads.contains(.x(1)) == true)
    }

    @Test func stgRtEqualThirtyOneRendersAsSp() {
        // STG with Rt=11111 — STG's Rt is SP-allowed, so encoded 31
        // is SP (not XZR). STG sp, [x1] = 0xD920_083F.
        let d = decode(0xD920_083F, at: 0)
        #expect(d.mnemonic == .stg)
        #expect(d.text ==
            "stg sp, [x1]")
    }

    @Test func ldgRtEqualThirtyOneRendersAsXzr() {
        // LDG with Rt=11111 — LDG's Rt is GPR-only (not SP-allowed),
        // so encoded 31 is XZR. LDG xzr, [x1] = 0xD960_003F.
        let d = decode(0xD960_003F, at: 0)
        #expect(d.mnemonic == .ldg)
        #expect(d.text ==
            "ldg xzr, [x1]")
    }
}
