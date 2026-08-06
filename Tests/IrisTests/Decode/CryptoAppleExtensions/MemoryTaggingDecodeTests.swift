// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates MTE across its three tiers.
@Suite("CryptoAppleExtensions / MemoryTaggingDecode")
struct MemoryTaggingDecodeTests {
    @Test func addgDecodes() {
        let d = decode(0x9182_0C5F, at: 0)
        #expect(d.mnemonic == .addg)
        #expect(d.category == .memoryTagging)
        #expect(d.flagEffect == FlagEffect.none)
        #expect(d.operands.count == 4)
        #expect(d.operands[2] == .unsignedImmediate(value: 32, width: 10))
        #expect(d.operands[3] == .unsignedImmediate(value: 3, width: 4))
    }

    @Test func subgDecodes() {
        let d = decode(0xD182_0C5F, at: 0)
        #expect(d.mnemonic == .subg)
        #expect(d.category == .memoryTagging)
    }

    @Test func addgWithUimm6Zero() {
        let d = decode(0x9180_0020, at: 0)
        #expect(d.mnemonic == .addg)
        #expect(d.operands[2] == .unsignedImmediate(value: 0, width: 10))
        #expect(d.operands[3] == .unsignedImmediate(value: 0, width: 4))
    }

    @Test func addgWithMaxImmediates() {
        let d = decode(0x91BF_3C20, at: 0)
        #expect(d.mnemonic == .addg)
        #expect(d.operands[2] == .unsignedImmediate(value: 1008, width: 10))
        #expect(d.operands[3] == .unsignedImmediate(value: 15, width: 4))
    }

    @Test func dpiReadsRnAndWritesRd() {
        let d = decode(0x9180_0020, at: 0)
        #expect(d.semanticReads.contains(.x(1)) == true)
        #expect(d.semanticWrites.contains(.x(0)) == true)
    }

    @Test func dpiWrongRowPrefixReturnsNil() {
        #expect(decode(0x9100_0000, at: 0).category != .memoryTagging)
    }

    @Test func dpiWithBit22SetIsRejected() {
        #expect(decode(0x91C3_0000, at: 0).category != .memoryTagging)
    }

    @Test func dpiWithSEqualOneIsRejected() {
        #expect(decode(0xB180_0000, at: 0).category != .memoryTagging)
    }

    @Test func dpiWithBits15_14NonZeroDecodesAsAddg() {
        let d = decode(0x9180_4000, at: 0)
        #expect(d.mnemonic == .addg)
    }

    @Test func subpDecodes() {
        let d = decode(0x9AC2_0020, at: 0)
        #expect(d.mnemonic == .subp)
        #expect(d.category == .memoryTagging)
        #expect(d.flagEffect == FlagEffect.none)
    }

    @Test func subpsDecodes() {
        let d = decode(0xBAC2_0020, at: 0)
        #expect(d.mnemonic == .subps)
        #expect(d.flagEffect == .nzcv)
    }

    @Test func irgDecodes() {
        let d = decode(0x9AC2_1020, at: 0)
        #expect(d.mnemonic == .irg)
        #expect(d.category == .memoryTagging)
        #expect(d.operands.count == 3)
    }

    @Test func gmiDecodes() {
        let d = decode(0x9AC2_1420, at: 0)
        #expect(d.mnemonic == .gmi)
        #expect(d.flagEffect == FlagEffect.none)
    }

    @Test func irgWithSEqualOneReturnsNil() {
        let d = decode(0xBAC2_1020, at: 0)
        #expect(d.category != .memoryTagging)
    }

    @Test func gmiWithSEqualOneReturnsNil() {
        let d = decode(0xBAC2_1420, at: 0)
        #expect(d.category != .memoryTagging)
    }

    @Test func dprWrongRowPrefixReturnsNil() {
        #expect(decode(0x0AC2_0020, at: 0).category != .memoryTagging)
        #expect(decode(0x1AC2_0020, at: 0).category != .memoryTagging)
    }

    @Test func dprOpc6OutsideMTESubspaceReturnsNil() {
        let d = decode(0x9AC2_0820, at: 0)
        #expect(d.category != .memoryTagging)
    }

    @Test func stzgmDecodes() {
        let d = decode(0xD920_0020, at: 0)
        #expect(d.mnemonic == .stzgm)
        #expect(d.category == .memoryTagging)
        #expect(d.memoryAccess == .store)
    }

    @Test func stgmDecodes() {
        let d = decode(0xD9A0_0020, at: 0)
        #expect(d.mnemonic == .stgm)
        #expect(d.memoryAccess == .store)
    }

    @Test func ldgmDecodes() {
        let d = decode(0xD9E0_0020, at: 0)
        #expect(d.mnemonic == .ldgm)
        #expect(d.memoryAccess == .load)
    }

    @Test func bulkWithNonZeroImmReturnsNil() {
        let withImm: UInt32 = 0xD920_0020 | (0x1 << 12)
        #expect(decode(withImm, at: 0).category != .memoryTagging)
        let stgmImm: UInt32 = 0xD9A0_0020 | (0x1 << 12)
        #expect(decode(stgmImm, at: 0).category != .memoryTagging)
        let ldgmImm: UInt32 = 0xD9E0_0020 | (0x1 << 12)
        #expect(decode(ldgmImm, at: 0).category != .memoryTagging)
    }

    @Test func ldgSignedOffsetDecodes() {
        let d = decode(0xD960_0020, at: 0)
        #expect(d.mnemonic == .ldg)
        #expect(d.memoryAccess == .load)
    }

    @Test func ldgAcceptsAnySimm9() {
        let d = decode(0xD960_1020, at: 0)
        #expect(d.mnemonic == .ldg)
    }

    @Test func ldgWithNegativeSimm9() {
        let d = decode(0xD97F_F020, at: 0)
        #expect(d.mnemonic == .ldg)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(1)), displacement: -16)))
        let canonical = d.text
        #expect(canonical == "ldg x0, [x1, #-16]")
    }

    @Test func stgSignedOffsetDecodes() {
        let d = decode(0xD920_0820, at: 0)
        #expect(d.mnemonic == .stg)
        #expect(d.memoryAccess == .store)
    }

    @Test func stgPostIndexDecodes() {
        let d = decode(0xD920_0420, at: 0)
        #expect(d.mnemonic == .stg)
    }

    @Test func stgPreIndexDecodes() {
        let d = decode(0xD920_0C20, at: 0)
        #expect(d.mnemonic == .stg)
    }

    @Test func stzgAllAddressingModes() {
        let signedOff = decode(0xD960_0820, at: 0)
        #expect(signedOff.mnemonic == .stzg)
        let postIdx = decode(0xD960_0420, at: 0)
        #expect(postIdx.mnemonic == .stzg)
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
        #expect(decode(0xD820_0820, at: 0).category != .memoryTagging)
        #expect(decode(0xD900_0820, at: 0).category != .memoryTagging)
    }

    @Test func postIndexWritesBackRn() {
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
        let d = decode(0xD960_0020, at: 0)
        #expect(d.semanticReads.contains(.x(0)) == true)
        #expect(d.semanticReads.contains(.x(1)) == true)
        #expect(d.semanticWrites.contains(.x(0)) == true)
    }

    @Test func storeReadsRtAndRn() {
        let d = decode(0xD920_0820, at: 0)
        #expect(d.semanticReads.contains(.x(0)) == true)
        #expect(d.semanticReads.contains(.x(1)) == true)
    }

    @Test func stgRtEqualThirtyOneRendersAsSp() {
        let d = decode(0xD920_083F, at: 0)
        #expect(d.mnemonic == .stg)
        #expect(d.text ==
            "stg sp, [x1]")
    }

    @Test func ldgRtEqualThirtyOneRendersAsXzr() {
        let d = decode(0xD960_003F, at: 0)
        #expect(d.mnemonic == .ldg)
        #expect(d.text ==
            "ldg xzr, [x1]")
    }
}
