// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates branch-register decode: regular forms
/// (BR / BLR / RET / ERET / DRPS) at `bit 24 == 0 && bits 15:11 == 00000`,
/// auth-zero / auth-return forms at `bit 24 == 0 && bits 15:11 == 00001`,
/// auth-two-operand forms at `bit 24 == 1`. Fixed-field checks reject
/// reserved encodings. Covers branchClass and pins
/// that RET-LR has empty operands at draft level.
@Suite("BES / Branch register decode (regular + auth)")
struct BESBranchRegTests {
    @Test func brXn() {
        // 0xD61F0000 = BR X0
        let d = decode(0xD61F_0000, at: 0)
        #expect(d.mnemonic == .br)
        #expect(d.branchClass == .indirect)
        #expect(d.operands.count == 1)
        #expect(d.operands[0] == .register(.x(0)))
        #expect(d.semanticReads.contains(.x(0)))
        #expect(d.semanticWrites.mask == 0)
    }

    @Test func brXnX30() {
        let d = decode(0xD61F_03C0, at: 0)
        #expect(d.mnemonic == .br)
        #expect(d.semanticReads.contains(.x(30)))
    }

    @Test func blrXn() {
        // 0xD63F0000 = BLR X0 (opc = 0001)
        let d = decode(0xD63F_0000, at: 0)
        #expect(d.mnemonic == .blr)
        #expect(d.branchClass == .call)
        // BLR reads Rn AND writes X30.
        #expect(d.semanticReads.contains(.x(0)))
        #expect(d.semanticWrites.contains(.x(30)))
    }

    @Test func retLrHasEmptyOperands() {
        // 0xD65F03C0 = RET (default LR). RET with Rn=30 has
        // draft.operands.isEmpty.
        let d = decode(0xD65F_03C0, at: 0)
        #expect(d.mnemonic == .ret)
        #expect(d.branchClass == .return)
        #expect(d.operands.isEmpty)
        #expect(d.semanticReads.contains(.x(30)))
    }

    @Test func retXnNotLrCarriesOperand() {
        // RET X15 (Rn=15) — operand kept since it's not the default LR.
        // 0xD65F01E0 = RET X15
        let d = decode(0xD65F_01E0, at: 0)
        #expect(d.mnemonic == .ret)
        #expect(d.operands.count == 1)
        #expect(d.operands[0] == .register(.x(15)))
    }

    @Test func eret() {
        // 0xD69F03E0 = ERET (opc=0100, Rn=11111)
        let d = decode(0xD69F_03E0, at: 0)
        #expect(d.mnemonic == .eret)
        #expect(d.branchClass == .return)
        #expect(d.operands.isEmpty)
        #expect(d.semanticReads.mask == 0)
    }

    @Test func drps() {
        // 0xD6BF03E0 = DRPS (opc=0101, Rn=11111)
        let d = decode(0xD6BF_03E0, at: 0)
        #expect(d.mnemonic == .drps)
        #expect(d.branchClass == .return)
        #expect(d.operands.isEmpty)
    }

    @Test func braa() {
        // 0xD71F0A11 = BRAA X16, X17 (opc=1000, M=0, Rn=16, Rm=17)
        let d = decode(0xD71F_0A11, at: 0)
        #expect(d.mnemonic == .braa)
        #expect(d.branchClass == .indirect)
        #expect(d.operands.count == 2)
        #expect(d.semanticReads.contains(.x(16)))
        #expect(d.semanticReads.contains(.x(17)))
        #expect(d.semanticWrites.mask == 0)
    }

    @Test func braaWithRmSp() {
        // BRAA X16, SP — Rm=31 in two-op form renders as SP #22.
        // 0xD71F0A1F
        let d = decode(0xD71F_0A1F, at: 0)
        #expect(d.mnemonic == .braa)
        #expect(d.operands[1] == .register(.sp()))
    }

    @Test func brab() {
        // 0xD71F0E11 = BRAB X16, X17 (M=1 at bit 10)
        let d = decode(0xD71F_0E11, at: 0)
        #expect(d.mnemonic == .brab)
        #expect(d.branchClass == .indirect)
    }

    @Test func blraa() {
        // 0xD73F0A11 = BLRAA X16, X17 (opcLow3=001 → bits 24:21=1001)
        let d = decode(0xD73F_0A11, at: 0)
        #expect(d.mnemonic == .blraa)
        #expect(d.branchClass == .call)
        #expect(d.semanticWrites.contains(.x(30)))
    }

    @Test func blrab() {
        let d = decode(0xD73F_0E11, at: 0)
        #expect(d.mnemonic == .blrab)
        #expect(d.branchClass == .call)
    }

    @Test func braaz() {
        // 0xD61F0A1F = BRAAZ X16 (opc=0000, M=0, Rn=16, Rm=11111)
        let d = decode(0xD61F_0A1F, at: 0)
        #expect(d.mnemonic == .braaz)
        #expect(d.branchClass == .indirect)
        #expect(d.operands.count == 1)
        #expect(d.semanticReads.contains(.x(16)))
    }

    @Test func brabz() {
        let d = decode(0xD61F_0E1F, at: 0)
        #expect(d.mnemonic == .brabz)
    }

    @Test func blraaz() {
        // 0xD63F0A1F = BLRAAZ X16 (opcLow3=001)
        let d = decode(0xD63F_0A1F, at: 0)
        #expect(d.mnemonic == .blraaz)
        #expect(d.branchClass == .call)
        #expect(d.semanticWrites.contains(.x(30)))
    }

    @Test func blrabz() {
        let d = decode(0xD63F_0E1F, at: 0)
        #expect(d.mnemonic == .blrabz)
    }

    @Test func retaa() {
        // 0xD65F0BFF = RETAA (opcLow3=010, M=0, Rn=11111, Rm=11111)
        let d = decode(0xD65F_0BFF, at: 0)
        #expect(d.mnemonic == .retaa)
        #expect(d.branchClass == .return)
        #expect(d.operands.isEmpty)
        // RETAA reads LR + SP.
        #expect(d.semanticReads.contains(.x(30)))
        #expect(d.semanticReads.contains(.sp()))
    }

    @Test func retab() {
        let d = decode(0xD65F_0FFF, at: 0)
        #expect(d.mnemonic == .retab)
        #expect(d.branchClass == .return)
    }

    @Test func eretaa() {
        // 0xD69F0BFF = ERETAA (opcLow3=100, M=0)
        let d = decode(0xD69F_0BFF, at: 0)
        #expect(d.mnemonic == .eretaa)
        #expect(d.branchClass == .return)
        #expect(d.semanticReads.mask == 0) // kernel only; no GP-set effect
    }

    @Test func eretab() {
        let d = decode(0xD69F_0FFF, at: 0)
        #expect(d.mnemonic == .eretab)
    }

    @Test func bits20To16NonAllOnesIsUndefined() {
        // BR with bits 20:16 = 0 (should be 11111) → UNDEFINED
        let d = decode(0xD600_0000, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func brWithBit10SetIsUndefined() {
        // Regular BR (bit 24 = 0, bits 15:11 = 00000) with bit 10 = 1 → UNDEFINED
        let d = decode(0xD61F_0400, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func brWithNonZeroRmIsUndefined() {
        // BR with bits 4:0 = 00001 (Rm field should be 0) → UNDEFINED
        let d = decode(0xD61F_0001, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func eretWithNonRnZeroIsUndefined() {
        // ERET with Rn != 11111 → UNDEFINED
        let d = decode(0xD69F_0000, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func drpsWithNonRnZeroIsUndefined() {
        let d = decode(0xD6BF_0000, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func authTwoOpReservedOpcUndefined() {
        // bit 24 = 1, opcLow3 = 010 (reserved for two-op family) → UNDEFINED
        let d = decode(0xD75F_0A1F, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func authTwoOpWithoutAuthMarkerUndefined() {
        // bit 24 = 1, bits 15:11 = 00000 (auth marker required = 00001) → UNDEFINED
        let d = decode(0xD71F_0011, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func authZeroFormWithNonAllOnesRmUndefined() {
        // BRAAZ-shaped (bits 15:11 = 00001) but Rm field != 11111 → UNDEFINED
        let d = decode(0xD61F_0A00, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func authReturnWithNonAllOnesRnUndefined() {
        // RETAA-shaped but Rn != 11111 → UNDEFINED
        let d = decode(0xD65F_0BDF, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func braaRnXzr() {
        // BRAA XZR, X17 — Rn=31 in two-operand form decodes as XZR
        // (not SP) since Rn is the target register, not a modifier.
        // Encoding: opc=1000, M=0, Rn=31, Rm=17 → 0xD71F_0BF1
        let d = decode(0xD71F_0BF1, at: 0)
        #expect(d.mnemonic == .braa)
        #expect(d.operands[0] == .register(.xzr()))
    }

    @Test func braazRnXzr() {
        // BRAAZ XZR — Rn=31 in one-operand-zero form decodes as XZR.
        // Encoding: opc=0000, M=0, Rn=31, Rm=11111 → 0xD61F_0BFF
        let d = decode(0xD61F_0BFF, at: 0)
        #expect(d.mnemonic == .braaz)
        #expect(d.operands[0] == .register(.xzr()))
    }

    @Test func eretaaWithNonAllOnesRnUndefined() {
        // ERETAA-shaped (bit 24=0, bits 15:11=00001, opcLow3=100) but Rn != 31 → UNDEFINED
        let d = decode(0xD69F_081F, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func authZeroReservedOpcUndefined() {
        // bit 24 = 0, bits 15:11 = 00001, opcLow3 = 011 (reserved) → UNDEFINED
        let d = decode(0xD67F_0BFF, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func regularReservedOpcUndefined() {
        // Regular form with opc = 0011 (reserved) → UNDEFINED
        let d = decode(0xD67F_0000, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func bits15To11NotMatchingAnyFormUndefined() {
        // bit 24 = 0, bits 15:11 = 00010 (neither regular nor auth pattern) → UNDEFINED
        let d = decode(0xD61F_1000, at: 0)
        #expect(d.mnemonic == .undefined)
    }
}
