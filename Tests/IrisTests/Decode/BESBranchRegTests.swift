// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates branch-register decode across the regular, auth-zero and
/// auth-two-operand forms, their reserved-field rejections, and that RET-LR.
@Suite("BES / Branch register decode (regular + auth)")
struct BESBranchRegTests {
    @Test func brXn() {
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
        let d = decode(0xD63F_0000, at: 0)
        #expect(d.mnemonic == .blr)
        #expect(d.branchClass == .call)
        #expect(d.semanticReads.contains(.x(0)))
        #expect(d.semanticWrites.contains(.x(30)))
    }

    @Test func retLrHasEmptyOperands() {
        let d = decode(0xD65F_03C0, at: 0)
        #expect(d.mnemonic == .ret)
        #expect(d.branchClass == .return)
        #expect(d.operands.isEmpty)
        #expect(d.semanticReads.contains(.x(30)))
    }

    @Test func retXnNotLrCarriesOperand() {
        let d = decode(0xD65F_01E0, at: 0)
        #expect(d.mnemonic == .ret)
        #expect(d.operands.count == 1)
        #expect(d.operands[0] == .register(.x(15)))
    }

    @Test func eret() {
        let d = decode(0xD69F_03E0, at: 0)
        #expect(d.mnemonic == .eret)
        #expect(d.branchClass == .return)
        #expect(d.operands.isEmpty)
        #expect(d.semanticReads.mask == 0)
    }

    @Test func drps() {
        let d = decode(0xD6BF_03E0, at: 0)
        #expect(d.mnemonic == .drps)
        #expect(d.branchClass == .return)
        #expect(d.operands.isEmpty)
    }

    @Test func braa() {
        let d = decode(0xD71F_0A11, at: 0)
        #expect(d.mnemonic == .braa)
        #expect(d.branchClass == .indirect)
        #expect(d.operands.count == 2)
        #expect(d.semanticReads.contains(.x(16)))
        #expect(d.semanticReads.contains(.x(17)))
        #expect(d.semanticWrites.mask == 0)
    }

    @Test func braaWithRmSp() {
        let d = decode(0xD71F_0A1F, at: 0)
        #expect(d.mnemonic == .braa)
        #expect(d.operands[1] == .register(.sp()))
    }

    @Test func brab() {
        let d = decode(0xD71F_0E11, at: 0)
        #expect(d.mnemonic == .brab)
        #expect(d.branchClass == .indirect)
    }

    @Test func blraa() {
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
        let d = decode(0xD65F_0BFF, at: 0)
        #expect(d.mnemonic == .retaa)
        #expect(d.branchClass == .return)
        #expect(d.operands.isEmpty)
        #expect(d.semanticReads.contains(.x(30)))
        #expect(d.semanticReads.contains(.sp()))
    }

    @Test func retab() {
        let d = decode(0xD65F_0FFF, at: 0)
        #expect(d.mnemonic == .retab)
        #expect(d.branchClass == .return)
    }

    @Test func eretaa() {
        let d = decode(0xD69F_0BFF, at: 0)
        #expect(d.mnemonic == .eretaa)
        #expect(d.branchClass == .return)
        #expect(d.semanticReads.mask == 0)
    }

    @Test func eretab() {
        let d = decode(0xD69F_0FFF, at: 0)
        #expect(d.mnemonic == .eretab)
    }

    @Test func bits20To16NonAllOnesIsUndefined() {
        let d = decode(0xD600_0000, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func brWithBit10SetIsUndefined() {
        let d = decode(0xD61F_0400, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func brWithNonZeroRmIsUndefined() {
        let d = decode(0xD61F_0001, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func eretWithNonRnZeroIsUndefined() {
        let d = decode(0xD69F_0000, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func drpsWithNonRnZeroIsUndefined() {
        let d = decode(0xD6BF_0000, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func authTwoOpReservedOpcUndefined() {
        let d = decode(0xD75F_0A1F, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func authTwoOpWithoutAuthMarkerUndefined() {
        let d = decode(0xD71F_0011, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func authZeroFormWithNonAllOnesRmUndefined() {
        let d = decode(0xD61F_0A00, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func authReturnWithNonAllOnesRnUndefined() {
        let d = decode(0xD65F_0BDF, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func braaRnXzr() {
        let d = decode(0xD71F_0BF1, at: 0)
        #expect(d.mnemonic == .braa)
        #expect(d.operands[0] == .register(.xzr()))
    }

    @Test func braazRnXzr() {
        let d = decode(0xD61F_0BFF, at: 0)
        #expect(d.mnemonic == .braaz)
        #expect(d.operands[0] == .register(.xzr()))
    }

    @Test func eretaaWithNonAllOnesRnUndefined() {
        let d = decode(0xD69F_081F, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func authZeroReservedOpcUndefined() {
        let d = decode(0xD67F_0BFF, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func regularReservedOpcUndefined() {
        let d = decode(0xD67F_0000, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func bits15To11NotMatchingAnyFormUndefined() {
        let d = decode(0xD61F_1000, at: 0)
        #expect(d.mnemonic == .undefined)
    }
}
