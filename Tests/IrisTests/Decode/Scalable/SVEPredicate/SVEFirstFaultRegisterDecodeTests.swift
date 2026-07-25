// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0, features: .scalable)
}

private func predicates(_ set: ScalableRegisterSet) -> [UInt8] {
    (0 ..< 16).filter { set.containsPredicate(UInt8($0)) }.map(UInt8.init)
}

/// Validates the first-fault-register group — RDFFR, RDFFRS, WRFFR, SETFFR. FFR
/// is the one architectural register in this tier that lives outside both the
/// general-purpose mask and the predicate mask, so the read/write of it is the
/// whole point: a decoder that dropped it would make every fault-tolerant load
/// loop look dependency-free to a downstream consumer. The predicated and
/// unpredicated reads share an encoding, split on a single bit, and the
/// flag-setting unpredicated combination does not exist.
@Suite("SVE predicate & control / first-fault register")
struct SVEFirstFaultRegisterDecodeTests {
    @Test func theUnpredicatedReadTakesNoGoverningPredicate() {
        let d = decode(0x2519_F003) // rdffr p3.b
        #expect(d.mnemonic == .rdffr)
        #expect(d.flagEffect == .none)
        #expect(Array(d.operands) == [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 3, element: .b, role: .result)),
        ])
        #expect(d.scalableReads.containsFFR)
        #expect(predicates(d.scalableReads).isEmpty)
        #expect(predicates(d.scalableWrites) == [3])
        #expect(!d.scalableWrites.containsFFR)
        #expect(d.scalableEffect == .readsStreamingMode)
    }

    @Test func thePredicatedReadAddsAZeroingGoverningPredicate() {
        let d = decode(0x2518_F043) // rdffr p3.b, p2/z
        #expect(d.mnemonic == .rdffr)
        #expect(d.flagEffect == .none)
        #expect(Array(d.operands) == [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 3, element: .b, role: .result)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 2, qualifier: .zeroing, role: .governing)),
        ])
        #expect(d.scalableReads.containsFFR)
        #expect(predicates(d.scalableReads) == [2])
        #expect(predicates(d.scalableWrites) == [3])
    }

    @Test func theFlagSettingReadExistsOnlyInItsPredicatedForm() {
        let d = decode(0x2558_F043) // rdffrs p3.b, p2/z
        #expect(d.mnemonic == .rdffrs)
        #expect(d.flagEffect == .nzcv)
        #expect(d.scalableReads.containsFFR)
        #expect(predicates(d.scalableReads) == [2])

        // Setting the flag bit on the unpredicated form is not an instruction.
        #expect(decode(0x2559_F003).mnemonic == .undefined)
    }

    @Test func theUnpredicatedReadRejectsAGoverningPredicateField() {
        // The predicate field is a fixed zero in the unpredicated encoding.
        #expect(decode(0x2519_F043).mnemonic == .undefined)
    }

    @Test func theFirstFaultReadRejectsItsReservedBits() {
        #expect(decode(0x2598_F043).mnemonic == .undefined) // bit 23
        #expect(decode(0x251A_F043).mnemonic == .undefined) // bits 18:17
        #expect(decode(0x2518_F243).mnemonic == .undefined) // bit 9
        #expect(decode(0x2518_F053).mnemonic == .undefined) // bit 4
    }

    @Test func theFirstFaultWriteReadsAPredicateAndWritesTheRegister() {
        let d = decode(0x2528_9040) // wrffr p2.b
        #expect(d.mnemonic == .wrffr)
        #expect(d.flagEffect == .none)
        #expect(Array(d.operands) == [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 2, element: .b)),
        ])
        #expect(predicates(d.scalableReads) == [2])
        #expect(!d.scalableReads.containsFFR)
        #expect(d.scalableWrites.containsFFR)
        #expect(predicates(d.scalableWrites).isEmpty)
        #expect(d.scalableEffect == .readsStreamingMode)
    }

    @Test func theFirstFaultSetTakesNoOperandAtAll() {
        let d = decode(0x252C_9000) // setffr
        #expect(d.mnemonic == .setffr)
        #expect(d.flagEffect == .none)
        #expect(d.operands.isEmpty)
        #expect(d.scalableReads == .empty)
        #expect(d.scalableWrites.containsFFR)
        #expect(d.scalableEffect == .readsStreamingMode)
    }

    @Test func theFirstFaultSetRejectsASourcePredicateField() {
        // SETFFR shares its encoding with WRFFR and differs only in bit 18; the
        // source-predicate field it inherits must be zero.
        #expect(decode(0x252C_9040).mnemonic == .undefined)
    }

    @Test func theFirstFaultWriteRejectsItsReservedBits() {
        #expect(decode(0x2568_9040).mnemonic == .undefined) // bits 23:22
        #expect(decode(0x2529_9040).mnemonic == .undefined) // bits 17:16
        #expect(decode(0x2528_9240).mnemonic == .undefined) // bits 10:9
        #expect(decode(0x2528_9041).mnemonic == .undefined) // bits 4:0
    }
}
