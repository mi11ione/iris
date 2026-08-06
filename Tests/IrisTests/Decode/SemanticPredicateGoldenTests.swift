// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Golden table for the semantic predicates.
@Suite("Instruction / semantic predicate golden table")
struct SemanticPredicateGoldenTests {
    @Test func callAndReturnPredicates() {
        let bl = decode(0x9400_0001)
        #expect(bl.isCall)
        #expect(!bl.isReturn)
        #expect(bl.branchTarget != nil)
        let blr = decode(0xD63F_0000)
        #expect(blr.isCall)
        #expect(blr.branchTarget == nil)
        let blraa = decode(0xD73F_0A11)
        #expect(blraa.isCall)
        let ret = decode(0xD65F_03C0)
        #expect(ret.isReturn)
        #expect(!ret.isCall)
        let retaa = decode(0xD65F_0BFF)
        #expect(retaa.isReturn)
        let b = decode(0x1400_0002)
        #expect(!b.isCall)
        #expect(!b.isReturn)
    }

    @Test func conditionalCoversBranchesAndConditionConsumers() {
        #expect(decode(0x5400_0080).isConditional)
        #expect(decode(0xB400_0040).isConditional)
        #expect(decode(0x3600_0040).isConditional)
        #expect(decode(0x9A82_1020).isConditional)
        #expect(decode(0xFA42_0820).isConditional)
        #expect(!decode(0x9A02_0020).isConditional)
        #expect(!decode(0x1400_0002).isConditional)
        #expect(!decode(0x9400_0001).isConditional)
        #expect(!decode(0xD503_201F).isConditional)
    }

    @Test func memoryPredicatesProjectMemoryAccess() {
        let ldr = decode(0xF940_0021)
        #expect(ldr.readsMemory)
        #expect(!ldr.writesMemory)
        #expect(!ldr.isAtomic)
        #expect(!ldr.isExclusive)
        let str = decode(0xF900_0020)
        #expect(str.writesMemory)
        #expect(!str.readsMemory)
        let ldadd = decode(0xF820_0041)
        #expect(ldadd.isAtomic)
        #expect(ldadd.readsMemory)
        #expect(ldadd.writesMemory)
        #expect(!ldadd.isExclusive)
        let ldxr = decode(0xC85F_7C20)
        #expect(ldxr.isExclusive)
        #expect(ldxr.readsMemory)
        #expect(!ldxr.isAtomic)
        let stxr = decode(0x8800_7C00)
        #expect(stxr.isExclusive)
        #expect(stxr.writesMemory)
        #expect(!stxr.isAtomic)
        let prfmLiteral = decode(0xD800_0040)
        #expect(prfmLiteral.memoryAccess == .prefetch)
        #expect(!prfmLiteral.readsMemory)
        #expect(!prfmLiteral.writesMemory)
        let prfmImmediate = decode(0xF980_0000)
        #expect(prfmImmediate.memoryAccess == .prefetch)
        #expect(!prfmImmediate.readsMemory)
        let add = decode(0x9100_0400)
        #expect(!add.readsMemory)
        #expect(!add.writesMemory)
    }

    @Test func flagPredicatesProjectFlagEffect() {
        let adds = decode(0xB100_0841)
        #expect(adds.writesFlags)
        #expect(!adds.readsFlags)
        let adc = decode(0x9A02_0020)
        #expect(adc.readsFlags)
        #expect(!adc.writesFlags)
        let ccmp = decode(0xFA42_0820)
        #expect(ccmp.readsFlags)
        #expect(ccmp.writesFlags)
        let csel = decode(0x9A82_1020)
        #expect(csel.readsFlags)
        #expect(!csel.writesFlags)
        let add = decode(0x9100_0400)
        #expect(!add.readsFlags)
        #expect(!add.writesFlags)
    }

    @Test func isUndefinedWitnessesTheUndefinedCategory() {
        #expect(decode(0x0200_0000).isUndefined)
        #expect(decode(0xF820_0400).isUndefined)
        #expect(!decode(0xF820_0400, features: .arm64e).isUndefined)
        #expect(!decode(0xD503_201F).isUndefined)
    }
}

/// Golden table for the mnemonic set behind `usesPointerAuthentication`.
@Suite("Instruction / pointer-authentication set golden table")
struct PACMnemonicSetGoldenTests {
    private static let members: [(word: UInt32, features: Features, mnemonic: Mnemonic)] = [
        (0xDAC1_0020, [], .pacia), (0xDAC1_0420, [], .pacib),
        (0xDAC1_0820, [], .pacda), (0xDAC1_0C20, [], .pacdb),
        (0xDAC1_1020, [], .autia), (0xDAC1_1420, [], .autib),
        (0xDAC1_1820, [], .autda), (0xDAC1_1C20, [], .autdb),
        (0xDAC1_23E0, [], .paciza), (0xDAC1_27E0, [], .pacizb),
        (0xDAC1_2BE0, [], .pacdza), (0xDAC1_2FE0, [], .pacdzb),
        (0xDAC1_33E0, [], .autiza), (0xDAC1_37E0, [], .autizb),
        (0xDAC1_3BE0, [], .autdza), (0xDAC1_3FE0, [], .autdzb),
        (0xDAC1_43E0, [], .xpaci), (0xDAC1_47E0, [], .xpacd),
        (0x9AC2_3020, [], .pacga),
        (0xD71F_0A11, [], .braa), (0xD71F_0E11, [], .brab),
        (0xD61F_0A1F, [], .braaz), (0xD61F_0E1F, [], .brabz),
        (0xD73F_0A11, [], .blraa), (0xD73F_0E11, [], .blrab),
        (0xD63F_0A1F, [], .blraaz), (0xD63F_0E1F, [], .blrabz),
        (0xD65F_0BFF, [], .retaa), (0xD65F_0FFF, [], .retab),
        (0xD69F_0BFF, [], .eretaa), (0xD69F_0FFF, [], .eretab),
        (0xD503_20FF, [], .xpaclri),
        (0xD503_211F, [], .pacia1716), (0xD503_215F, [], .pacib1716),
        (0xD503_219F, [], .autia1716), (0xD503_21DF, [], .autib1716),
        (0xD503_231F, [], .paciaz), (0xD503_233F, [], .paciasp),
        (0xD503_235F, [], .pacibz), (0xD503_237F, [], .pacibsp),
        (0xD503_239F, [], .autiaz), (0xD503_23BF, [], .autiasp),
        (0xD503_23DF, [], .autibz), (0xD503_23FF, [], .autibsp),
        (0xF820_0400, .arm64e, .ldraa), (0xF8A0_0400, .arm64e, .ldrab),
    ]

    @Test func everyPACSetMemberReportsTrue() {
        #expect(Self.members.count == 46)
        for row in Self.members {
            let instruction = decode(row.word, features: row.features)
            #expect(instruction.mnemonic == row.mnemonic,
                    "0x\(String(row.word, radix: 16)) decoded \(instruction.mnemonic.name), expected \(row.mnemonic.name)")
            #expect(instruction.usesPointerAuthentication,
                    "\(row.mnemonic.name) must report usesPointerAuthentication")
        }
    }

    @Test func nearMissNeighborsReportFalse() {
        let negatives: [(word: UInt32, mnemonic: Mnemonic)] = [
            (0xD65F_03C0, .ret),
            (0xD61F_0000, .br),
            (0xD63F_0000, .blr),
            (0xD69F_03E0, .eret),
            (0x9400_0001, .bl),
            (0x1400_0002, .b),
            (0xF940_0021, .ldr),
            (0xC8DF_FC20, .ldar),
            (0xD503_201F, .nop),
            (0xD503_20DF, .dgh),
        ]
        for row in negatives {
            let instruction = decode(row.word)
            #expect(instruction.mnemonic == row.mnemonic,
                    "0x\(String(row.word, radix: 16)) decoded \(instruction.mnemonic.name)")
            #expect(!instruction.usesPointerAuthentication,
                    "\(row.mnemonic.name) must NOT report usesPointerAuthentication")
        }
    }
}
