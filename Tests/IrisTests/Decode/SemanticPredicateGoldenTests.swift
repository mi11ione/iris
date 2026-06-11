// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Golden table for the Instruction semantic predicates: representative
/// encodings per predicate, including the documented non-claims as
/// negative rows (PRFM is not a read, ADC is not conditional, LDXR is
/// exclusive-not-atomic).
@Suite("Instruction / semantic predicate golden table")
struct SemanticPredicateGoldenTests {
    @Test func callAndReturnPredicates() {
        let bl = decode(0x9400_0001)
        #expect(bl.isCall)
        #expect(!bl.isReturn)
        #expect(bl.branchTarget != nil) // direct call
        let blr = decode(0xD63F_0000)
        #expect(blr.isCall)
        #expect(blr.branchTarget == nil) // indirect call
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
        #expect(decode(0x5400_0080).isConditional) // b.eq
        #expect(decode(0xB400_0040).isConditional) // cbz
        #expect(decode(0x3600_0040).isConditional) // tbz
        #expect(decode(0x9A82_1020).isConditional) // csel x0, x1, x2, ne
        #expect(decode(0xFA42_0820).isConditional) // ccmp x1, x2, #0, eq
        // Non-claims: flag-consuming arithmetic executes unconditionally;
        // unconditional control flow is not conditional.
        #expect(!decode(0x9A02_0020).isConditional) // adc x0, x1, x2
        #expect(!decode(0x1400_0002).isConditional) // b
        #expect(!decode(0x9400_0001).isConditional) // bl
        #expect(!decode(0xD503_201F).isConditional) // nop
    }

    @Test func memoryPredicatesProjectMemoryAccess() {
        let ldr = decode(0xF940_0021) // ldr x1, [x1]
        #expect(ldr.readsMemory)
        #expect(!ldr.writesMemory)
        #expect(!ldr.isAtomic)
        #expect(!ldr.isExclusive)
        let str = decode(0xF900_0020) // str x0, [x1]
        #expect(str.writesMemory)
        #expect(!str.readsMemory)
        // Atomic read-modify-write is both a read and a write.
        let ldadd = decode(0xF820_0041) // ldadd x0, x1, [x2]
        #expect(ldadd.isAtomic)
        #expect(ldadd.readsMemory)
        #expect(ldadd.writesMemory)
        #expect(!ldadd.isExclusive)
        // Exclusive-monitor halves are exclusive, NOT atomic (non-claim:
        // the pair is atomic only as a sequence).
        let ldxr = decode(0xC85F_7C20) // ldxr x0, [x1]
        #expect(ldxr.isExclusive)
        #expect(ldxr.readsMemory)
        #expect(!ldxr.isAtomic)
        let stxr = decode(0x8800_7C00) // stxr w0, w0, [x0]
        #expect(stxr.isExclusive)
        #expect(stxr.writesMemory)
        #expect(!stxr.isAtomic)
        // Non-claim: PRFM is an architectural hint, not a read.
        let prfmLiteral = decode(0xD800_0040)
        #expect(prfmLiteral.memoryAccess == .prefetch)
        #expect(!prfmLiteral.readsMemory)
        #expect(!prfmLiteral.writesMemory)
        let prfmImmediate = decode(0xF980_0000) // prfm pldl1keep, [x0]
        #expect(prfmImmediate.memoryAccess == .prefetch)
        #expect(!prfmImmediate.readsMemory)
        // No memory at all.
        let add = decode(0x9100_0400)
        #expect(!add.readsMemory)
        #expect(!add.writesMemory)
    }

    @Test func flagPredicatesProjectFlagEffect() {
        let adds = decode(0xB100_0841) // adds x1, x2, #2
        #expect(adds.writesFlags)
        #expect(!adds.readsFlags)
        let adc = decode(0x9A02_0020) // adc x0, x1, x2 — reads C only
        #expect(adc.readsFlags)
        #expect(!adc.writesFlags)
        let ccmp = decode(0xFA42_0820) // ccmp — reads cond, writes nzcv
        #expect(ccmp.readsFlags)
        #expect(ccmp.writesFlags)
        let csel = decode(0x9A82_1020) // csel — reads cond
        #expect(csel.readsFlags)
        #expect(!csel.writesFlags)
        let add = decode(0x9100_0400)
        #expect(!add.readsFlags)
        #expect(!add.writesFlags)
    }

    @Test func isUndefinedWitnessesTheUndefinedCategory() {
        #expect(decode(0x0200_0000).isUndefined)
        // Feature-gated encodings are undefined without the feature.
        #expect(decode(0xF820_0400).isUndefined)
        #expect(!decode(0xF820_0400, features: .arm64e).isUndefined)
        #expect(!decode(0xD503_201F).isUndefined)
    }
}

/// Golden table for the pointer-authentication mnemonic set behind
/// `usesPointerAuthentication`: every mnemonic in the set decodes from
/// a representative word and reports true; near-miss neighbors report
/// false.
@Suite("Instruction / pointer-authentication set golden table")
struct PACMnemonicSetGoldenTests {
    /// Every member of the PAC set as (word, features, mnemonic).
    private static let members: [(word: UInt32, features: Features, mnemonic: Mnemonic)] = [
        // Standalone PAC (category == .pointerAuthentication).
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
        // BES authenticated branches and returns.
        (0xD71F_0A11, [], .braa), (0xD71F_0E11, [], .brab),
        (0xD61F_0A1F, [], .braaz), (0xD61F_0E1F, [], .brabz),
        (0xD73F_0A11, [], .blraa), (0xD73F_0E11, [], .blrab),
        (0xD63F_0A1F, [], .blraaz), (0xD63F_0E1F, [], .blrabz),
        (0xD65F_0BFF, [], .retaa), (0xD65F_0FFF, [], .retab),
        (0xD69F_0BFF, [], .eretaa), (0xD69F_0FFF, [], .eretab),
        // Hint-space PAC forms.
        (0xD503_20FF, [], .xpaclri),
        (0xD503_211F, [], .pacia1716), (0xD503_215F, [], .pacib1716),
        (0xD503_219F, [], .autia1716), (0xD503_21DF, [], .autib1716),
        (0xD503_231F, [], .paciaz), (0xD503_233F, [], .paciasp),
        (0xD503_235F, [], .pacibz), (0xD503_237F, [], .pacibsp),
        (0xD503_239F, [], .autiaz), (0xD503_23BF, [], .autiasp),
        (0xD503_23DF, [], .autibz), (0xD503_23FF, [], .autibsp),
        // Authenticated loads (feature-gated tier).
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
        // Unauthenticated forms of the same shapes, and ordinary memory.
        let negatives: [(word: UInt32, mnemonic: Mnemonic)] = [
            (0xD65F_03C0, .ret), //   ret (vs retaa)
            (0xD61F_0000, .br), //    br (vs braa)
            (0xD63F_0000, .blr), //   blr (vs blraa)
            (0xD69F_03E0, .eret), //  eret (vs eretaa)
            (0x9400_0001, .bl), //    bl
            (0x1400_0002, .b), //     b
            (0xF940_0021, .ldr), //   ldr (vs ldraa)
            (0xC8DF_FC20, .ldar), //  ldar
            (0xD503_201F, .nop), //   nop (hint #0 vs PAC hints)
            (0xD503_20DF, .dgh), //   hint #6 (vs xpaclri at #7)
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
