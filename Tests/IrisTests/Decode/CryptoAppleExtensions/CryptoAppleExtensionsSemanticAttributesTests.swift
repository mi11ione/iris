// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

@_spi(Validation) import Iris
import Testing

private func decode(_ e: UInt32) -> Instruction {
    Iris.decode(e, at: 0)
}

/// Validates `CryptoAppleExtensionsSemanticChecker.verify(_:)` — the
/// independent reads/writes/flags/memory-access oracle for every
/// crypto/Apple-extensions tier (PAC standalone, MTE DPR/DPI/L-S, crypto,
/// AMX) — agreement with the decoder on real records, every
/// field-mismatch arm, and the operand→mask helper edges.
@Suite("Crypto+Apple extensions / Semantic attribute checker")
struct CryptoAppleExtensionsSemanticAttributesTests {
    @Test func verifyAgreesWithTheDecoderAcrossEveryTier() {
        let rows: [(word: UInt32, mnemonic: Mnemonic)] = [
            // PAC standalone: register-source sign/auth, zero-source
            // sign/auth, strip, and the 3-operand PACGA.
            (0xDAC1_0020, .pacia), (0xDAC1_1020, .autia),
            (0xDAC1_23E0, .paciza), (0xDAC1_33E0, .autiza),
            (0xDAC1_43E0, .xpaci), (0xDAC1_47E0, .xpacd),
            (0x9AC2_3020, .pacga),
            // MTE DPR (SUBPS is the one NZCV setter in the family).
            (0x9AC2_1020, .irg), (0x9AC2_1420, .gmi),
            (0x9AC2_0020, .subp), (0xBAC2_0020, .subps),
            // MTE DPI.
            (0x9180_0020, .addg), (0xD180_0020, .subg),
            // MTE L/S: tag load, every store form (post-index carries
            // writeback), and the bulk forms.
            (0xD960_0020, .ldg), (0xD920_0420, .stg), (0xD920_0820, .stg),
            (0xD960_0420, .stzg), (0xD9A0_0420, .st2g), (0xD9E0_0C20, .stz2g),
            (0xD9A0_0020, .stgm), (0xD9E0_0020, .ldgm), (0xD920_0020, .stzgm),
            // Crypto: tied destination (AESE), pure output (AESMC),
            // multi-source tied (SHA512H), and the immediate-carrying XAR.
            (0x4E28_48E5, .aese), (0x4E28_68E5, .aesmc),
            (0xCE69_80E5, .sha512h), (0xCE89_00E5, .xar),
            // AMX: documented data op, the X31 form, set/clr, and an
            // undocumented opcode.
            (0x0020_1085, .amxLdz), (0x0020_109F, .amxLdz),
            (0x0020_1220, .amxSet), (0x0020_12E5, .amxUnknownOp),
        ]
        for row in rows {
            let d = decode(row.word)
            #expect(d.mnemonic == row.mnemonic, "0x\(String(row.word, radix: 16))")
            let issue = CryptoAppleExtensionsSemanticChecker.verify(d)
            #expect(issue == nil, "0x\(String(row.word, radix: 16)) (\(d.mnemonic.name)): \(String(describing: issue))")
        }
    }

    @Test func foreignRecordsAreSkipped() {
        // Mnemonics/categories outside every tier return nil untouched.
        let add = decode(0x9100_0420)
        #expect(add.mnemonic == .add)
        #expect(CryptoAppleExtensionsSemanticChecker.verify(add) == nil)
        let nop = decode(0xD503_201F)
        #expect(CryptoAppleExtensionsSemanticChecker.verify(nop) == nil)
    }

    @Test func everyFieldMismatchArmReportsItsIssue() {
        let pacia = decode(0xDAC1_0020)
        #expect(CryptoAppleExtensionsSemanticChecker.verify(
            mutated(pacia, branchClass: .call),
        )?.field == "branchClass")
        #expect(CryptoAppleExtensionsSemanticChecker.verify(
            mutated(pacia, memoryOrdering: [.acquire]),
        )?.field == "memoryOrdering")
        #expect(CryptoAppleExtensionsSemanticChecker.verify(
            mutated(pacia, category: .dataProcessingRegister),
        )?.field == "category")
        #expect(CryptoAppleExtensionsSemanticChecker.verify(
            mutated(pacia, flagEffect: .nzcv),
        )?.field == "flagEffect")
        #expect(CryptoAppleExtensionsSemanticChecker.verify(
            mutated(pacia, semanticWrites: .empty),
        )?.field == "semanticWrites")
        #expect(CryptoAppleExtensionsSemanticChecker.verify(
            mutated(pacia, semanticReads: .empty),
        )?.field == "semanticReads")
        let ldg = decode(0xD960_0020)
        #expect(CryptoAppleExtensionsSemanticChecker.verify(
            mutated(ldg, memoryAccess: .store),
        )?.field == "memoryAccess")
        // The issue value carries the field/actual/expected triple.
        let issue = CryptoAppleExtensionsSemanticChecker.verify(mutated(pacia, flagEffect: .nzcv))
        #expect(issue == CryptoSemanticIssue(
            field: "flagEffect", actual: "\(FlagEffect.nzcv)", expected: "\(FlagEffect.none)",
        ))
    }

    @Test func pacTierReadWriteRulesPerClass() {
        // Register-source sign: reads Rd + Rn, writes Rd.
        let pacia = decode(0xDAC1_0020)
        #expect(pacia.semanticReads.mask == 0b11)
        #expect(pacia.semanticWrites.mask == 0b01)
        // Zero-source and strip forms read only Rd.
        let paciza = decode(0xDAC1_23E0)
        #expect(paciza.semanticReads.mask == 0b01)
        // PACGA x0, x1, x2: Rd is pure output; reads Rn + Rm.
        let pacga = decode(0x9AC2_3020)
        #expect(pacga.semanticReads.mask == 0b110)
        #expect(pacga.semanticWrites.mask == 0b01)
    }

    @Test func pacgaWithZeroRegisterSourceDropsTheBit() {
        // Hand-built PACGA whose Rm is XZR: the zero register contributes
        // no read bit; checker and record agree.
        let d = Instruction(
            mnemonic: .pacga,
            semanticReads: RegisterSet.empty.inserting(.x(1)),
            semanticWrites: RegisterSet.empty.inserting(.x(0)),
            category: .pointerAuthentication,
            operands: [.register(.x(0)), .register(.x(1)), .register(.xzr())],
        )
        #expect(CryptoAppleExtensionsSemanticChecker.verify(d) == nil)
    }

    @Test func shortOperandListsContributeNoMaskBits() {
        // A PACGA record with a truncated operand list: indices 1 and 2
        // are out of range, so the expected reads collapse to empty.
        let d = Instruction(
            mnemonic: .pacga, category: .pointerAuthentication,
            operands: [.register(.x(0))],
        )
        let issue = CryptoAppleExtensionsSemanticChecker.verify(d)
        #expect(issue?.field == "semanticWrites")
        #expect(issue?.expected == "0x1")
        #expect(issue?.actual == "0x0")
    }

    @Test func mteLoadStoreMaskRules() {
        // LDG is a read-modify-write of Rt plus a base read.
        let ldg = decode(0xD960_0020)
        #expect(ldg.semanticReads.mask == 0b11) // x0 (Rt) + x1 (base)
        #expect(ldg.semanticWrites.mask == 0b01)
        // LDGM fully writes Rt; reads only the base.
        let ldgm = decode(0xD9E0_0020)
        #expect(ldgm.semanticReads.mask == 0b10)
        #expect(ldgm.semanticWrites.mask == 0b01)
        // Post-index STG writes back the base.
        let stg = decode(0xD920_0420)
        #expect(stg.semanticWrites.mask == 0b10)
    }

    @Test func mteLoadStoreRecordsWithoutMemoryOperandsStillVerify() {
        // Defensive: hand-built LDG whose operand list carries no memory
        // operand — base mask and writeback collapse to zero.
        let d = Instruction(
            mnemonic: .ldg,
            semanticReads: RegisterSet.empty.inserting(.x(3)),
            semanticWrites: RegisterSet.empty.inserting(.x(3)),
            memoryAccess: .load, category: .memoryTagging,
            operands: [.register(.x(3)), .register(.x(4))],
        )
        #expect(CryptoAppleExtensionsSemanticChecker.verify(d) == nil)
    }

    @Test func mteStoreWithZeroRegisterBaseContributesNoBaseBit() {
        // A `.memory` operand whose base is the zero register (hand-built;
        // real encodings render SP for 31) contributes no base read.
        let mem = MemoryOperand(
            base: .register(.xzr()), index: nil, displacement: 0,
            extend: .none, shift: 0, writeback: .preIndex,
        )
        let d = Instruction(
            mnemonic: .stg,
            semanticReads: RegisterSet.empty.inserting(.x(3)),
            memoryAccess: .store, category: .memoryTagging,
            operands: [.register(.x(3)), .memory(mem)],
        )
        #expect(CryptoAppleExtensionsSemanticChecker.verify(d) == nil)
    }

    @Test func mteStoreWithPCBaseContributesNoBaseBit() {
        // `.pc`-based memory (impossible for MTE in real encodings) is
        // ignored by the base-mask helper rather than misattributed.
        let mem = MemoryOperand(
            base: .pc, index: nil, displacement: 0,
            extend: .none, shift: 0, writeback: .none,
        )
        let d = Instruction(
            mnemonic: .stg,
            semanticReads: RegisterSet.empty.inserting(.x(3)),
            memoryAccess: .store, category: .memoryTagging,
            operands: [.register(.x(3)), .memory(mem)],
        )
        #expect(CryptoAppleExtensionsSemanticChecker.verify(d) == nil)
    }

    @Test func cryptoTiedDestinationIsReadAndWritten() {
        // AESE Vd is both source and destination.
        let aese = decode(0x4E28_48E5)
        let v5 = UInt64(1) << (32 + 5)
        let v7 = UInt64(1) << (32 + 7)
        #expect(aese.semanticReads.mask == (v5 | v7))
        #expect(aese.semanticWrites.mask == v5)
        // AESMC Vd is pure output.
        let aesmc = decode(0x4E28_68E5)
        #expect(aesmc.semanticReads.mask == v7)
        #expect(aesmc.semanticWrites.mask == v5)
    }

    @Test func amxReadRules() {
        // Documented data op reads the X register named by the operand field.
        let ldz = decode(0x0020_1085)
        #expect(ldz.semanticReads.mask == (UInt64(1) << 5))
        // X31 names XZR — no read.
        #expect(decode(0x0020_109F).semanticReads.isEmpty)
        // set/clr (opcode 17) and undocumented opcodes name no register.
        #expect(decode(0x0020_1220).semanticReads.isEmpty)
        #expect(decode(0x0020_12E5).semanticReads.isEmpty)
    }

    @Test func amxRecordWithoutAMXFieldOperandReadsNothing() {
        // Defensive: an `.amx`-category record whose first operand is not
        // `.amxField` contributes no expected reads.
        let d = Instruction(
            mnemonic: .amxLdz, category: .amx,
            operands: [.register(.x(5))],
        )
        #expect(CryptoAppleExtensionsSemanticChecker.verify(d) == nil)
    }

    @Test func cryptoSemanticIssuePublicInit() {
        let issue = CryptoSemanticIssue(field: "f", actual: "a", expected: "e")
        #expect(issue.field == "f")
        #expect(issue.actual == "a")
        #expect(issue.expected == "e")
        #expect(issue == CryptoSemanticIssue(field: "f", actual: "a", expected: "e"))
    }
}
