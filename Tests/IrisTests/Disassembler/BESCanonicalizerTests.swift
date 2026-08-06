// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func canonical(_ encoding: UInt32) -> String {
    let draft = decode(encoding, at: 0)
    return draft.text
}

private func canonicalDraft(_ mnemonic: Mnemonic, operands: [Operand] = []) -> String {
    let draft = Instruction(
        address: 0,
        encoding: 0,
        mnemonic: mnemonic,
        category: .branchesExceptionSystem,
        operands: operands,
    )
    return draft.text
}

/// Validates `BESCanonicalizer.format(draft:)` against llvm-mc-equivalent text
/// at the parity mattr.
@Suite("BES / BESCanonicalizer text rendering")
struct BESCanonicalizerTests {
    @Test func undefinedRendersLongDirective() {
        let undef = Instruction(address: 0, encoding: 0xFFFF_FFFF, mnemonic: .undefined, category: .undefined)
        #expect(undef.isUndefined)
        #expect(undef.text == ".long 0xffffffff")
        let armed = Instruction(address: 0, encoding: 0, mnemonic: .undefined, category: .branchesExceptionSystem)
        #expect(armed.text == "")
    }

    @Test func bZeroAndOffsets() {
        #expect(canonical(0x1400_0000) == "b #0")
        #expect(canonical(0x1400_0001) == "b #4")
        #expect(canonical(0x17FF_FFFF) == "b #-4")
    }

    @Test func blZeroAndOffsets() {
        #expect(canonical(0x9400_0000) == "bl #0")
        #expect(canonical(0x9400_0001) == "bl #4")
    }

    @Test func bCondAllCondNames() {
        let cases: [(UInt32, String)] = [
            (0x5400_0000, "b.eq #0"),
            (0x5400_0001, "b.ne #0"),
            (0x5400_0002, "b.hs #0"),
            (0x5400_0003, "b.lo #0"),
            (0x5400_0004, "b.mi #0"),
            (0x5400_0005, "b.pl #0"),
            (0x5400_0006, "b.vs #0"),
            (0x5400_0007, "b.vc #0"),
            (0x5400_0008, "b.hi #0"),
            (0x5400_0009, "b.ls #0"),
            (0x5400_000A, "b.ge #0"),
            (0x5400_000B, "b.lt #0"),
            (0x5400_000C, "b.gt #0"),
            (0x5400_000D, "b.le #0"),
            (0x5400_000E, "b.al #0"),
            (0x5400_000F, "b.nv #0"),
        ]
        for (enc, text) in cases {
            #expect(canonical(enc) == text)
        }
    }

    @Test func bcCondRenders() {
        #expect(canonical(0x5400_0010) == "bc.eq #0")
    }

    @Test func cbzCbnzRender() {
        #expect(canonical(0x3400_0000) == "cbz w0, #0")
        #expect(canonical(0xB400_001E) == "cbz x30, #0")
        #expect(canonical(0x3500_0001) == "cbnz w1, #0")
        #expect(canonical(0xB500_000F) == "cbnz x15, #0")
    }

    @Test func tbzTbnzRender() {
        #expect(canonical(0x3600_0000) == "tbz w0, #0, #0")
        #expect(canonical(0xB600_0000) == "tbz x0, #32, #0")
        #expect(canonical(0x3700_0000) == "tbnz w0, #0, #0")
    }

    @Test func exceptionImmZeroDecimal() {
        #expect(canonical(0xD400_0001) == "svc #0")
        #expect(canonical(0xD400_0002) == "hvc #0")
        #expect(canonical(0xD400_0003) == "smc #0")
        #expect(canonical(0xD420_0000) == "brk #0")
        #expect(canonical(0xD440_0000) == "hlt #0")
    }

    @Test func exceptionImmNonZeroHex() {
        #expect(canonical(0xD420_5540) == "brk #0x2aa")
        #expect(canonical(0xD400_0021) == "svc #0x1")
    }

    @Test func udfImm16Decimal() {
        #expect(canonical(0x0000_0000) == "udf #0")
        #expect(canonical(0x0000_0001) == "udf #1")
        #expect(canonical(0x0000_0010) == "udf #16")
        #expect(canonical(0x0000_1234) == "udf #4660")
        #expect(canonical(0x0000_ABCD) == "udf #43981")
        #expect(canonical(0x0000_FFFF) == "udf #65535")
    }

    @Test func dcpsBareWhenImmZero() {
        #expect(canonical(0xD4A0_0001) == "dcps1")
        #expect(canonical(0xD4A0_0002) == "dcps2")
        #expect(canonical(0xD4A0_0003) == "dcps3")
    }

    @Test func dcpsImmNonZeroHex() {
        #expect(canonical(0xD4A0_0021) == "dcps1 #0x1")
    }

    @Test func brBlrRet() {
        #expect(canonical(0xD61F_0000) == "br x0")
        #expect(canonical(0xD63F_0000) == "blr x0")
        #expect(canonical(0xD65F_03C0) == "ret")
        #expect(canonical(0xD65F_01E0) == "ret x15")
    }

    @Test func eretAndDrps() {
        #expect(canonical(0xD69F_03E0) == "eret")
        #expect(canonical(0xD6BF_03E0) == "drps")
    }

    @Test func authBranchTwoOperand() {
        #expect(canonical(0xD71F_0A11) == "braa x16, x17")
        #expect(canonical(0xD71F_0E11) == "brab x16, x17")
        #expect(canonical(0xD73F_0A11) == "blraa x16, x17")
        #expect(canonical(0xD73F_0E11) == "blrab x16, x17")
        #expect(canonical(0xD71F_0A1F) == "braa x16, sp")
    }

    @Test func authBranchZeroForm() {
        #expect(canonical(0xD61F_0A1F) == "braaz x16")
        #expect(canonical(0xD61F_0E1F) == "brabz x16")
        #expect(canonical(0xD63F_0A1F) == "blraaz x16")
        #expect(canonical(0xD63F_0E1F) == "blrabz x16")
    }

    @Test func authReturn() {
        #expect(canonical(0xD65F_0BFF) == "retaa")
        #expect(canonical(0xD65F_0FFF) == "retab")
        #expect(canonical(0xD69F_0BFF) == "eretaa")
        #expect(canonical(0xD69F_0FFF) == "eretab")
    }

    @Test func namedHints() {
        #expect(canonical(0xD503_201F) == "nop")
        #expect(canonical(0xD503_203F) == "yield")
        #expect(canonical(0xD503_205F) == "wfe")
        #expect(canonical(0xD503_207F) == "wfi")
        #expect(canonical(0xD503_209F) == "sev")
        #expect(canonical(0xD503_20BF) == "sevl")
        #expect(canonical(0xD503_20DF) == "dgh")
        #expect(canonical(0xD503_20FF) == "xpaclri")
    }

    @Test func pacNamedHints() {
        #expect(canonical(0xD503_211F) == "pacia1716")
        #expect(canonical(0xD503_215F) == "pacib1716")
        #expect(canonical(0xD503_219F) == "autia1716")
        #expect(canonical(0xD503_21DF) == "autib1716")
        #expect(canonical(0xD503_231F) == "paciaz")
        #expect(canonical(0xD503_233F) == "paciasp")
        #expect(canonical(0xD503_235F) == "pacibz")
        #expect(canonical(0xD503_237F) == "pacibsp")
        #expect(canonical(0xD503_239F) == "autiaz")
        #expect(canonical(0xD503_23BF) == "autiasp")
        #expect(canonical(0xD503_23DF) == "autibz")
        #expect(canonical(0xD503_23FF) == "autibsp")
    }

    @Test func psbTsbCsdb() {
        #expect(canonical(0xD503_221F) == "esb")
        #expect(canonical(0xD503_223F) == "psb csync")
        #expect(canonical(0xD503_225F) == "tsb csync")
        #expect(canonical(0xD503_229F) == "csdb")
    }

    @Test func btiVariants() {
        #expect(canonical(0xD503_241F) == "bti r")
        #expect(canonical(0xD503_245F) == "bti c")
        #expect(canonical(0xD503_249F) == "bti j")
        #expect(canonical(0xD503_24DF) == "bti jc")
    }

    @Test func unknownHintRendersGenerically() {
        #expect(canonical(0xD503_281F) == "hint #64")
    }

    @Test func dsbNamedOptions() {
        #expect(canonical(0xD503_3F9F) == "dsb sy")
        #expect(canonical(0xD503_3B9F) == "dsb ish")
    }

    @Test func dsbReservedCRmGenericImmediate() {
        #expect(canonical(0xD503_389F) == "dsb #8")
        #expect(canonical(0xD503_3C9F) == "dfb")
    }

    @Test func ssbbAndPssbb() {
        #expect(canonical(0xD503_309F) == "ssbb")
        #expect(canonical(0xD503_349F) == "pssbb")
    }

    @Test func dmbNamedAndReserved() {
        #expect(canonical(0xD503_3FBF) == "dmb sy")
        #expect(canonical(0xD503_34BF) == "dmb #4")
    }

    @Test func isbAndClrex() {
        #expect(canonical(0xD503_3FDF) == "isb")
        #expect(canonical(0xD503_30DF) == "isb #0")
        #expect(canonical(0xD503_3F5F) == "clrex")
        #expect(canonical(0xD503_305F) == "clrex #0")
    }

    @Test func sb() {
        #expect(canonical(0xD503_30FF) == "sb")
    }

    @Test func dsbNxsNamedForms() {
        #expect(canonical(0xD503_323F) == "dsb oshnxs")
        #expect(canonical(0xD503_363F) == "dsb nshnxs")
        #expect(canonical(0xD503_3A3F) == "dsb ishnxs")
        #expect(canonical(0xD503_3E3F) == "dsb synxs")
    }

    @Test func cfinvXaflagAxflag() {
        #expect(canonical(0xD500_401F) == "cfinv")
        #expect(canonical(0xD500_403F) == "xaflag")
        #expect(canonical(0xD500_405F) == "axflag")
    }

    @Test func msrImmNamedFields() {
        #expect(canonical(0xD500_40BF) == "msr spsel, #0")
        #expect(canonical(0xD503_40DF) == "msr daifset, #0")
        #expect(canonical(0xD503_40FF) == "msr daifclr, #0")
        #expect(canonical(0xD500_407F) == "msr uao, #0")
        #expect(canonical(0xD500_409F) == "msr pan, #0")
        #expect(canonical(0xD503_405F) == "msr dit, #0")
        #expect(canonical(0xD503_409F) == "msr tco, #0")
        #expect(canonical(0xD503_403F) == "msr ssbs, #0")
    }

    @Test func msrImmFallbackSform() {
        #expect(canonical(0xD502_435F) == "msr s0_2_c4_c3_2, xzr")
    }

    @Test func mrsNamedRegisters() {
        #expect(canonical(0xD53B_D040) == "mrs x0, tpidr_el0")
        #expect(canonical(0xD53B_D060) == "mrs x0, tpidrro_el0")
        #expect(canonical(0xD53B_E040) == "mrs x0, cntvct_el0")
        #expect(canonical(0xD53B_E020) == "mrs x0, cntpct_el0")
        #expect(canonical(0xD53B_E0C0) == "mrs x0, cntvctss_el0")
        #expect(canonical(0xD53B_42A8) == "mrs x8, dit")
    }

    @Test func msrNamedRegisters() {
        #expect(canonical(0xD51B_D040) == "msr tpidr_el0, x0")
        #expect(canonical(0xD51B_D060) == "msr tpidrro_el0, x0")
    }

    @Test func msrToReadOnlyFallsBackToSform() {
        #expect(canonical(0xD518_0000) == "msr s3_0_c0_c0_0, x0")
        #expect(canonical(0xD51B_E020) == "msr s3_3_c14_c0_1, x0")
        #expect(canonical(0xD51B_E040) == "msr s3_3_c14_c0_2, x0")
    }

    @Test func mrsUnknownSysregSform() {
        #expect(canonical(0xD53F_FFE0) == "mrs x0, s3_7_c15_c15_7")
    }

    @Test func appleImpdefSysregSform() {
        #expect(canonical(0xD538_B020) == "mrs x0, s3_0_c11_c0_1")
        #expect(canonical(0xD51B_F3E5) == "msr s3_3_c15_c3_7, x5")
    }

    @Test func sysNamedAliases() {
        #expect(canonical(0xD508_711F) == "ic ialluis")
        #expect(canonical(0xD50B_7A25) == "dc cvac, x5")
        #expect(canonical(0xD508_8321) == "tlbi vae1is, x1")
        #expect(canonical(0xD508_871F) == "tlbi vmalle1")
        #expect(canonical(0xD508_8705) == "sys #0, c8, c7, #0, x5")
    }

    @Test func sysGenericFallback() {
        #expect(canonical(0xD509_2380) == "sys #1, c2, c3, #4, x0")
        #expect(canonical(0xD509_239F) == "sys #1, c2, c3, #4")
    }

    @Test func syslGenericRendering() {
        #expect(canonical(0xD52B_7C20) == "sysl x0, #3, c7, c12, #1")
    }

    @Test func wfetWfit() {
        #expect(canonical(0xD503_1000) == "wfet x0")
        #expect(canonical(0xD503_1021) == "wfit x1")
        #expect(canonical(0xD503_101F) == "wfet xzr")
    }

    @Test func formatDraftDirect() {
        let draft = Instruction(
            address: 0,
            encoding: 0x1400_0000,
            mnemonic: .b,
            branchClass: .direct,
            category: .branchesExceptionSystem,
            operands: [.label(byteOffset: 16)],
        )
        #expect(draft.text == "b #16")
    }

    @Test func bcCondDraftWithoutOperandsRendersSafely() {
        let draft = Instruction(
            address: 0,
            encoding: 0,
            mnemonic: .bcCond,
            category: .branchesExceptionSystem,
        )
        #expect(draft.text.hasPrefix("?"))
    }

    @Test func unrecognisedMnemonicRendersWithRawValue() {
        let draft = Instruction(
            address: 0,
            encoding: 0,
            mnemonic: .add,
            category: .branchesExceptionSystem,
        )
        let text = draft.text
        #expect(text == "?\(Mnemonic.add.rawValue)")
    }

    @Test func authBranchWithoutEnoughOperandsRendersSentinel() {
        let braaNoOps = Instruction(
            address: 0, encoding: 0, mnemonic: .braa,
            category: .branchesExceptionSystem,
            operands: [],
        )
        #expect(braaNoOps.text == "?braa")
    }

    @Test func authBranchZeroWithoutOperandsRendersSentinel() {
        let braazNoOps = Instruction(
            address: 0, encoding: 0, mnemonic: .braaz,
            category: .branchesExceptionSystem,
            operands: [],
        )
        #expect(braazNoOps.text == "?braaz")
    }

    @Test func brWithLabelOperandRendersSentinel() {
        let bad = Instruction(
            address: 0, encoding: 0, mnemonic: .br,
            category: .branchesExceptionSystem,
            operands: [.label(byteOffset: 0)],
        )
        #expect(bad.text == "?br")
    }

    @Test func dsbWithoutOperandsRendersBare() {
        let bare = Instruction(
            address: 0, encoding: 0, mnemonic: .dsb,
            category: .branchesExceptionSystem,
            operands: [],
        )
        #expect(bare.text == "dsb")
    }

    @Test func dsbWithBogusOperandRendersSentinel() {
        let bogus = Instruction(
            address: 0, encoding: 0, mnemonic: .dsb,
            category: .branchesExceptionSystem,
            operands: [.label(byteOffset: 0)],
        )
        #expect(bogus.text == "dsb ?")
    }

    @Test func dsbNxsImmediateOutsideKnownCRm() {
        let weird = Instruction(
            address: 0, encoding: 0, mnemonic: .dsb,
            category: .branchesExceptionSystem,
            operands: [.unsignedImmediate(value: 0x18, width: 5)],
        )
        #expect(weird.text == "dsb #24")
    }

    @Test func operandRegisterHelperReturnsXzrOnBadShape() {
        let badTbz = Instruction(
            address: 0, encoding: 0, mnemonic: .tbz,
            category: .branchesExceptionSystem,
            operands: [
                .label(byteOffset: 0),
                .unsignedImmediate(value: 0, width: 6),
                .label(byteOffset: 0),
            ],
        )
        #expect(badTbz.text == "tbz xzr, #0, #0")
    }

    @Test func registerTextForEncoded31GeneralRoleFallsBackToXzr() {
        let weirdReg = RegisterRef(canonicalIndex: 31, role: .general, width: .x64)
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .br,
            category: .branchesExceptionSystem,
            operands: [.register(weirdReg)],
        )
        #expect(draft.text == "br xzr")
    }

    @Test func registerTextForEncoded31GeneralRoleW32FallsBackToWzr() {
        let weirdReg = RegisterRef(canonicalIndex: 31, role: .general, width: .w32)
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .tbz,
            category: .branchesExceptionSystem,
            operands: [
                .register(weirdReg),
                .unsignedImmediate(value: 0, width: 6),
                .label(byteOffset: 0),
            ],
        )
        #expect(draft.text == "tbz wzr, #0, #0")
    }

    @Test func registerTextForSimdRegister() {
        let v5 = RegisterRef.simd(5)
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .br,
            category: .branchesExceptionSystem,
            operands: [.register(v5)],
        )
        #expect(draft.text == "br v5")
    }

    @Test func registerTextForOutOfRangeRendersSentinel() {
        let bogus = RegisterRef(canonicalIndex: 100, role: .general, width: .x64)
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .br,
            category: .branchesExceptionSystem,
            operands: [.register(bogus)],
        )
        #expect(draft.text == "br ?100")
    }

    @Test func malformedOperandShapesHitDefensiveSentinels() {
        #expect(canonicalDraft(.bCond, operands: [.label(byteOffset: 0), .label(byteOffset: 0)])
            == "?b.cond")
        #expect(canonicalDraft(.msr, operands: [.register(.x(0)), .register(.x(1))]) == "?msr")
        #expect(canonicalDraft(.mrs, operands: [.label(byteOffset: 0), .systemRegister(.init(packed: 0))]) == "?mrs")
        #expect(canonicalDraft(.msrImm, operands: [.register(.x(0))]) == "?msrImm")
        #expect(canonicalDraft(.sys, operands: [.label(byteOffset: 0)]) == "?sys")
        #expect(canonicalDraft(.sysl, operands: [.label(byteOffset: 0)]) == "?sysl")
        #expect(canonicalDraft(.b, operands: [.register(.x(0))]) == "b ?label")
    }

    @Test func explicitBtiImmediateForms() {
        #expect(canonicalDraft(.bti, operands: [.unsignedImmediate(value: 0, width: 2)]) == "bti r")
        #expect(canonicalDraft(.bti, operands: [.unsignedImmediate(value: 4, width: 3)]) == "bti #4")
    }

    @Test func unsignedImmediateHelperAcceptsSignedAndFallbackOperands() {
        #expect(canonicalDraft(.hint, operands: [.immediate(value: 7, width: 7)]) == "hint #7")
        #expect(canonicalDraft(.hint, operands: [.label(byteOffset: 12)]) == "hint #0")
    }

    @Test func registerTextForWspAndWzr() {
        #expect(canonicalDraft(.br, operands: [.register(.wsp())]) == "br wsp")
        #expect(canonicalDraft(.br, operands: [.register(.wzr())]) == "br wzr")
    }

    @Test func remainingBareMnemonicNames() {
        #expect(canonicalDraft(.gcsbDsync) == "gcsb dsync")
        #expect(canonicalDraft(.chkfeat) == "chkfeat x16")
        #expect(canonicalDraft(.clrbhb) == "clrbhb")
    }

    @Test func barrierOptionNamesCoverEveryCase() {
        let cases: [(BarrierOption, String)] = [
            (.oshld, "oshld"),
            (.oshst, "oshst"),
            (.osh, "osh"),
            (.nshld, "nshld"),
            (.nshst, "nshst"),
            (.nsh, "nsh"),
            (.ishld, "ishld"),
            (.ishst, "ishst"),
            (.ld, "ld"),
            (.st, "st"),
        ]
        for (option, text) in cases {
            #expect(canonicalDraft(.dsb, operands: [.barrierOption(option)]) == "dsb \(text)")
        }
    }

    @Test func pstateAllIntAndUnknownNames() {
        #expect(canonicalDraft(.msrImm, operands: [
            .pstateField(.allInt),
            .unsignedImmediate(value: 1, width: 4),
        ]) == "msr allint, #1")
        #expect(canonicalDraft(.msrImm, operands: [
            .pstateField(.unknown(op1: 5, op2: 3)),
            .unsignedImmediate(value: 2, width: 4),
        ]) == "msr pstate5_3, #2")
    }

    @Test func remainingSystemRegisterNames() {
        let readable: [(SystemRegisterEncoding, String)] = [
            (.init(op0: 3, op1: 3, crn: 4, crm: 2, op2: 0), "nzcv"),
            (.init(op0: 3, op1: 3, crn: 4, crm: 4, op2: 0), "fpcr"),
            (.init(op0: 3, op1: 3, crn: 4, crm: 4, op2: 1), "fpsr"),
            (.init(op0: 3, op1: 3, crn: 14, crm: 0, op2: 5), "cntpctss_el0"),
        ]
        for (sysreg, text) in readable {
            #expect(canonicalDraft(.mrs, operands: [.register(.x(0)), .systemRegister(sysreg)])
                == "mrs x0, \(text)")
        }

        let sctlr = SystemRegisterEncoding(op0: 3, op1: 0, crn: 1, crm: 0, op2: 0)
        #expect(canonicalDraft(.msr, operands: [.systemRegister(sctlr), .register(.x(0))])
            == "msr sctlr_el1, x0")
    }

    @Test func malformedOperandListsRenderTheGuardSentinel() {
        for m: Mnemonic in [.b, .bl, .cbz, .cbnz, .tbz, .tbnz, .svc, .hvc,
                            .dcps1, .hint, .smstart, .smstop, .wfet, .wfit, .cbgt, .cbbeq, .cbhne,
                            .udf]
        {
            #expect(canonicalDraft(m) == "?\(m.name)", "\(m.name)")
        }
        #expect(canonicalDraft(.sysp) == "?sysp")
        #expect(canonicalDraft(.sysp, operands: [.register(.x(0))]) == "?sysp")
        #expect(canonicalDraft(.mrrs) == "?mrrs")
        #expect(canonicalDraft(.mrrs, operands: [.register(.x(0)), .register(.x(1)), .register(.x(2))]) == "?mrrs")
        #expect(canonicalDraft(.msrr) == "?msrr")
        #expect(canonicalDraft(.msrr, operands: [.register(.x(0)), .register(.x(1)), .register(.x(2))]) == "?msrr")
    }

    @Test func misshapenOperandListsForTheNewFormsRenderTheSentinel() {
        #expect(canonicalDraft(.retaasppcr) == "?retaasppcr")
        #expect(canonicalDraft(.retabsppcr, operands: [.label(byteOffset: 4)]) == "?retabsppcr")
        #expect(canonicalDraft(.retaasppc) == "?retaasppc")
        #expect(canonicalDraft(.retabsppc, operands: [.register(.x(1))]) == "?retabsppc")
        #expect(canonicalDraft(.tenter) == "?tenter")
        #expect(canonicalDraft(.shuh) == "?shuh")
        #expect(canonicalDraft(.tchangef, operands: [.register(.x(1))]) == "?tchangef")
        #expect(canonicalDraft(.tchangebNb, operands: [.label(byteOffset: 0), .register(.x(1))]) == "?tchangeb")
        #expect(canonicalDraft(.stshh) == "stshh")
        #expect(canonicalDraft(.bti) == "bti")
    }

    @Test func explicitNewHintAndTIndexOperandForms() {
        #expect(canonicalDraft(.stshh, operands: [.unsignedImmediate(value: 6, width: 3)]) == "stshh #6")
        #expect(canonicalDraft(.shuh, operands: [.unsignedImmediate(value: 0, width: 3)]) == "shuh")
        #expect(canonicalDraft(.tenterNb, operands: [.unsignedImmediate(value: 3, width: 7)]) == "tenter #3, nb")
        #expect(canonicalDraft(.pacm) == "pacm")
        #expect(canonicalDraft(.stcph) == "stcph")
        #expect(canonicalDraft(.dfb) == "dfb")
        #expect(canonicalDraft(.texit) == "texit")
        #expect(canonicalDraft(.texitNb) == "texit nb")
    }
}
