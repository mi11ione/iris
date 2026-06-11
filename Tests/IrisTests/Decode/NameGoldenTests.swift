// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Spot table for `Mnemonic.name` and its CustomStringConvertible
/// conformance: sentinels, composites, real names from every family
/// range, and the total `?<raw>` fallback for unallocated values.
@Suite("Mnemonic / name spot table")
struct MnemonicNameGoldenTests {
    @Test func sentinelNamesAreCensusLabels() {
        #expect(Mnemonic.undefined.name == "undefined")
        #expect(Mnemonic.dataMarker.name == "data")
        #expect(Mnemonic.truncatedTail.name == "truncated")
        #expect(Mnemonic.udf.name == "udf")
        #expect(Mnemonic.amxUnknownOp.name == "amx-unknown")
    }

    @Test func compositesUseTheirManualSpellingLowercased() {
        #expect(Mnemonic.bCond.name == "b.cond")
        #expect(Mnemonic.bcCond.name == "bc.cond")
        #expect(Mnemonic.msrImm.name == "msr")
    }

    @Test func everyFamilyRangeResolvesRealNames() {
        #expect(Mnemonic.add.name == "add") //     DPI
        #expect(Mnemonic.b.name == "b") //         BES
        #expect(Mnemonic.ldp.name == "ldp") //     L/S
        #expect(Mnemonic.csel.name == "csel") //   DPR
        #expect(Mnemonic.fmov.name == "fmov") //   SIMD/FP
        #expect(Mnemonic.pacia.name == "pacia") // crypto/PAC
        #expect(Mnemonic.amxLdx.name == "ldx") //  AMX
    }

    @Test func unallocatedRawValuesFallBackTotally() {
        #expect(Mnemonic(rawValue: 200).name == "?200") //     sentinel range, unallocated
        #expect(Mnemonic(rawValue: 999).name == "?999") //     DPI range, unallocated
        #expect(Mnemonic(rawValue: 16500).name == "?16500") // future-extensions range
        #expect(Mnemonic(rawValue: 65535).name == "?65535") // reserved sentinel
    }

    @Test func descriptionMatchesName() {
        #expect(Mnemonic.add.description == "add")
        #expect("\(Mnemonic.bCond)" == "b.cond")
        #expect("\(Mnemonic.undefined)" == "undefined")
    }

    @Test func decodedMnemonicsCarryTheirNames() {
        #expect(decode(0xD503_201F).mnemonic.name == "nop")
        #expect(decode(0x9400_0001).mnemonic.name == "bl")
    }
}

/// Spot table for `RegisterRef.name` and its CustomStringConvertible
/// conformance: the canonical register names, the W-width policy, the
/// encoding-31 roles, vector names, and the `?<index>` fallback.
@Suite("RegisterRef / name spot table")
struct RegisterRefNameGoldenTests {
    @Test func generalPurposeNamesFollowWidth() {
        #expect(RegisterRef.x(0).name == "x0")
        #expect(RegisterRef.x(30).name == "x30")
        #expect(RegisterRef.w(7).name == "w7")
        #expect(RegisterRef.w(0).name == "w0")
    }

    @Test func encoding31RolesDisambiguate() {
        #expect(RegisterRef.sp().name == "sp")
        #expect(RegisterRef.wsp().name == "wsp")
        #expect(RegisterRef.xzr().name == "xzr")
        #expect(RegisterRef.wzr().name == "wzr")
        // A .general-role reference at the encoding-31 slot names the
        // zero register — the architectural meaning of encoding 31 in a
        // register-operand position.
        #expect(RegisterRef.x(31).name == "xzr")
        #expect(RegisterRef.w(31).name == "wzr")
    }

    @Test func vectorRegisterNames() {
        #expect(RegisterRef.simd(0).name == "v0")
        #expect(RegisterRef.simd(31).name == "v31")
    }

    @Test func impossibleIndicesFallBackTotally() {
        let synthetic = RegisterRef(canonicalIndex: 100, role: .general, width: .x64)
        #expect(synthetic.name == "?100")
    }

    @Test func descriptionMatchesName() {
        #expect(RegisterRef.x(5).description == "x5")
        #expect("\(RegisterRef.sp())" == "sp")
        #expect("\(RegisterRef.simd(31))" == "v31")
    }
}
