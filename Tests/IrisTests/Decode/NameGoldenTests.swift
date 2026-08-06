// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Spot table for `Mnemonic.name`.
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
        #expect(Mnemonic.add.name == "add")
        #expect(Mnemonic.b.name == "b")
        #expect(Mnemonic.ldp.name == "ldp")
        #expect(Mnemonic.csel.name == "csel")
        #expect(Mnemonic.fmov.name == "fmov")
        #expect(Mnemonic.pacia.name == "pacia")
        #expect(Mnemonic.amxLdx.name == "ldx")
    }

    @Test func unallocatedRawValuesFallBackTotally() {
        #expect(Mnemonic(rawValue: 200).name == "?200")
        #expect(Mnemonic(rawValue: 999).name == "?999")
        #expect(Mnemonic(rawValue: 50000).name == "?50000")
        #expect(Mnemonic(rawValue: 65535).name == "?65535")
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

/// Spot table for `RegisterRef.name`.
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
