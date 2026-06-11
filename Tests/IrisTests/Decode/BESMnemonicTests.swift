// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the BES mnemonic allocation against its declared table:
/// every static constant has the declared raw value, every raw value
/// falls within the BES reservation (1024..2047 per Mnemonic.swift's
/// `allocations`), and no two BES mnemonics share a raw value.
@Suite("BES / Mnemonic constants")
struct BESMnemonicTests {
    /// Source-of-truth mapping — every named BES mnemonic
    /// + its declared raw value. Used by the uniqueness + range tests
    /// below; also pins every constant individually.
    private static let besMnemonics: [(String, Mnemonic, UInt16)] = [
        ("b", .b, 1024), ("bl", .bl, 1025),
        ("cbz", .cbz, 1026), ("cbnz", .cbnz, 1027),
        ("tbz", .tbz, 1028), ("tbnz", .tbnz, 1029),
        ("bCond", .bCond, 1030), ("bcCond", .bcCond, 1031),
        ("svc", .svc, 1032), ("hvc", .hvc, 1033),
        ("smc", .smc, 1034), ("brk", .brk, 1035), ("hlt", .hlt, 1036),
        ("dcps1", .dcps1, 1037), ("dcps2", .dcps2, 1038), ("dcps3", .dcps3, 1039),
        ("br", .br, 1040), ("blr", .blr, 1041), ("ret", .ret, 1042),
        ("eret", .eret, 1043), ("drps", .drps, 1044),
        ("braa", .braa, 1045), ("brab", .brab, 1046),
        ("braaz", .braaz, 1047), ("brabz", .brabz, 1048),
        ("blraa", .blraa, 1049), ("blrab", .blrab, 1050),
        ("blraaz", .blraaz, 1051), ("blrabz", .blrabz, 1052),
        ("retaa", .retaa, 1053), ("retab", .retab, 1054),
        ("eretaa", .eretaa, 1055), ("eretab", .eretab, 1056),
        ("nop", .nop, 1057), ("yield", .yield, 1058),
        ("wfe", .wfe, 1059), ("wfi", .wfi, 1060),
        ("sev", .sev, 1061), ("sevl", .sevl, 1062),
        ("dgh", .dgh, 1063), ("csdb", .csdb, 1064),
        ("esb", .esb, 1065), ("psb", .psb, 1066),
        ("tsb", .tsb, 1067), ("gcsbDsync", .gcsbDsync, 1068),
        ("xpaclri", .xpaclri, 1069),
        ("pacia1716", .pacia1716, 1070), ("pacib1716", .pacib1716, 1071),
        ("autia1716", .autia1716, 1072), ("autib1716", .autib1716, 1073),
        ("paciaz", .paciaz, 1074), ("paciasp", .paciasp, 1075),
        ("pacibz", .pacibz, 1076), ("pacibsp", .pacibsp, 1077),
        ("autiaz", .autiaz, 1078), ("autiasp", .autiasp, 1079),
        ("autibz", .autibz, 1080), ("autibsp", .autibsp, 1081),
        ("bti", .bti, 1082),
        ("chkfeat", .chkfeat, 1083), ("clrbhb", .clrbhb, 1084),
        ("hint", .hint, 1085),
        ("clrex", .clrex, 1086), ("dsb", .dsb, 1087),
        ("dmb", .dmb, 1088), ("isb", .isb, 1089),
        ("sb", .sb, 1090), ("ssbb", .ssbb, 1091),
        ("pssbb", .pssbb, 1092),
        ("msr", .msr, 1093), ("mrs", .mrs, 1094),
        ("cfinv", .cfinv, 1095), ("xaflag", .xaflag, 1096),
        ("axflag", .axflag, 1097),
        ("sys", .sys, 1098), ("sysl", .sysl, 1099),
        ("msrImm", .msrImm, 1100),
        ("wfet", .wfet, 1101), ("wfit", .wfit, 1102),
    ]

    @Test func everyMnemonicHasDeclaredRawValue() {
        for (name, mnemonic, expected) in Self.besMnemonics {
            #expect(mnemonic.rawValue == expected, "\(name) expected raw \(expected)")
        }
    }

    @Test func everyMnemonicIsInBesAllocationRange() {
        for (name, mnemonic, _) in Self.besMnemonics {
            #expect((1024 ... 2047).contains(mnemonic.rawValue), "\(name) out of range")
        }
    }

    @Test func allRawValuesAreUnique() {
        let rawValues = Self.besMnemonics.map(\.2)
        #expect(rawValues.count == Set(rawValues).count)
    }

    @Test func mnemonicCountMatchesTheCommittedTable() {
        // The BES family commits to 79 mnemonics (slots 1024..1102
        // inclusive); this table mirrors the declarations one-for-one.
        #expect(Self.besMnemonics.count == 79)
    }

    @Test func mnemonicAllocationTableContainsBes() {
        // Mnemonic.allocations includes the BES entry.
        let bes = Mnemonic.allocations.first { $0.label == "Branches, Exception, System" }
        #expect(bes != nil)
        #expect(bes?.range == (1024 ... 2047))
    }

    @Test func mnemonicEquality() {
        // Same raw value → equal.
        #expect(Mnemonic.b == Mnemonic(rawValue: 1024))
        #expect(Mnemonic.ret != Mnemonic.retaa)
    }
}
