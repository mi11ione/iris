// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Mnemonic constants for the Branches, Exception, System
// family. Raw values 1024..1102 within the family's reserved 1024..2047
// slab. Mnemonics are grouped contiguously per sub-family so the
// per-family classification helpers (BESMnemonicAttributes) become
// branch-predictable table lookups. 79 mnemonics populate
// 1024..1102 inclusive; slots 1103..2047 stay free for future expansion.

public extension Mnemonic {
    // Branch immediate (1024..1025)
    static let b = Mnemonic(rawValue: 1024)
    static let bl = Mnemonic(rawValue: 1025)

    // Compare-and-branch (1026..1027)
    static let cbz = Mnemonic(rawValue: 1026)
    static let cbnz = Mnemonic(rawValue: 1027)

    // Test-and-branch (1028..1029)
    static let tbz = Mnemonic(rawValue: 1028)
    static let tbnz = Mnemonic(rawValue: 1029)

    // Conditional branch (1030..1031). bCond carries the condition code as
    // the first operand; bcCond is the FEAT_HBC variant (BC.cond).
    static let bCond = Mnemonic(rawValue: 1030)
    static let bcCond = Mnemonic(rawValue: 1031)

    // Exception generation (1032..1039)
    static let svc = Mnemonic(rawValue: 1032)
    static let hvc = Mnemonic(rawValue: 1033)
    static let smc = Mnemonic(rawValue: 1034)
    static let brk = Mnemonic(rawValue: 1035)
    static let hlt = Mnemonic(rawValue: 1036)
    static let dcps1 = Mnemonic(rawValue: 1037)
    static let dcps2 = Mnemonic(rawValue: 1038)
    static let dcps3 = Mnemonic(rawValue: 1039)

    // Branch register — regular (1040..1044)
    static let br = Mnemonic(rawValue: 1040)
    static let blr = Mnemonic(rawValue: 1041)
    static let ret = Mnemonic(rawValue: 1042)
    static let eret = Mnemonic(rawValue: 1043)
    static let drps = Mnemonic(rawValue: 1044)

    // Branch register — ARM64E auth (1045..1056)
    static let braa = Mnemonic(rawValue: 1045)
    static let brab = Mnemonic(rawValue: 1046)
    static let braaz = Mnemonic(rawValue: 1047)
    static let brabz = Mnemonic(rawValue: 1048)
    static let blraa = Mnemonic(rawValue: 1049)
    static let blrab = Mnemonic(rawValue: 1050)
    static let blraaz = Mnemonic(rawValue: 1051)
    static let blrabz = Mnemonic(rawValue: 1052)
    static let retaa = Mnemonic(rawValue: 1053)
    static let retab = Mnemonic(rawValue: 1054)
    static let eretaa = Mnemonic(rawValue: 1055)
    static let eretab = Mnemonic(rawValue: 1056)

    // Named-NOP hints (1057..1058)
    static let nop = Mnemonic(rawValue: 1057)
    static let yield = Mnemonic(rawValue: 1058)

    // Event waits (1059..1062)
    static let wfe = Mnemonic(rawValue: 1059)
    static let wfi = Mnemonic(rawValue: 1060)
    static let sev = Mnemonic(rawValue: 1061)
    static let sevl = Mnemonic(rawValue: 1062)

    // Sync hints (1063..1068)
    static let dgh = Mnemonic(rawValue: 1063)
    static let csdb = Mnemonic(rawValue: 1064)
    static let esb = Mnemonic(rawValue: 1065)
    static let psb = Mnemonic(rawValue: 1066)
    static let tsb = Mnemonic(rawValue: 1067)
    static let gcsbDsync = Mnemonic(rawValue: 1068)

    /// Implicit-LR PAC strip (1069)
    static let xpaclri = Mnemonic(rawValue: 1069)

    // PAC HINT-space (1716 variants) (1070..1073)
    static let pacia1716 = Mnemonic(rawValue: 1070)
    static let pacib1716 = Mnemonic(rawValue: 1071)
    static let autia1716 = Mnemonic(rawValue: 1072)
    static let autib1716 = Mnemonic(rawValue: 1073)

    // PAC HINT-space (Z/SP variants) (1074..1081)
    static let paciaz = Mnemonic(rawValue: 1074)
    static let paciasp = Mnemonic(rawValue: 1075)
    static let pacibz = Mnemonic(rawValue: 1076)
    static let pacibsp = Mnemonic(rawValue: 1077)
    static let autiaz = Mnemonic(rawValue: 1078)
    static let autiasp = Mnemonic(rawValue: 1079)
    static let autibz = Mnemonic(rawValue: 1080)
    static let autibsp = Mnemonic(rawValue: 1081)

    /// BTI — single mnemonic; sub-target lives in operand[0].
    static let bti = Mnemonic(rawValue: 1082)

    // CHKFEAT (FEAT_CHK) / CLRBHB (FEAT_CLRBHB) — HINT-space instructions.
    static let chkfeat = Mnemonic(rawValue: 1083)
    static let clrbhb = Mnemonic(rawValue: 1084)

    /// Generic HINT — emitted when the imm7 has no named alias. Carries the
    /// raw imm7 as `.unsignedImmediate(value:, width: 7)`.
    static let hint = Mnemonic(rawValue: 1085)

    // Barriers (1086..1092)
    static let clrex = Mnemonic(rawValue: 1086)
    static let dsb = Mnemonic(rawValue: 1087)
    static let dmb = Mnemonic(rawValue: 1088)
    static let isb = Mnemonic(rawValue: 1089)
    static let sb = Mnemonic(rawValue: 1090)
    static let ssbb = Mnemonic(rawValue: 1091)
    static let pssbb = Mnemonic(rawValue: 1092)

    // System register move (1093..1094)
    static let msr = Mnemonic(rawValue: 1093)
    static let mrs = Mnemonic(rawValue: 1094)

    // Standalone PSTATE writes (1095..1097)
    static let cfinv = Mnemonic(rawValue: 1095)
    static let xaflag = Mnemonic(rawValue: 1096)
    static let axflag = Mnemonic(rawValue: 1097)

    // SYS-family (1098..1100). `.sys`/`.sysl` carry a single
    // `.systemOp(SystemOp(rawEncoding:))` operand; the canonicalizer
    // extracts op1/CRn/CRm/op2/Rt. `.msrImm` is MSR-immediate to a named
    // PSTATE field — distinct from `.msr` (register form) so downstream
    // consumers can filter on the operand-shape difference without parsing
    // operands.
    static let sys = Mnemonic(rawValue: 1098)
    static let sysl = Mnemonic(rawValue: 1099)
    static let msrImm = Mnemonic(rawValue: 1100)

    // Wait with timeout — FEAT_WFxT (1101..1102)
    static let wfet = Mnemonic(rawValue: 1101)
    static let wfit = Mnemonic(rawValue: 1102)

    // FEAT_CMPBR compare-and-branch — word/dword register + immediate forms
    // (1103..1110). cbgt/cbhi/cbeq/cbne are shared by register and
    // immediate (operand shape disambiguates); cbge/cbhs are register-only
    // and cblt/cblo are immediate-only (per the cc → CmpOp tables).
    static let cbgt = Mnemonic(rawValue: 1103)
    static let cbge = Mnemonic(rawValue: 1104)
    static let cbhi = Mnemonic(rawValue: 1105)
    static let cbhs = Mnemonic(rawValue: 1106)
    static let cbeq = Mnemonic(rawValue: 1107)
    static let cbne = Mnemonic(rawValue: 1108)
    static let cblt = Mnemonic(rawValue: 1109)
    static let cblo = Mnemonic(rawValue: 1110)

    // FEAT_CMPBR compare-and-branch — byte register form (1111..1116)
    static let cbbgt = Mnemonic(rawValue: 1111)
    static let cbbge = Mnemonic(rawValue: 1112)
    static let cbbhi = Mnemonic(rawValue: 1113)
    static let cbbhs = Mnemonic(rawValue: 1114)
    static let cbbeq = Mnemonic(rawValue: 1115)
    static let cbbne = Mnemonic(rawValue: 1116)

    // FEAT_CMPBR compare-and-branch — halfword register form (1117..1122)
    static let cbhgt = Mnemonic(rawValue: 1117)
    static let cbhge = Mnemonic(rawValue: 1118)
    static let cbhhi = Mnemonic(rawValue: 1119)
    static let cbhhs = Mnemonic(rawValue: 1120)
    static let cbheq = Mnemonic(rawValue: 1121)
    static let cbhne = Mnemonic(rawValue: 1122)

    // FEAT_D128 128-bit system moves + SYS pair (1123..1125). `.mrrs`/`.msrr`
    // read/write a consecutive X-register pair; `.sysp` carries the whole
    // encoding via `.systemOp` like `.sys`/`.sysl`.
    static let mrrs = Mnemonic(rawValue: 1123)
    static let msrr = Mnemonic(rawValue: 1124)
    static let sysp = Mnemonic(rawValue: 1125)

    // FEAT_SME PSTATE.SM/ZA enable/disable (MSR-immediate special forms)
    // (1126..1127). The selected field (sm / za / both) is carried as the
    // sole `.pstateField` operand via the `.unknown` round-trip slot.
    static let smstart = Mnemonic(rawValue: 1126)
    static let smstop = Mnemonic(rawValue: 1127)
}

extension Mnemonic {
    /// Canonical lowercase name for every Branches, Exception, System mnemonic constant —
    /// the family's slice of ``Mnemonic/name``, declared beside the
    /// constants it names so the two cannot drift. Unallocated raw
    /// values in the family's range return `"?<raw>"`.
    static func branchesExceptionSystemName(_ m: Mnemonic) -> String {
        switch m {
        case .b: "b"
        case .bl: "bl"
        case .cbz: "cbz"
        case .cbnz: "cbnz"
        case .tbz: "tbz"
        case .tbnz: "tbnz"
        case .svc: "svc"
        case .hvc: "hvc"
        case .smc: "smc"
        case .brk: "brk"
        case .hlt: "hlt"
        case .dcps1: "dcps1"
        case .dcps2: "dcps2"
        case .dcps3: "dcps3"
        case .br: "br"
        case .blr: "blr"
        case .ret: "ret"
        case .eret: "eret"
        case .drps: "drps"
        case .braa: "braa"
        case .brab: "brab"
        case .braaz: "braaz"
        case .brabz: "brabz"
        case .blraa: "blraa"
        case .blrab: "blrab"
        case .blraaz: "blraaz"
        case .blrabz: "blrabz"
        case .retaa: "retaa"
        case .retab: "retab"
        case .eretaa: "eretaa"
        case .eretab: "eretab"
        case .nop: "nop"
        case .yield: "yield"
        case .wfe: "wfe"
        case .wfi: "wfi"
        case .sev: "sev"
        case .sevl: "sevl"
        case .dgh: "dgh"
        case .csdb: "csdb"
        case .esb: "esb"
        case .psb: "psb"
        case .tsb: "tsb"
        case .gcsbDsync: "gcsb dsync"
        case .xpaclri: "xpaclri"
        case .pacia1716: "pacia1716"
        case .pacib1716: "pacib1716"
        case .autia1716: "autia1716"
        case .autib1716: "autib1716"
        case .paciaz: "paciaz"
        case .paciasp: "paciasp"
        case .pacibz: "pacibz"
        case .pacibsp: "pacibsp"
        case .autiaz: "autiaz"
        case .autiasp: "autiasp"
        case .autibz: "autibz"
        case .autibsp: "autibsp"
        case .bti: "bti"
        case .chkfeat: "chkfeat"
        case .clrbhb: "clrbhb"
        case .hint: "hint"
        case .clrex: "clrex"
        case .dsb: "dsb"
        case .dmb: "dmb"
        case .isb: "isb"
        case .sb: "sb"
        case .ssbb: "ssbb"
        case .pssbb: "pssbb"
        case .msr: "msr"
        case .mrs: "mrs"
        case .cfinv: "cfinv"
        case .xaflag: "xaflag"
        case .axflag: "axflag"
        case .sys: "sys"
        case .sysl: "sysl"
        case .msrImm: "msr"
        case .wfet: "wfet"
        case .wfit: "wfit"
        case .cbgt: "cbgt"
        case .cbge: "cbge"
        case .cbhi: "cbhi"
        case .cbhs: "cbhs"
        case .cbeq: "cbeq"
        case .cbne: "cbne"
        case .cblt: "cblt"
        case .cblo: "cblo"
        case .cbbgt: "cbbgt"
        case .cbbge: "cbbge"
        case .cbbhi: "cbbhi"
        case .cbbhs: "cbbhs"
        case .cbbeq: "cbbeq"
        case .cbbne: "cbbne"
        case .cbhgt: "cbhgt"
        case .cbhge: "cbhge"
        case .cbhhi: "cbhhi"
        case .cbhhs: "cbhhs"
        case .cbheq: "cbheq"
        case .cbhne: "cbhne"
        case .mrrs: "mrrs"
        case .msrr: "msrr"
        case .sysp: "sysp"
        case .smstart: "smstart"
        case .smstop: "smstop"
        case .bCond: "b.cond"
        case .bcCond: "bc.cond"
        default: "?\(m.rawValue)"
        }
    }
}
