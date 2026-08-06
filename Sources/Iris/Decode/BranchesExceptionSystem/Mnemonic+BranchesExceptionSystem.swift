// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

public extension Mnemonic {
    static let b = Mnemonic(rawValue: 1024)
    static let bl = Mnemonic(rawValue: 1025)

    static let cbz = Mnemonic(rawValue: 1026)
    static let cbnz = Mnemonic(rawValue: 1027)

    static let tbz = Mnemonic(rawValue: 1028)
    static let tbnz = Mnemonic(rawValue: 1029)

    static let bCond = Mnemonic(rawValue: 1030)
    static let bcCond = Mnemonic(rawValue: 1031)

    static let svc = Mnemonic(rawValue: 1032)
    static let hvc = Mnemonic(rawValue: 1033)
    static let smc = Mnemonic(rawValue: 1034)
    static let brk = Mnemonic(rawValue: 1035)
    static let hlt = Mnemonic(rawValue: 1036)
    static let dcps1 = Mnemonic(rawValue: 1037)
    static let dcps2 = Mnemonic(rawValue: 1038)
    static let dcps3 = Mnemonic(rawValue: 1039)

    static let br = Mnemonic(rawValue: 1040)
    static let blr = Mnemonic(rawValue: 1041)
    static let ret = Mnemonic(rawValue: 1042)
    static let eret = Mnemonic(rawValue: 1043)
    static let drps = Mnemonic(rawValue: 1044)

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

    static let nop = Mnemonic(rawValue: 1057)
    static let yield = Mnemonic(rawValue: 1058)

    static let wfe = Mnemonic(rawValue: 1059)
    static let wfi = Mnemonic(rawValue: 1060)
    static let sev = Mnemonic(rawValue: 1061)
    static let sevl = Mnemonic(rawValue: 1062)

    static let dgh = Mnemonic(rawValue: 1063)
    static let csdb = Mnemonic(rawValue: 1064)
    static let esb = Mnemonic(rawValue: 1065)
    static let psb = Mnemonic(rawValue: 1066)
    static let tsb = Mnemonic(rawValue: 1067)
    static let gcsbDsync = Mnemonic(rawValue: 1068)

    /// Implicit-LR PAC strip (1069)
    static let xpaclri = Mnemonic(rawValue: 1069)

    static let pacia1716 = Mnemonic(rawValue: 1070)
    static let pacib1716 = Mnemonic(rawValue: 1071)
    static let autia1716 = Mnemonic(rawValue: 1072)
    static let autib1716 = Mnemonic(rawValue: 1073)

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

    static let chkfeat = Mnemonic(rawValue: 1083)
    static let clrbhb = Mnemonic(rawValue: 1084)

    /// Generic HINT — emitted when the imm7 has no named alias. Carries the
    /// raw imm7 as `.unsignedImmediate(value:, width: 7)`.
    static let hint = Mnemonic(rawValue: 1085)

    static let clrex = Mnemonic(rawValue: 1086)
    static let dsb = Mnemonic(rawValue: 1087)
    static let dmb = Mnemonic(rawValue: 1088)
    static let isb = Mnemonic(rawValue: 1089)
    static let sb = Mnemonic(rawValue: 1090)
    static let ssbb = Mnemonic(rawValue: 1091)
    static let pssbb = Mnemonic(rawValue: 1092)

    static let msr = Mnemonic(rawValue: 1093)
    static let mrs = Mnemonic(rawValue: 1094)

    static let cfinv = Mnemonic(rawValue: 1095)
    static let xaflag = Mnemonic(rawValue: 1096)
    static let axflag = Mnemonic(rawValue: 1097)

    static let sys = Mnemonic(rawValue: 1098)
    static let sysl = Mnemonic(rawValue: 1099)
    static let msrImm = Mnemonic(rawValue: 1100)

    static let wfet = Mnemonic(rawValue: 1101)
    static let wfit = Mnemonic(rawValue: 1102)

    static let cbgt = Mnemonic(rawValue: 1103)
    static let cbge = Mnemonic(rawValue: 1104)
    static let cbhi = Mnemonic(rawValue: 1105)
    static let cbhs = Mnemonic(rawValue: 1106)
    static let cbeq = Mnemonic(rawValue: 1107)
    static let cbne = Mnemonic(rawValue: 1108)
    static let cblt = Mnemonic(rawValue: 1109)
    static let cblo = Mnemonic(rawValue: 1110)

    static let cbbgt = Mnemonic(rawValue: 1111)
    static let cbbge = Mnemonic(rawValue: 1112)
    static let cbbhi = Mnemonic(rawValue: 1113)
    static let cbbhs = Mnemonic(rawValue: 1114)
    static let cbbeq = Mnemonic(rawValue: 1115)
    static let cbbne = Mnemonic(rawValue: 1116)

    static let cbhgt = Mnemonic(rawValue: 1117)
    static let cbhge = Mnemonic(rawValue: 1118)
    static let cbhhi = Mnemonic(rawValue: 1119)
    static let cbhhs = Mnemonic(rawValue: 1120)
    static let cbheq = Mnemonic(rawValue: 1121)
    static let cbhne = Mnemonic(rawValue: 1122)

    static let mrrs = Mnemonic(rawValue: 1123)
    static let msrr = Mnemonic(rawValue: 1124)
    static let sysp = Mnemonic(rawValue: 1125)

    static let smstart = Mnemonic(rawValue: 1126)
    static let smstop = Mnemonic(rawValue: 1127)

    static let pacm = Mnemonic(rawValue: 1128)
    static let stshh = Mnemonic(rawValue: 1129)
    static let shuh = Mnemonic(rawValue: 1130)
    static let stcph = Mnemonic(rawValue: 1131)

    static let dfb = Mnemonic(rawValue: 1132)

    static let retaasppc = Mnemonic(rawValue: 1133)
    static let retabsppc = Mnemonic(rawValue: 1134)
    static let retaasppcr = Mnemonic(rawValue: 1135)
    static let retabsppcr = Mnemonic(rawValue: 1136)

    /// Apple TIndex `TENTER` (1137) and its no-branch form (1138).
    static let tenter = Mnemonic(rawValue: 1137)
    static let tenterNb = Mnemonic(rawValue: 1138)

    /// Apple TIndex `TEXIT` (1139) and its no-branch form (1140).
    static let texit = Mnemonic(rawValue: 1139)
    static let texitNb = Mnemonic(rawValue: 1140)

    /// Apple TIndex `TCHANGEF` / `TCHANGEB` and their no-branch forms.
    static let tchangef = Mnemonic(rawValue: 1141)
    static let tchangefNb = Mnemonic(rawValue: 1142)
    static let tchangeb = Mnemonic(rawValue: 1143)
    static let tchangebNb = Mnemonic(rawValue: 1144)
}

extension Mnemonic {
    /// Canonical lowercase name for every Branches, Exception, System
    /// mnemonic; unallocated raw values in the range return `"?<raw>"`.
    static func branchesExceptionSystemName(_ m: Mnemonic) -> StaticString? {
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
        case .pacm: "pacm"
        case .stshh: "stshh"
        case .shuh: "shuh"
        case .stcph: "stcph"
        case .dfb: "dfb"
        case .retaasppc: "retaasppc"
        case .retabsppc: "retabsppc"
        case .retaasppcr: "retaasppcr"
        case .retabsppcr: "retabsppcr"
        case .tenter, .tenterNb: "tenter"
        case .texit: "texit"
        case .texitNb: "texit nb"
        case .tchangef, .tchangefNb: "tchangef"
        case .tchangeb, .tchangebNb: "tchangeb"
        default: nil
        }
    }
}
