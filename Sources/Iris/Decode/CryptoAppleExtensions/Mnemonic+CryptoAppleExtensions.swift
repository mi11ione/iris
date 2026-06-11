// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Crypto/Apple-extensions Mnemonic constants: AES / SHA-1 / SHA-256 /
// SHA-3 / SHA-512 /
// SM3 / SM4 (crypto), PAC standalone, MTE, AMX. Each value falls strictly
// inside its declared sub-range from the carve-up below; the
// `range-membership` self-check on Mnemonic.allocations enforces this.
//
// Sub-range carve-up within the family's reserved range [12288, 16383]:
//   12288 ... 12299  Crypto AES (4) + headroom
//   12300 ... 12319  Crypto SHA-1 (6) + SHA-256 (4) + headroom
//   12320 ... 12351  Crypto SHA-3 + SHA-512 + SM3 + SM4 (17) + headroom
//   12352 ... 12415  PAC standalone (19) + headroom
//   12416 ... 12479  MTE (15) + headroom
//   12480 ... 12527  AMX documented (23) + amxUnknownOp (1) + headroom
//   12528 ... 16383  reserved (future 2.x growth)

public extension Mnemonic {
    // MARK: Crypto — AES (4)

    static let aese = Mnemonic(rawValue: 12288)
    static let aesd = Mnemonic(rawValue: 12289)
    static let aesmc = Mnemonic(rawValue: 12290)
    static let aesimc = Mnemonic(rawValue: 12291)

    // MARK: Crypto — SHA-1 (6)

    static let sha1c = Mnemonic(rawValue: 12300)
    static let sha1p = Mnemonic(rawValue: 12301)
    static let sha1m = Mnemonic(rawValue: 12302)
    static let sha1su0 = Mnemonic(rawValue: 12303)
    static let sha1h = Mnemonic(rawValue: 12304)
    static let sha1su1 = Mnemonic(rawValue: 12305)

    // MARK: Crypto — SHA-256 (4)

    static let sha256h = Mnemonic(rawValue: 12306)
    static let sha256h2 = Mnemonic(rawValue: 12307)
    static let sha256su0 = Mnemonic(rawValue: 12308)
    static let sha256su1 = Mnemonic(rawValue: 12309)

    // MARK: Crypto — SHA-3 (4), SHA-512 (4), SM3 (7), SM4 (2)

    static let eor3 = Mnemonic(rawValue: 12320)
    static let bcax = Mnemonic(rawValue: 12321)
    static let xar = Mnemonic(rawValue: 12322)
    static let rax1 = Mnemonic(rawValue: 12323)
    static let sha512h = Mnemonic(rawValue: 12324)
    static let sha512h2 = Mnemonic(rawValue: 12325)
    static let sha512su0 = Mnemonic(rawValue: 12326)
    static let sha512su1 = Mnemonic(rawValue: 12327)
    static let sm3ss1 = Mnemonic(rawValue: 12328)
    static let sm3tt1a = Mnemonic(rawValue: 12329)
    static let sm3tt1b = Mnemonic(rawValue: 12330)
    static let sm3tt2a = Mnemonic(rawValue: 12331)
    static let sm3tt2b = Mnemonic(rawValue: 12332)
    static let sm3partw1 = Mnemonic(rawValue: 12333)
    static let sm3partw2 = Mnemonic(rawValue: 12334)
    static let sm4e = Mnemonic(rawValue: 12335)
    static let sm4ekey = Mnemonic(rawValue: 12336)

    // MARK: Pointer Authentication standalone (19)

    static let pacia = Mnemonic(rawValue: 12352)
    static let pacib = Mnemonic(rawValue: 12353)
    static let pacda = Mnemonic(rawValue: 12354)
    static let pacdb = Mnemonic(rawValue: 12355)
    static let autia = Mnemonic(rawValue: 12356)
    static let autib = Mnemonic(rawValue: 12357)
    static let autda = Mnemonic(rawValue: 12358)
    static let autdb = Mnemonic(rawValue: 12359)
    static let paciza = Mnemonic(rawValue: 12360)
    static let pacizb = Mnemonic(rawValue: 12361)
    static let pacdza = Mnemonic(rawValue: 12362)
    static let pacdzb = Mnemonic(rawValue: 12363)
    static let autiza = Mnemonic(rawValue: 12364)
    static let autizb = Mnemonic(rawValue: 12365)
    static let autdza = Mnemonic(rawValue: 12366)
    static let autdzb = Mnemonic(rawValue: 12367)
    static let xpaci = Mnemonic(rawValue: 12368)
    static let xpacd = Mnemonic(rawValue: 12369)
    static let pacga = Mnemonic(rawValue: 12370)

    // MARK: Memory Tagging Extension (15)

    static let addg = Mnemonic(rawValue: 12416)
    static let subg = Mnemonic(rawValue: 12417)
    static let irg = Mnemonic(rawValue: 12418)
    static let gmi = Mnemonic(rawValue: 12419)
    static let subp = Mnemonic(rawValue: 12420)
    static let subps = Mnemonic(rawValue: 12421)
    static let ldg = Mnemonic(rawValue: 12422)
    static let stg = Mnemonic(rawValue: 12423)
    static let st2g = Mnemonic(rawValue: 12424)
    static let stzg = Mnemonic(rawValue: 12425)
    static let stz2g = Mnemonic(rawValue: 12426)
    static let ldgm = Mnemonic(rawValue: 12427)
    static let stgm = Mnemonic(rawValue: 12428)
    static let stzgm = Mnemonic(rawValue: 12429)

    // MARK: Apple AMX (24 — 23 documented + amxUnknownOp)

    static let amxLdx = Mnemonic(rawValue: 12480)
    static let amxLdy = Mnemonic(rawValue: 12481)
    static let amxStx = Mnemonic(rawValue: 12482)
    static let amxSty = Mnemonic(rawValue: 12483)
    static let amxLdz = Mnemonic(rawValue: 12484)
    static let amxStz = Mnemonic(rawValue: 12485)
    static let amxLdzi = Mnemonic(rawValue: 12486)
    static let amxStzi = Mnemonic(rawValue: 12487)
    static let amxExtrx = Mnemonic(rawValue: 12488)
    static let amxExtry = Mnemonic(rawValue: 12489)
    static let amxFma64 = Mnemonic(rawValue: 12490)
    static let amxFms64 = Mnemonic(rawValue: 12491)
    static let amxFma32 = Mnemonic(rawValue: 12492)
    static let amxFms32 = Mnemonic(rawValue: 12493)
    static let amxMac16 = Mnemonic(rawValue: 12494)
    static let amxFma16 = Mnemonic(rawValue: 12495)
    static let amxFms16 = Mnemonic(rawValue: 12496)
    static let amxSet = Mnemonic(rawValue: 12497)
    static let amxClr = Mnemonic(rawValue: 12498)
    static let amxVecint = Mnemonic(rawValue: 12499)
    static let amxVecfp = Mnemonic(rawValue: 12500)
    static let amxMatint = Mnemonic(rawValue: 12501)
    static let amxMatfp = Mnemonic(rawValue: 12502)
    static let amxGenlut = Mnemonic(rawValue: 12503)
    static let amxUnknownOp = Mnemonic(rawValue: 12504)
}

extension Mnemonic {
    /// Canonical lowercase name for every Crypto + Apple Extensions mnemonic constant —
    /// the family's slice of ``Mnemonic/name``, declared beside the
    /// constants it names so the two cannot drift. Unallocated raw
    /// values in the family's range return `"?<raw>"`.
    static func cryptoAppleExtensionsName(_ m: Mnemonic) -> String {
        switch m {
        case .aese: "aese"
        case .aesd: "aesd"
        case .aesmc: "aesmc"
        case .aesimc: "aesimc"
        case .sha1c: "sha1c"
        case .sha1p: "sha1p"
        case .sha1m: "sha1m"
        case .sha1su0: "sha1su0"
        case .sha1h: "sha1h"
        case .sha1su1: "sha1su1"
        case .sha256h: "sha256h"
        case .sha256h2: "sha256h2"
        case .sha256su0: "sha256su0"
        case .sha256su1: "sha256su1"
        case .eor3: "eor3"
        case .bcax: "bcax"
        case .xar: "xar"
        case .rax1: "rax1"
        case .sha512h: "sha512h"
        case .sha512h2: "sha512h2"
        case .sha512su0: "sha512su0"
        case .sha512su1: "sha512su1"
        case .sm3ss1: "sm3ss1"
        case .sm3tt1a: "sm3tt1a"
        case .sm3tt1b: "sm3tt1b"
        case .sm3tt2a: "sm3tt2a"
        case .sm3tt2b: "sm3tt2b"
        case .sm3partw1: "sm3partw1"
        case .sm3partw2: "sm3partw2"
        case .sm4e: "sm4e"
        case .sm4ekey: "sm4ekey"
        case .pacia: "pacia"
        case .pacib: "pacib"
        case .pacda: "pacda"
        case .pacdb: "pacdb"
        case .autia: "autia"
        case .autib: "autib"
        case .autda: "autda"
        case .autdb: "autdb"
        case .paciza: "paciza"
        case .pacizb: "pacizb"
        case .pacdza: "pacdza"
        case .pacdzb: "pacdzb"
        case .autiza: "autiza"
        case .autizb: "autizb"
        case .autdza: "autdza"
        case .autdzb: "autdzb"
        case .xpaci: "xpaci"
        case .xpacd: "xpacd"
        case .pacga: "pacga"
        case .addg: "addg"
        case .subg: "subg"
        case .irg: "irg"
        case .gmi: "gmi"
        case .subp: "subp"
        case .subps: "subps"
        case .ldg: "ldg"
        case .stg: "stg"
        case .st2g: "st2g"
        case .stzg: "stzg"
        case .stz2g: "stz2g"
        case .ldgm: "ldgm"
        case .stgm: "stgm"
        case .stzgm: "stzgm"
        case .amxLdx: "ldx"
        case .amxLdy: "ldy"
        case .amxStx: "stx"
        case .amxSty: "sty"
        case .amxLdz: "ldz"
        case .amxStz: "stz"
        case .amxLdzi: "ldzi"
        case .amxStzi: "stzi"
        case .amxExtrx: "extrx"
        case .amxExtry: "extry"
        case .amxFma64: "fma64"
        case .amxFms64: "fms64"
        case .amxFma32: "fma32"
        case .amxFms32: "fms32"
        case .amxMac16: "mac16"
        case .amxFma16: "fma16"
        case .amxFms16: "fms16"
        case .amxSet: "set"
        case .amxClr: "clr"
        case .amxVecint: "vecint"
        case .amxVecfp: "vecfp"
        case .amxMatint: "matint"
        case .amxMatfp: "matfp"
        case .amxGenlut: "genlut"
        case .amxUnknownOp: "amx-unknown"
        default: "?\(m.rawValue)"
        }
    }
}
