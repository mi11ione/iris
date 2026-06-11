// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Mnemonic constants for the Data Processing — Register
// family. Raw values 4096..4153 within the family's reserved 4096..6143
// slab. Sixteen mnemonics DPR emits are owned by DPI and REUSED here
// without redeclaration: add, adds, sub, subs, and, orr, eor, ands, mov,
// cmp, cmn, tst, lsl, lsr, asr, ror. `Mnemonic.allocations` is the
// authoritative source for which slab each mnemonic comes from; this
// file declares only the 58 new-in-DPR entries.

public extension Mnemonic {
    // Logical shifted-register additions (4096..4099)
    static let bic = Mnemonic(rawValue: 4096)
    static let orn = Mnemonic(rawValue: 4097)
    static let eon = Mnemonic(rawValue: 4098)
    static let bics = Mnemonic(rawValue: 4099)

    /// MVN — alias of ORN with Rn=XZR (4100)
    static let mvn = Mnemonic(rawValue: 4100)

    // Add/subtract with carry (4101..4104)
    static let adc = Mnemonic(rawValue: 4101)
    static let adcs = Mnemonic(rawValue: 4102)
    static let sbc = Mnemonic(rawValue: 4103)
    static let sbcs = Mnemonic(rawValue: 4104)

    // NGC/NGCS aliases of SBC/SBCS with Rn=XZR (4105..4106)
    static let ngc = Mnemonic(rawValue: 4105)
    static let ngcs = Mnemonic(rawValue: 4106)

    // NEG/NEGS aliases of SUB/SUBS shifted-register with Rn=XZR (4107..4108)
    static let neg = Mnemonic(rawValue: 4107)
    static let negs = Mnemonic(rawValue: 4108)

    // Conditional compare (4109..4110)
    static let ccmn = Mnemonic(rawValue: 4109)
    static let ccmp = Mnemonic(rawValue: 4110)

    // Conditional select (4111..4114)
    static let csel = Mnemonic(rawValue: 4111)
    static let csinc = Mnemonic(rawValue: 4112)
    static let csinv = Mnemonic(rawValue: 4113)
    static let csneg = Mnemonic(rawValue: 4114)

    // Conditional select aliases (4115..4119)
    static let cset = Mnemonic(rawValue: 4115)
    static let csetm = Mnemonic(rawValue: 4116)
    static let cinc = Mnemonic(rawValue: 4117)
    static let cinv = Mnemonic(rawValue: 4118)
    static let cneg = Mnemonic(rawValue: 4119)

    // Multiply-accumulate same-size (4120..4121)
    static let madd = Mnemonic(rawValue: 4120)
    static let msub = Mnemonic(rawValue: 4121)

    // Multiply-accumulate wide (4122..4125)
    static let smaddl = Mnemonic(rawValue: 4122)
    static let smsubl = Mnemonic(rawValue: 4123)
    static let umaddl = Mnemonic(rawValue: 4124)
    static let umsubl = Mnemonic(rawValue: 4125)

    // Multiply-high (4126..4127)
    static let smulh = Mnemonic(rawValue: 4126)
    static let umulh = Mnemonic(rawValue: 4127)

    // MUL/MNEG aliases of MADD/MSUB with Ra=XZR (4128..4129)
    static let mul = Mnemonic(rawValue: 4128)
    static let mneg = Mnemonic(rawValue: 4129)

    // Wide-multiply aliases with Ra=XZR (4130..4133)
    static let smull = Mnemonic(rawValue: 4130)
    static let smnegl = Mnemonic(rawValue: 4131)
    static let umull = Mnemonic(rawValue: 4132)
    static let umnegl = Mnemonic(rawValue: 4133)

    // Divide (4134..4135)
    static let udiv = Mnemonic(rawValue: 4134)
    static let sdiv = Mnemonic(rawValue: 4135)

    // Variable-shift base mnemonics (4136..4139). NEVER emitted by DPR's
    // decoder — llvm-mc canonicalises every variable-shift form to the
    // DPI-owned `.lsl` / `.lsr` / `.asr` / `.ror`. Allocated for downstream
    // tooling that needs a discriminator.
    static let lslv = Mnemonic(rawValue: 4136)
    static let lsrv = Mnemonic(rawValue: 4137)
    static let asrv = Mnemonic(rawValue: 4138)
    static let rorv = Mnemonic(rawValue: 4139)

    // Data-processing 1-source (4140..4145). One `rev` mnemonic covers
    // both 32-bit and 64-bit byte-swap forms; `rev32` is the byte-swap-
    // within-each-32-bit-lane variant valid only at sf=1.
    static let clz = Mnemonic(rawValue: 4140)
    static let cls = Mnemonic(rawValue: 4141)
    static let rbit = Mnemonic(rawValue: 4142)
    static let rev = Mnemonic(rawValue: 4143)
    static let rev16 = Mnemonic(rawValue: 4144)
    static let rev32 = Mnemonic(rawValue: 4145)

    // CRC32 / CRC32C — FEAT_CRC32 (Armv8.1 baseline) (4146..4153)
    static let crc32b = Mnemonic(rawValue: 4146)
    static let crc32h = Mnemonic(rawValue: 4147)
    static let crc32w = Mnemonic(rawValue: 4148)
    static let crc32x = Mnemonic(rawValue: 4149)
    static let crc32cb = Mnemonic(rawValue: 4150)
    static let crc32ch = Mnemonic(rawValue: 4151)
    static let crc32cw = Mnemonic(rawValue: 4152)
    static let crc32cx = Mnemonic(rawValue: 4153)

    /// FEAT_CSSC count-trailing-zeros (4154). ABS/CNT and SMAX/SMIN/UMAX/UMIN
    /// are SIMD/FP-owned mnemonics reused by the DPR decoder, so only CTZ is new.
    static let ctz = Mnemonic(rawValue: 4154)

    // FEAT_FlagM flag-manipulation (4155..4157): RMIF rotate-into-flags,
    // SETF8 / SETF16 evaluate-into-flags.
    static let rmif = Mnemonic(rawValue: 4155)
    static let setf8 = Mnemonic(rawValue: 4156)
    static let setf16 = Mnemonic(rawValue: 4157)

    // FEAT_CPA checked-pointer arithmetic (4158..4161): ADDPT / SUBPT and
    // the multiply-add forms MADDPT / MSUBPT.
    static let addpt = Mnemonic(rawValue: 4158)
    static let subpt = Mnemonic(rawValue: 4159)
    static let maddpt = Mnemonic(rawValue: 4160)
    static let msubpt = Mnemonic(rawValue: 4161)
}

extension Mnemonic {
    /// Canonical lowercase name for every Data Processing — Register mnemonic constant —
    /// the family's slice of ``Mnemonic/name``, declared beside the
    /// constants it names so the two cannot drift. Unallocated raw
    /// values in the family's range return `"?<raw>"`.
    static func dataProcessingRegisterName(_ m: Mnemonic) -> String {
        switch m {
        case .bic: "bic"
        case .orn: "orn"
        case .eon: "eon"
        case .bics: "bics"
        case .mvn: "mvn"
        case .adc: "adc"
        case .adcs: "adcs"
        case .sbc: "sbc"
        case .sbcs: "sbcs"
        case .ngc: "ngc"
        case .ngcs: "ngcs"
        case .neg: "neg"
        case .negs: "negs"
        case .ccmn: "ccmn"
        case .ccmp: "ccmp"
        case .csel: "csel"
        case .csinc: "csinc"
        case .csinv: "csinv"
        case .csneg: "csneg"
        case .cset: "cset"
        case .csetm: "csetm"
        case .cinc: "cinc"
        case .cinv: "cinv"
        case .cneg: "cneg"
        case .madd: "madd"
        case .msub: "msub"
        case .smaddl: "smaddl"
        case .smsubl: "smsubl"
        case .umaddl: "umaddl"
        case .umsubl: "umsubl"
        case .smulh: "smulh"
        case .umulh: "umulh"
        case .mul: "mul"
        case .mneg: "mneg"
        case .smull: "smull"
        case .smnegl: "smnegl"
        case .umull: "umull"
        case .umnegl: "umnegl"
        case .udiv: "udiv"
        case .sdiv: "sdiv"
        case .lslv: "lslv"
        case .lsrv: "lsrv"
        case .asrv: "asrv"
        case .rorv: "rorv"
        case .clz: "clz"
        case .cls: "cls"
        case .rbit: "rbit"
        case .rev: "rev"
        case .rev16: "rev16"
        case .rev32: "rev32"
        case .crc32b: "crc32b"
        case .crc32h: "crc32h"
        case .crc32w: "crc32w"
        case .crc32x: "crc32x"
        case .crc32cb: "crc32cb"
        case .crc32ch: "crc32ch"
        case .crc32cw: "crc32cw"
        case .crc32cx: "crc32cx"
        case .ctz: "ctz"
        case .rmif: "rmif"
        case .setf8: "setf8"
        case .setf16: "setf16"
        case .addpt: "addpt"
        case .subpt: "subpt"
        case .maddpt: "maddpt"
        case .msubpt: "msubpt"
        default: "?\(m.rawValue)"
        }
    }
}
