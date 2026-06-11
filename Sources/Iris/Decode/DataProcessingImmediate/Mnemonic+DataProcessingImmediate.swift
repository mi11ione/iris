// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Mnemonic constants for the Data Processing — Immediate
// family. Raw values 256..299 within the family's reserved 256..1023
// slab. Shared mnemonics (add/sub/and/orr/eor/ands/mov/cmp/lsl/lsr/asr/
// ror) are owned here by DPI (the first family needing them) and
// REUSED by the other families per the shared-mnemonic ownership
// rule. Other families must not redeclare these with different raw
// values; they reference `Mnemonic.add` etc. directly.

public extension Mnemonic {
    // Add/subtract immediate (base mnemonics)
    static let add = Mnemonic(rawValue: 256)
    static let adds = Mnemonic(rawValue: 257)
    static let sub = Mnemonic(rawValue: 258)
    static let subs = Mnemonic(rawValue: 259)

    // Logical immediate (base mnemonics)
    static let and = Mnemonic(rawValue: 260)
    static let orr = Mnemonic(rawValue: 261)
    static let eor = Mnemonic(rawValue: 262)
    static let ands = Mnemonic(rawValue: 263)

    // Move wide immediate (base mnemonics)
    static let movn = Mnemonic(rawValue: 264)
    static let movz = Mnemonic(rawValue: 265)
    static let movk = Mnemonic(rawValue: 266)

    // PC-relative addressing
    static let adr = Mnemonic(rawValue: 267)
    static let adrp = Mnemonic(rawValue: 268)

    // Bitfield (base mnemonics)
    static let bfm = Mnemonic(rawValue: 269)
    static let sbfm = Mnemonic(rawValue: 270)
    static let ubfm = Mnemonic(rawValue: 271)

    /// Extract
    static let extr = Mnemonic(rawValue: 272)

    // Aliases — flag-setting comparisons and tests
    static let cmp = Mnemonic(rawValue: 280)
    static let cmn = Mnemonic(rawValue: 281)
    static let tst = Mnemonic(rawValue: 282)

    /// Alias — MOV (multiple sources: ADD-to/from-SP, ORR-bitmask, MOVZ-wide, MOVN-wide)
    static let mov = Mnemonic(rawValue: 283)

    // Bitfield aliases
    static let bfi = Mnemonic(rawValue: 284)
    static let bfxil = Mnemonic(rawValue: 285)
    static let bfc = Mnemonic(rawValue: 286)
    static let sbfiz = Mnemonic(rawValue: 287)
    static let sbfx = Mnemonic(rawValue: 288)
    static let ubfiz = Mnemonic(rawValue: 289)
    static let ubfx = Mnemonic(rawValue: 290)

    // Shift / rotate aliases (immediate forms — register forms are DPR's)
    static let lsl = Mnemonic(rawValue: 291)
    static let lsr = Mnemonic(rawValue: 292)
    static let asr = Mnemonic(rawValue: 293)
    static let ror = Mnemonic(rawValue: 294)

    // Sign / zero extension aliases
    static let sxtb = Mnemonic(rawValue: 295)
    static let sxth = Mnemonic(rawValue: 296)
    static let sxtw = Mnemonic(rawValue: 297)
    static let uxtb = Mnemonic(rawValue: 298)
    static let uxth = Mnemonic(rawValue: 299)
}

extension Mnemonic {
    /// Canonical lowercase name for every Data Processing — Immediate mnemonic constant —
    /// the family's slice of ``Mnemonic/name``, declared beside the
    /// constants it names so the two cannot drift. Unallocated raw
    /// values in the family's range return `"?<raw>"`.
    static func dataProcessingImmediateName(_ m: Mnemonic) -> String {
        switch m {
        case .add: "add"
        case .adds: "adds"
        case .sub: "sub"
        case .subs: "subs"
        case .and: "and"
        case .orr: "orr"
        case .eor: "eor"
        case .ands: "ands"
        case .movn: "movn"
        case .movz: "movz"
        case .movk: "movk"
        case .adr: "adr"
        case .adrp: "adrp"
        case .bfm: "bfm"
        case .sbfm: "sbfm"
        case .ubfm: "ubfm"
        case .extr: "extr"
        case .cmp: "cmp"
        case .cmn: "cmn"
        case .tst: "tst"
        case .mov: "mov"
        case .bfi: "bfi"
        case .bfxil: "bfxil"
        case .bfc: "bfc"
        case .sbfiz: "sbfiz"
        case .sbfx: "sbfx"
        case .ubfiz: "ubfiz"
        case .ubfx: "ubfx"
        case .lsl: "lsl"
        case .lsr: "lsr"
        case .asr: "asr"
        case .ror: "ror"
        case .sxtb: "sxtb"
        case .sxth: "sxth"
        case .sxtw: "sxtw"
        case .uxtb: "uxtb"
        case .uxth: "uxth"
        default: "?\(m.rawValue)"
        }
    }
}
