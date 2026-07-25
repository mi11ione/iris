// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// mnemonic constants — SVE / SVE2 integer. Raw values from the
// SVE / SVE2 slab (16384 ..< 28672); SVE-predicate consumed 16384...16468, so SVE-integer
// allocates from 16469. Shared tokens whose text is identical to an earlier
// family's (106 of them: add/sub/and/orr/eor/bic/mul/mov/asr/… ) are REUSED
// per the shared-mnemonic ownership rule; only the 158 SVE-integer-unique
// tokens are declared here. DUP and CPY always disassemble as `mov`, so the
// decoder emits `.mov` for them (no `.dup`/`.cpy` constant needed). The
// Mnemonic is the text token; operand shape and `category == .sve`
// distinguish the integer form at canonicalization.

public extension Mnemonic {
    // MARK: G12 sve2 mla-long

    /// `ADCLB` — SVE/SVE2 integer.
    static let adclb = Mnemonic(rawValue: 16469)
    /// `ADCLT` — SVE/SVE2 integer.
    static let adclt = Mnemonic(rawValue: 16470)
    /// `SABALB` — SVE/SVE2 integer.
    static let sabalb = Mnemonic(rawValue: 16525)
    /// `SABALT` — SVE/SVE2 integer.
    static let sabalt = Mnemonic(rawValue: 16526)
    /// `SBCLB` — SVE/SVE2 integer.
    static let sbclb = Mnemonic(rawValue: 16535)
    /// `SBCLT` — SVE/SVE2 integer.
    static let sbclt = Mnemonic(rawValue: 16536)
    /// `SMLALB` — SVE/SVE2 integer.
    static let smlalb = Mnemonic(rawValue: 16544)
    /// `SMLALT` — SVE/SVE2 integer.
    static let smlalt = Mnemonic(rawValue: 16545)
    /// `SMLSLB` — SVE/SVE2 integer.
    static let smlslb = Mnemonic(rawValue: 16546)
    /// `SMLSLT` — SVE/SVE2 integer.
    static let smlslt = Mnemonic(rawValue: 16547)
    /// `SMULLB` — SVE/SVE2 integer.
    static let smullb = Mnemonic(rawValue: 16548)
    /// `SQDMLALB` — SVE/SVE2 integer.
    static let sqdmlalb = Mnemonic(rawValue: 16553)
    /// `SQDMLALBT` — SVE/SVE2 integer.
    static let sqdmlalbt = Mnemonic(rawValue: 16554)
    /// `SQDMLALT` — SVE/SVE2 integer.
    static let sqdmlalt = Mnemonic(rawValue: 16555)
    /// `SQDMLSLB` — SVE/SVE2 integer.
    static let sqdmlslb = Mnemonic(rawValue: 16556)
    /// `SQDMLSLBT` — SVE/SVE2 integer.
    static let sqdmlslbt = Mnemonic(rawValue: 16557)
    /// `SQDMLSLT` — SVE/SVE2 integer.
    static let sqdmlslt = Mnemonic(rawValue: 16558)
    /// `SQDMULLT` — SVE/SVE2 integer.
    static let sqdmullt = Mnemonic(rawValue: 16560)
    /// `UABALB` — SVE/SVE2 integer.
    static let uabalb = Mnemonic(rawValue: 16589)
    /// `UABALT` — SVE/SVE2 integer.
    static let uabalt = Mnemonic(rawValue: 16590)
    /// `UMLALB` — SVE/SVE2 integer.
    static let umlalb = Mnemonic(rawValue: 16603)
    /// `UMLALT` — SVE/SVE2 integer.
    static let umlalt = Mnemonic(rawValue: 16604)
    /// `UMLSLB` — SVE/SVE2 integer.
    static let umlslb = Mnemonic(rawValue: 16605)
    /// `UMLSLT` — SVE/SVE2 integer.
    static let umlslt = Mnemonic(rawValue: 16606)

    // MARK: G14 sve2 narrow

    /// `ADDHNB` — SVE/SVE2 integer.
    static let addhnb = Mnemonic(rawValue: 16471)
    /// `ADDHNT` — SVE/SVE2 integer.
    static let addhnt = Mnemonic(rawValue: 16472)
    /// `RADDHNB` — SVE/SVE2 integer.
    static let raddhnb = Mnemonic(rawValue: 16519)
    /// `RADDHNT` — SVE/SVE2 integer.
    static let raddhnt = Mnemonic(rawValue: 16520)
    /// `RSHRNB` — SVE/SVE2 integer.
    static let rshrnb = Mnemonic(rawValue: 16521)
    /// `RSHRNT` — SVE/SVE2 integer.
    static let rshrnt = Mnemonic(rawValue: 16522)
    /// `RSUBHNB` — SVE/SVE2 integer.
    static let rsubhnb = Mnemonic(rawValue: 16523)
    /// `RSUBHNT` — SVE/SVE2 integer.
    static let rsubhnt = Mnemonic(rawValue: 16524)
    /// `SHRNB` — SVE/SVE2 integer.
    static let shrnb = Mnemonic(rawValue: 16539)
    /// `SHRNT` — SVE/SVE2 integer.
    static let shrnt = Mnemonic(rawValue: 16540)
    /// `SQCVTN` — SVE/SVE2 integer.
    static let sqcvtn = Mnemonic(rawValue: 16551)
    /// `SQCVTUN` — SVE/SVE2 integer.
    static let sqcvtun = Mnemonic(rawValue: 16552)
    /// `SQRSHRNB` — SVE/SVE2 integer.
    static let sqrshrnb = Mnemonic(rawValue: 16563)
    /// `SQRSHRNT` — SVE/SVE2 integer.
    static let sqrshrnt = Mnemonic(rawValue: 16564)
    /// `SQRSHRUNB` — SVE/SVE2 integer.
    static let sqrshrunb = Mnemonic(rawValue: 16565)
    /// `SQRSHRUNT` — SVE/SVE2 integer.
    static let sqrshrunt = Mnemonic(rawValue: 16566)
    /// `SQSHRNB` — SVE/SVE2 integer.
    static let sqshrnb = Mnemonic(rawValue: 16568)
    /// `SQSHRNT` — SVE/SVE2 integer.
    static let sqshrnt = Mnemonic(rawValue: 16569)
    /// `SQSHRUNB` — SVE/SVE2 integer.
    static let sqshrunb = Mnemonic(rawValue: 16570)
    /// `SQSHRUNT` — SVE/SVE2 integer.
    static let sqshrunt = Mnemonic(rawValue: 16571)
    /// `SQXTNB` — SVE/SVE2 integer.
    static let sqxtnb = Mnemonic(rawValue: 16573)
    /// `SQXTNT` — SVE/SVE2 integer.
    static let sqxtnt = Mnemonic(rawValue: 16574)
    /// `SQXTUNB` — SVE/SVE2 integer.
    static let sqxtunb = Mnemonic(rawValue: 16575)
    /// `SQXTUNT` — SVE/SVE2 integer.
    static let sqxtunt = Mnemonic(rawValue: 16576)
    /// `SUBHNB` — SVE/SVE2 integer.
    static let subhnb = Mnemonic(rawValue: 16586)
    /// `SUBHNT` — SVE/SVE2 integer.
    static let subhnt = Mnemonic(rawValue: 16587)
    /// `UQCVTN` — SVE/SVE2 integer.
    static let uqcvtn = Mnemonic(rawValue: 16609)
    /// `UQRSHRNB` — SVE/SVE2 integer.
    static let uqrshrnb = Mnemonic(rawValue: 16611)
    /// `UQRSHRNT` — SVE/SVE2 integer.
    static let uqrshrnt = Mnemonic(rawValue: 16612)
    /// `UQSHRNB` — SVE/SVE2 integer.
    static let uqshrnb = Mnemonic(rawValue: 16614)
    /// `UQSHRNT` — SVE/SVE2 integer.
    static let uqshrnt = Mnemonic(rawValue: 16615)
    /// `UQXTNB` — SVE/SVE2 integer.
    static let uqxtnb = Mnemonic(rawValue: 16617)
    /// `UQXTNT` — SVE/SVE2 integer.
    static let uqxtnt = Mnemonic(rawValue: 16618)

    // MARK: G6 unpredicated

    /// `ADDQP` — SVE/SVE2 integer.
    static let addqp = Mnemonic(rawValue: 16473)
    /// `ADDSUBP` — SVE/SVE2 integer.
    static let addsubp = Mnemonic(rawValue: 16475)

    // MARK: G5 reductions

    /// `ADDQV` — SVE/SVE2 integer.
    static let addqv = Mnemonic(rawValue: 16474)
    /// `ANDQV` — SVE/SVE2 integer.
    static let andqv = Mnemonic(rawValue: 16476)
    /// `ANDV` — SVE/SVE2 integer.
    static let andv = Mnemonic(rawValue: 16477)
    /// `EORQV` — SVE/SVE2 integer.
    static let eorqv = Mnemonic(rawValue: 16501)
    /// `EORV` — SVE/SVE2 integer.
    static let eorv = Mnemonic(rawValue: 16503)
    /// `ORQV` — SVE/SVE2 integer.
    static let orqv = Mnemonic(rawValue: 16515)
    /// `ORV` — SVE/SVE2 integer.
    static let orv = Mnemonic(rawValue: 16516)
    /// `SADDV` — SVE/SVE2 integer.
    static let saddv = Mnemonic(rawValue: 16532)
    /// `SMAXQV` — SVE/SVE2 integer.
    static let smaxqv = Mnemonic(rawValue: 16542)
    /// `SMINQV` — SVE/SVE2 integer.
    static let sminqv = Mnemonic(rawValue: 16543)
    /// `UADDV` — SVE/SVE2 integer.
    static let uaddv = Mnemonic(rawValue: 16595)
    /// `UMAXQV` — SVE/SVE2 integer.
    static let umaxqv = Mnemonic(rawValue: 16601)
    /// `UMINQV` — SVE/SVE2 integer.
    static let uminqv = Mnemonic(rawValue: 16602)

    // MARK: G2 predicated shift

    /// `ASRD` — SVE/SVE2 integer.
    static let asrd = Mnemonic(rawValue: 16478)
    /// `ASRR` — SVE/SVE2 integer.
    static let asrr = Mnemonic(rawValue: 16479)
    /// `LSLR` — SVE/SVE2 integer.
    static let lslr = Mnemonic(rawValue: 16506)
    /// `LSRR` — SVE/SVE2 integer.
    static let lsrr = Mnemonic(rawValue: 16507)

    // MARK: G16 sve2 bitperm/misc

    /// `BDEP` — SVE/SVE2 integer.
    static let bdep = Mnemonic(rawValue: 16480)
    /// `BEXT` — SVE/SVE2 integer.
    static let bext = Mnemonic(rawValue: 16481)
    /// `BGRP` — SVE/SVE2 integer.
    static let bgrp = Mnemonic(rawValue: 16482)
    /// `EORBT` — SVE/SVE2 integer.
    static let eorbt = Mnemonic(rawValue: 16500)
    /// `EORTB` — SVE/SVE2 integer.
    static let eortb = Mnemonic(rawValue: 16502)
    /// `HISTCNT` — SVE/SVE2 integer.
    static let histcnt = Mnemonic(rawValue: 16504)
    /// `HISTSEG` — SVE/SVE2 integer.
    static let histseg = Mnemonic(rawValue: 16505)
    /// `MATCH` — SVE/SVE2 integer.
    static let match = Mnemonic(rawValue: 16510)
    /// `NMATCH` — SVE/SVE2 integer.
    static let nmatch = Mnemonic(rawValue: 16514)
    /// `PMULLB` — SVE/SVE2 integer.
    static let pmullb = Mnemonic(rawValue: 16517)
    /// `PMULLT` — SVE/SVE2 integer.
    static let pmullt = Mnemonic(rawValue: 16518)
    /// `SABDLB` — SVE/SVE2 integer.
    static let sabdlb = Mnemonic(rawValue: 16527)
    /// `SABDLT` — SVE/SVE2 integer.
    static let sabdlt = Mnemonic(rawValue: 16528)
    /// `SADDLB` — SVE/SVE2 integer.
    static let saddlb = Mnemonic(rawValue: 16529)
    /// `SADDLBT` — SVE/SVE2 integer.
    static let saddlbt = Mnemonic(rawValue: 16530)
    /// `SADDLT` — SVE/SVE2 integer.
    static let saddlt = Mnemonic(rawValue: 16531)
    /// `SADDWB` — SVE/SVE2 integer.
    static let saddwb = Mnemonic(rawValue: 16533)
    /// `SADDWT` — SVE/SVE2 integer.
    static let saddwt = Mnemonic(rawValue: 16534)
    /// `SMULLT` — SVE/SVE2 integer.
    static let smullt = Mnemonic(rawValue: 16549)
    /// `SQDMULLB` — SVE/SVE2 integer.
    static let sqdmullb = Mnemonic(rawValue: 16559)
    /// `SSUBLB` — SVE/SVE2 integer.
    static let ssublb = Mnemonic(rawValue: 16580)
    /// `SSUBLBT` — SVE/SVE2 integer.
    static let ssublbt = Mnemonic(rawValue: 16581)
    /// `SSUBLT` — SVE/SVE2 integer.
    static let ssublt = Mnemonic(rawValue: 16582)
    /// `SSUBLTB` — SVE/SVE2 integer.
    static let ssubltb = Mnemonic(rawValue: 16583)
    /// `SSUBWB` — SVE/SVE2 integer.
    static let ssubwb = Mnemonic(rawValue: 16584)
    /// `SSUBWT` — SVE/SVE2 integer.
    static let ssubwt = Mnemonic(rawValue: 16585)
    /// `UABDLB` — SVE/SVE2 integer.
    static let uabdlb = Mnemonic(rawValue: 16591)
    /// `UABDLT` — SVE/SVE2 integer.
    static let uabdlt = Mnemonic(rawValue: 16592)
    /// `UADDLB` — SVE/SVE2 integer.
    static let uaddlb = Mnemonic(rawValue: 16593)
    /// `UADDLT` — SVE/SVE2 integer.
    static let uaddlt = Mnemonic(rawValue: 16594)
    /// `UADDWB` — SVE/SVE2 integer.
    static let uaddwb = Mnemonic(rawValue: 16596)
    /// `UADDWT` — SVE/SVE2 integer.
    static let uaddwt = Mnemonic(rawValue: 16597)
    /// `UMULLB` — SVE/SVE2 integer.
    static let umullb = Mnemonic(rawValue: 16607)
    /// `UMULLT` — SVE/SVE2 integer.
    static let umullt = Mnemonic(rawValue: 16608)
    /// `USUBLB` — SVE/SVE2 integer.
    static let usublb = Mnemonic(rawValue: 16622)
    /// `USUBLT` — SVE/SVE2 integer.
    static let usublt = Mnemonic(rawValue: 16623)
    /// `USUBWB` — SVE/SVE2 integer.
    static let usubwb = Mnemonic(rawValue: 16624)
    /// `USUBWT` — SVE/SVE2 integer.
    static let usubwt = Mnemonic(rawValue: 16625)

    // MARK: G17 ternary

    /// `BSL1N` — SVE/SVE2 integer.
    static let bsl1n = Mnemonic(rawValue: 16483)
    /// `BSL2N` — SVE/SVE2 integer.
    static let bsl2n = Mnemonic(rawValue: 16484)
    /// `NBSL` — SVE/SVE2 integer.
    static let nbsl = Mnemonic(rawValue: 16513)

    // MARK: G13 sve2 complex

    /// `CADD` — SVE/SVE2 integer.
    static let cadd = Mnemonic(rawValue: 16485)
    /// `CDOT` — SVE/SVE2 integer.
    static let cdot = Mnemonic(rawValue: 16486)
    /// `CMLA` — SVE/SVE2 integer.
    static let cmla = Mnemonic(rawValue: 16487)
    /// `SQCADD` — SVE/SVE2 integer.
    static let sqcadd = Mnemonic(rawValue: 16550)
    /// `SQRDCMLAH` — SVE/SVE2 integer.
    static let sqrdcmlah = Mnemonic(rawValue: 16561)

    // MARK: G7 compare

    /// `CMPEQ` — SVE/SVE2 integer.
    static let cmpeq = Mnemonic(rawValue: 16488)
    /// `CMPGE` — SVE/SVE2 integer.
    static let cmpge = Mnemonic(rawValue: 16489)
    /// `CMPGT` — SVE/SVE2 integer.
    static let cmpgt = Mnemonic(rawValue: 16490)
    /// `CMPHI` — SVE/SVE2 integer.
    static let cmphi = Mnemonic(rawValue: 16491)
    /// `CMPHS` — SVE/SVE2 integer.
    static let cmphs = Mnemonic(rawValue: 16492)
    /// `CMPLE` — SVE/SVE2 integer.
    static let cmple = Mnemonic(rawValue: 16493)
    /// `CMPLO` — SVE/SVE2 integer.
    static let cmplo = Mnemonic(rawValue: 16494)
    /// `CMPLS` — SVE/SVE2 integer.
    static let cmpls = Mnemonic(rawValue: 16495)
    /// `CMPLT` — SVE/SVE2 integer.
    static let cmplt = Mnemonic(rawValue: 16496)
    /// `CMPNE` — SVE/SVE2 integer.
    static let cmpne = Mnemonic(rawValue: 16497)

    // MARK: G3 predicated unary

    /// `CNOT` — SVE/SVE2 integer.
    static let cnot = Mnemonic(rawValue: 16498)
    /// `UXTW` — SVE/SVE2 integer.
    static let uxtw = Mnemonic(rawValue: 16626)

    // MARK: G9 bitwise-imm

    /// `DUPM` — SVE/SVE2 integer.
    static let dupm = Mnemonic(rawValue: 16499)

    // MARK: G4 multiply-add

    /// `MAD` — SVE/SVE2 integer.
    static let mad = Mnemonic(rawValue: 16508)
    /// `MSB` — SVE/SVE2 integer.
    static let msb = Mnemonic(rawValue: 16512)

    // MARK: G21 cpa

    /// `MADPT` — SVE/SVE2 integer.
    static let madpt = Mnemonic(rawValue: 16509)
    /// `MLAPT` — SVE/SVE2 integer.
    static let mlapt = Mnemonic(rawValue: 16511)

    // MARK: G19 clamp

    /// `SCLAMP` — SVE/SVE2 integer.
    static let sclamp = Mnemonic(rawValue: 16537)
    /// `UCLAMP` — SVE/SVE2 integer.
    static let uclamp = Mnemonic(rawValue: 16598)

    // MARK: G1 predicated arith/logical

    /// `SDIVR` — SVE/SVE2 integer.
    static let sdivr = Mnemonic(rawValue: 16538)
    /// `UDIVR` — SVE/SVE2 integer.
    static let udivr = Mnemonic(rawValue: 16599)

    // MARK: G11 sve2 saturating

    /// `SHSUBR` — SVE/SVE2 integer.
    static let shsubr = Mnemonic(rawValue: 16541)
    /// `SQRSHLR` — SVE/SVE2 integer.
    static let sqrshlr = Mnemonic(rawValue: 16562)
    /// `SQSHLR` — SVE/SVE2 integer.
    static let sqshlr = Mnemonic(rawValue: 16567)
    /// `SQSUBR` — SVE/SVE2 integer.
    static let sqsubr = Mnemonic(rawValue: 16572)
    /// `SRSHLR` — SVE/SVE2 integer.
    static let srshlr = Mnemonic(rawValue: 16577)
    /// `UHSUBR` — SVE/SVE2 integer.
    static let uhsubr = Mnemonic(rawValue: 16600)
    /// `UQRSHLR` — SVE/SVE2 integer.
    static let uqrshlr = Mnemonic(rawValue: 16610)
    /// `UQSHLR` — SVE/SVE2 integer.
    static let uqshlr = Mnemonic(rawValue: 16613)
    /// `UQSUBR` — SVE/SVE2 integer.
    static let uqsubr = Mnemonic(rawValue: 16616)
    /// `URSHLR` — SVE/SVE2 integer.
    static let urshlr = Mnemonic(rawValue: 16619)

    // MARK: G15 sve2 shift-imm

    /// `SSHLLB` — SVE/SVE2 integer.
    static let sshllb = Mnemonic(rawValue: 16578)
    /// `SSHLLT` — SVE/SVE2 integer.
    static let sshllt = Mnemonic(rawValue: 16579)
    /// `USHLLB` — SVE/SVE2 integer.
    static let ushllb = Mnemonic(rawValue: 16620)
    /// `USHLLT` — SVE/SVE2 integer.
    static let ushllt = Mnemonic(rawValue: 16621)

    // MARK: G10 wide-imm

    /// `SUBR` — SVE/SVE2 integer.
    static let subr = Mnemonic(rawValue: 16588)
}
