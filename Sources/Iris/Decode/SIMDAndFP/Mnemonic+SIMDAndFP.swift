// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Mnemonic constants for the SIMD & Floating-Point family.
// Raw values within the family's reserved 6144..12287 slab.
//
// Mnemonics already declared by other families are REUSED here without
// redeclaration. From DPI: .add, .sub, .adds, .subs, .and, .orr,
// .eor, .ands, .mov, .cmp, .cmn, .tst, .lsl, .lsr, .asr, .ror,
// .movz/movn/movk, .adr/adrp, .bfm/sbfm/ubfm + aliases, .extr, .sxtb,
// .sxth, .sxtw, .uxtb, .uxth.
// From L/S: .ldr/.str/.ldp/.stp/.ldur/.stur/.ldnp/.stnp/.ldpsw/.stgp,
// .ldrb/.ldrh/.ldrsb/.ldrsh/.ldrsw/.strb/.strh + matching .ldurb-/.sturh-,
// .prfm/.prfum, the LDx/STx exclusive/acquire-release families, the
// LSE atomics LDADD/LDSET/LDCLR/LDEOR/SWP/CAS plus aliases, .ldraa/.ldrab,
// .ldtr/.sttr/.ldtrb-/.ldtrsw etc.
// From DPR: .bic, .orn, .eon, .bics, .mvn, .adc/.adcs/.sbc/.sbcs/.ngc/.ngcs,
// .neg/.negs, .ccmn/.ccmp, .csel/.csinc/.csinv/.csneg + .cset/.csetm/.cinc/.cinv/.cneg,
// .madd/.msub/.smaddl/.smsubl/.umaddl/.umsubl, .smulh/.umulh,
// .mul/.mneg/.smull/.smnegl/.umull/.umnegl, .udiv/.sdiv,
// .lslv/.lsrv/.asrv/.rorv (allocated but never emitted),
// .clz/.cls/.rbit/.rev/.rev16/.rev32, .crc32b-cx.

public extension Mnemonic {
    // MARK: - Slab 6144..6191 — AdvSIMD scalar arithmetic / compare / misc / pairwise / three-different / three-same-extra (new)

    static let sqadd = Mnemonic(rawValue: 6144)
    static let uqadd = Mnemonic(rawValue: 6145)
    static let sqsub = Mnemonic(rawValue: 6146)
    static let uqsub = Mnemonic(rawValue: 6147)
    static let cmtst = Mnemonic(rawValue: 6148)
    static let cmgt = Mnemonic(rawValue: 6149)
    static let cmge = Mnemonic(rawValue: 6150)
    static let cmeq = Mnemonic(rawValue: 6151)
    static let cmhi = Mnemonic(rawValue: 6152)
    static let cmhs = Mnemonic(rawValue: 6153)
    static let cmle = Mnemonic(rawValue: 6154)
    static let cmlt = Mnemonic(rawValue: 6155)
    static let sshl = Mnemonic(rawValue: 6156)
    static let ushl = Mnemonic(rawValue: 6157)
    static let sqshl = Mnemonic(rawValue: 6158)
    static let uqshl = Mnemonic(rawValue: 6159)
    static let srshl = Mnemonic(rawValue: 6160)
    static let urshl = Mnemonic(rawValue: 6161)
    static let sqrshl = Mnemonic(rawValue: 6162)
    static let uqrshl = Mnemonic(rawValue: 6163)
    static let sqdmulh = Mnemonic(rawValue: 6164)
    static let sqrdmulh = Mnemonic(rawValue: 6165)
    static let sqrdmlah = Mnemonic(rawValue: 6166)
    static let sqrdmlsh = Mnemonic(rawValue: 6167)
    static let sqdmlal = Mnemonic(rawValue: 6168)
    static let sqdmlsl = Mnemonic(rawValue: 6169)
    static let sqdmull = Mnemonic(rawValue: 6170)
    static let suqadd = Mnemonic(rawValue: 6171)
    static let usqadd = Mnemonic(rawValue: 6172)
    static let sqabs = Mnemonic(rawValue: 6173)
    static let sqneg = Mnemonic(rawValue: 6174)
    static let sqxtn = Mnemonic(rawValue: 6175)
    static let sqxtn2 = Mnemonic(rawValue: 6176)
    static let uqxtn = Mnemonic(rawValue: 6177)
    static let uqxtn2 = Mnemonic(rawValue: 6178)
    static let sqxtun = Mnemonic(rawValue: 6179)
    static let sqxtun2 = Mnemonic(rawValue: 6180)
    static let addp = Mnemonic(rawValue: 6181)
    static let abs = Mnemonic(rawValue: 6182)
    // .neg, .mul, .cls, .bic, .smull, .umull, .rbit, .rev, .rev16, .rev32 — REUSED from DPR

    // MARK: - Slab 6192..6239 — AdvSIMD scalar shift-by-immediate / x-indexed-element + SXTL/UXTL aliases

    static let sshr = Mnemonic(rawValue: 6192)
    static let ssra = Mnemonic(rawValue: 6193)
    static let srshr = Mnemonic(rawValue: 6194)
    static let srsra = Mnemonic(rawValue: 6195)
    static let shl = Mnemonic(rawValue: 6196)
    static let ushr = Mnemonic(rawValue: 6197)
    static let usra = Mnemonic(rawValue: 6198)
    static let urshr = Mnemonic(rawValue: 6199)
    static let ursra = Mnemonic(rawValue: 6200)
    static let sri = Mnemonic(rawValue: 6201)
    static let sli = Mnemonic(rawValue: 6202)
    static let sqshlu = Mnemonic(rawValue: 6203)
    static let shrn = Mnemonic(rawValue: 6204)
    static let shrn2 = Mnemonic(rawValue: 6205)
    static let rshrn = Mnemonic(rawValue: 6206)
    static let rshrn2 = Mnemonic(rawValue: 6207)
    static let sqshrn = Mnemonic(rawValue: 6208)
    static let sqshrn2 = Mnemonic(rawValue: 6209)
    static let sqrshrn = Mnemonic(rawValue: 6210)
    static let sqrshrn2 = Mnemonic(rawValue: 6211)
    static let uqshrn = Mnemonic(rawValue: 6212)
    static let uqshrn2 = Mnemonic(rawValue: 6213)
    static let uqrshrn = Mnemonic(rawValue: 6214)
    static let uqrshrn2 = Mnemonic(rawValue: 6215)
    static let sqshrun = Mnemonic(rawValue: 6216)
    static let sqshrun2 = Mnemonic(rawValue: 6217)
    static let sqrshrun = Mnemonic(rawValue: 6218)
    static let sqrshrun2 = Mnemonic(rawValue: 6219)
    static let sshll = Mnemonic(rawValue: 6220)
    static let sshll2 = Mnemonic(rawValue: 6221)
    static let ushll = Mnemonic(rawValue: 6222)
    static let ushll2 = Mnemonic(rawValue: 6223)
    static let sxtl = Mnemonic(rawValue: 6224)
    static let sxtl2 = Mnemonic(rawValue: 6225)
    static let uxtl = Mnemonic(rawValue: 6226)
    static let uxtl2 = Mnemonic(rawValue: 6227)

    // MARK: - Slab 6240..6271 — AdvSIMD scalar three-same FP16 / two-reg-misc FP16 (FRECPE / FRSQRTE / FCMxx-zero shared with vector forms)

    static let fmulx = Mnemonic(rawValue: 6240)
    static let frecps = Mnemonic(rawValue: 6241)
    static let frsqrts = Mnemonic(rawValue: 6242)
    static let fcmeq = Mnemonic(rawValue: 6243)
    static let fcmge = Mnemonic(rawValue: 6244)
    static let fcmgt = Mnemonic(rawValue: 6245)
    static let fcmle = Mnemonic(rawValue: 6246)
    static let fcmlt = Mnemonic(rawValue: 6247)
    static let facge = Mnemonic(rawValue: 6248)
    static let facgt = Mnemonic(rawValue: 6249)
    static let fabd = Mnemonic(rawValue: 6250)
    static let frecpe = Mnemonic(rawValue: 6251) // scalar AND vector FRECPE share this mnemonic
    static let frecpx = Mnemonic(rawValue: 6252)
    static let frsqrte = Mnemonic(rawValue: 6253) // scalar AND vector FRSQRTE share this mnemonic

    // MARK: - Slab 6272..6383 — AdvSIMD vector three-same (and FP family)

    static let shadd = Mnemonic(rawValue: 6272)
    static let srhadd = Mnemonic(rawValue: 6273)
    static let shsub = Mnemonic(rawValue: 6274)
    static let uhadd = Mnemonic(rawValue: 6275)
    static let urhadd = Mnemonic(rawValue: 6276)
    static let uhsub = Mnemonic(rawValue: 6277)
    static let smax = Mnemonic(rawValue: 6278)
    static let smin = Mnemonic(rawValue: 6279)
    static let umax = Mnemonic(rawValue: 6280)
    static let umin = Mnemonic(rawValue: 6281)
    static let sabd = Mnemonic(rawValue: 6282)
    static let uabd = Mnemonic(rawValue: 6283)
    static let saba = Mnemonic(rawValue: 6284)
    static let uaba = Mnemonic(rawValue: 6285)
    static let mla = Mnemonic(rawValue: 6286)
    static let mls = Mnemonic(rawValue: 6287)
    static let pmul = Mnemonic(rawValue: 6289)
    static let smaxp = Mnemonic(rawValue: 6290)
    static let sminp = Mnemonic(rawValue: 6291)
    static let umaxp = Mnemonic(rawValue: 6292)
    static let uminp = Mnemonic(rawValue: 6293)
    static let bsl = Mnemonic(rawValue: 6294)
    static let bit = Mnemonic(rawValue: 6295)
    static let bif = Mnemonic(rawValue: 6296)
    static let fmaxnm = Mnemonic(rawValue: 6297)
    static let fminnm = Mnemonic(rawValue: 6298)
    static let fmax = Mnemonic(rawValue: 6299)
    static let fmin = Mnemonic(rawValue: 6300)
    static let fmla = Mnemonic(rawValue: 6301)
    static let fmls = Mnemonic(rawValue: 6302)
    static let fadd = Mnemonic(rawValue: 6303)
    static let fsub = Mnemonic(rawValue: 6304)
    static let fmaxnmp = Mnemonic(rawValue: 6305)
    static let fminnmp = Mnemonic(rawValue: 6306)
    static let fmul = Mnemonic(rawValue: 6307)
    static let fdiv = Mnemonic(rawValue: 6308)
    static let faddp = Mnemonic(rawValue: 6309)
    static let fmaxp = Mnemonic(rawValue: 6310)
    static let fminp = Mnemonic(rawValue: 6311)
    // .mul, .neg, .abs, .bic — see above (.bic, .mul, .neg are reused; .abs is new at 6182)

    // MARK: - Slab 6384..6463 — AdvSIMD vector three-different / two-reg-misc / across-lanes (new mnemonics)

    static let saddl = Mnemonic(rawValue: 6384)
    static let saddl2 = Mnemonic(rawValue: 6385)
    static let saddw = Mnemonic(rawValue: 6386)
    static let saddw2 = Mnemonic(rawValue: 6387)
    static let ssubl = Mnemonic(rawValue: 6388)
    static let ssubl2 = Mnemonic(rawValue: 6389)
    static let ssubw = Mnemonic(rawValue: 6390)
    static let ssubw2 = Mnemonic(rawValue: 6391)
    static let addhn = Mnemonic(rawValue: 6392)
    static let addhn2 = Mnemonic(rawValue: 6393)
    static let sabal = Mnemonic(rawValue: 6394)
    static let sabal2 = Mnemonic(rawValue: 6395)
    static let subhn = Mnemonic(rawValue: 6396)
    static let subhn2 = Mnemonic(rawValue: 6397)
    static let sabdl = Mnemonic(rawValue: 6398)
    static let sabdl2 = Mnemonic(rawValue: 6399)
    static let smlal = Mnemonic(rawValue: 6400)
    static let smlal2 = Mnemonic(rawValue: 6401)
    static let smlsl = Mnemonic(rawValue: 6402)
    static let smlsl2 = Mnemonic(rawValue: 6403)
    static let smull2 = Mnemonic(rawValue: 6405)
    static let pmull = Mnemonic(rawValue: 6406)
    static let pmull2 = Mnemonic(rawValue: 6407)
    static let uaddl = Mnemonic(rawValue: 6408)
    static let uaddl2 = Mnemonic(rawValue: 6409)
    static let uaddw = Mnemonic(rawValue: 6410)
    static let uaddw2 = Mnemonic(rawValue: 6411)
    static let usubl = Mnemonic(rawValue: 6412)
    static let usubl2 = Mnemonic(rawValue: 6413)
    static let usubw = Mnemonic(rawValue: 6414)
    static let usubw2 = Mnemonic(rawValue: 6415)
    static let raddhn = Mnemonic(rawValue: 6416)
    static let raddhn2 = Mnemonic(rawValue: 6417)
    static let uabal = Mnemonic(rawValue: 6418)
    static let uabal2 = Mnemonic(rawValue: 6419)
    static let rsubhn = Mnemonic(rawValue: 6420)
    static let rsubhn2 = Mnemonic(rawValue: 6421)
    static let uabdl = Mnemonic(rawValue: 6422)
    static let uabdl2 = Mnemonic(rawValue: 6423)
    static let umlal = Mnemonic(rawValue: 6424)
    static let umlal2 = Mnemonic(rawValue: 6425)
    static let umlsl = Mnemonic(rawValue: 6426)
    static let umlsl2 = Mnemonic(rawValue: 6427)
    static let umull2 = Mnemonic(rawValue: 6429)
    static let sqdmlal2 = Mnemonic(rawValue: 6430)
    static let sqdmlsl2 = Mnemonic(rawValue: 6431)
    static let sqdmull2 = Mnemonic(rawValue: 6432)
    static let rev64 = Mnemonic(rawValue: 6433) // .rev16, .rev32 reused from DPR; rev64 is new
    static let saddlp = Mnemonic(rawValue: 6434)
    static let uaddlp = Mnemonic(rawValue: 6435)
    static let sadalp = Mnemonic(rawValue: 6436)
    static let uadalp = Mnemonic(rawValue: 6437)
    static let cnt = Mnemonic(rawValue: 6438)
    static let xtn = Mnemonic(rawValue: 6439)
    static let xtn2 = Mnemonic(rawValue: 6440)
    static let shll = Mnemonic(rawValue: 6441)
    static let shll2 = Mnemonic(rawValue: 6442)
    static let urecpe = Mnemonic(rawValue: 6443)
    static let ursqrte = Mnemonic(rawValue: 6444)
    static let saddlv = Mnemonic(rawValue: 6447)
    static let smaxv = Mnemonic(rawValue: 6448)
    static let sminv = Mnemonic(rawValue: 6449)
    static let addv = Mnemonic(rawValue: 6450)
    static let uaddlv = Mnemonic(rawValue: 6451)
    static let umaxv = Mnemonic(rawValue: 6452)
    static let uminv = Mnemonic(rawValue: 6453)
    static let fmaxnmv = Mnemonic(rawValue: 6454)
    static let fmaxv = Mnemonic(rawValue: 6455)
    static let fminnmv = Mnemonic(rawValue: 6456)
    static let fminv = Mnemonic(rawValue: 6457)
    static let not = Mnemonic(rawValue: 6459) // canonical NOT vector; MVN alias preferred (.mvn reused from DPR)

    // MARK: - Slab 6464..6527 — AdvSIMD vector three-reg-extension (DOT/MMLA/USDOT/BFDOT/BFMMLA)

    static let sdot = Mnemonic(rawValue: 6464)
    static let udot = Mnemonic(rawValue: 6465)
    static let usdot = Mnemonic(rawValue: 6466)
    static let sudot = Mnemonic(rawValue: 6467)
    static let bfdot = Mnemonic(rawValue: 6468)
    static let bfmlalb = Mnemonic(rawValue: 6469)
    static let bfmlalt = Mnemonic(rawValue: 6470)
    static let bfmmla = Mnemonic(rawValue: 6471)
    static let bfcvt = Mnemonic(rawValue: 6472)
    static let smmla = Mnemonic(rawValue: 6473)
    static let ummla = Mnemonic(rawValue: 6474)
    static let usmmla = Mnemonic(rawValue: 6475)
    static let fmlal = Mnemonic(rawValue: 6476)
    static let fmlal2 = Mnemonic(rawValue: 6477)
    static let fmlsl = Mnemonic(rawValue: 6478)
    static let fmlsl2 = Mnemonic(rawValue: 6479)

    // MARK: - Slab 6576..6623 — AdvSIMD modified-immediate / vector copy (DUP/INS/UMOV/SMOV)

    static let movi = Mnemonic(rawValue: 6576)
    static let mvni = Mnemonic(rawValue: 6577)
    static let dup = Mnemonic(rawValue: 6578)
    static let ins = Mnemonic(rawValue: 6579)
    static let umov = Mnemonic(rawValue: 6580)
    static let smov = Mnemonic(rawValue: 6581)
    // .bic for vector immediate REUSES DPR's .bic; .mov for register/element/UMOV-S/D aliases REUSES DPI's .mov

    // MARK: - Slab 6624..6671 — AdvSIMD permute / extract / table lookup

    static let uzp1 = Mnemonic(rawValue: 6624)
    static let uzp2 = Mnemonic(rawValue: 6625)
    static let trn1 = Mnemonic(rawValue: 6626)
    static let trn2 = Mnemonic(rawValue: 6627)
    static let zip1 = Mnemonic(rawValue: 6628)
    static let zip2 = Mnemonic(rawValue: 6629)
    static let ext = Mnemonic(rawValue: 6630)
    static let tbl = Mnemonic(rawValue: 6631)
    static let tbx = Mnemonic(rawValue: 6632)

    // MARK: - Slab 6672..6735 — FP data-processing 1-source

    static let fmov = Mnemonic(rawValue: 6672)
    static let fabs = Mnemonic(rawValue: 6673)
    static let fneg = Mnemonic(rawValue: 6674)
    static let fsqrt = Mnemonic(rawValue: 6675)
    static let fcvt = Mnemonic(rawValue: 6676)
    static let frintn = Mnemonic(rawValue: 6677)
    static let frintp = Mnemonic(rawValue: 6678)
    static let frintm = Mnemonic(rawValue: 6679)
    static let frintz = Mnemonic(rawValue: 6680)
    static let frinta = Mnemonic(rawValue: 6681)
    static let frintx = Mnemonic(rawValue: 6682)
    static let frinti = Mnemonic(rawValue: 6683)
    static let frint32z = Mnemonic(rawValue: 6684)
    static let frint32x = Mnemonic(rawValue: 6685)
    static let frint64z = Mnemonic(rawValue: 6686)
    static let frint64x = Mnemonic(rawValue: 6687)
    static let fcvtl = Mnemonic(rawValue: 6688)
    static let fcvtl2 = Mnemonic(rawValue: 6689)
    static let fcvtn = Mnemonic(rawValue: 6690)
    static let fcvtn2 = Mnemonic(rawValue: 6691)
    static let fcvtxn = Mnemonic(rawValue: 6692)
    static let fcvtxn2 = Mnemonic(rawValue: 6693)

    // MARK: - Slab 6736..6783 — FP data-processing 2/3-source

    static let fnmul = Mnemonic(rawValue: 6736)
    static let fmadd = Mnemonic(rawValue: 6737)
    static let fmsub = Mnemonic(rawValue: 6738)
    static let fnmadd = Mnemonic(rawValue: 6739)
    static let fnmsub = Mnemonic(rawValue: 6740)

    // MARK: - Slab 6784..6815 — FP integer conversion (FCVT family + FJCVTZS + SCVTF/UCVTF)

    // SCVTF/UCVTF/FCVTZS/FCVTZU mnemonics are shared between integer and
    // fixed-point conversion forms (llvm-mc emits same name for both
    // shapes); a single Mnemonic per name covers both.
    static let fcvtas = Mnemonic(rawValue: 6784)
    static let fcvtau = Mnemonic(rawValue: 6785)
    static let fcvtms = Mnemonic(rawValue: 6786)
    static let fcvtmu = Mnemonic(rawValue: 6787)
    static let fcvtns = Mnemonic(rawValue: 6788)
    static let fcvtnu = Mnemonic(rawValue: 6789)
    static let fcvtps = Mnemonic(rawValue: 6790)
    static let fcvtpu = Mnemonic(rawValue: 6791)
    static let fcvtzs = Mnemonic(rawValue: 6792)
    static let fcvtzu = Mnemonic(rawValue: 6793)
    static let fjcvtzs = Mnemonic(rawValue: 6794)

    // FEAT_FAMINMAX (vector FAMAX/FAMIN) + FEAT_FP8 FSCALE — three-same v9.
    // Raw values 6932-6934 (after the prior max 6931); 6795-6797 collided
    // with scvtf/ucvtf and silently shadowed them in the canonicalizer.
    static let famax = Mnemonic(rawValue: 6932)
    static let famin = Mnemonic(rawValue: 6933)
    static let fscale = Mnemonic(rawValue: 6934)
    static let fcmla = Mnemonic(rawValue: 6935)
    static let fcadd = Mnemonic(rawValue: 6936)
    static let fdot = Mnemonic(rawValue: 6937)
    static let fmlalb = Mnemonic(rawValue: 6938)
    static let fmlalt = Mnemonic(rawValue: 6939)
    static let fmlallbb = Mnemonic(rawValue: 6940)
    static let fmlallbt = Mnemonic(rawValue: 6941)
    static let fmlalltb = Mnemonic(rawValue: 6942)
    static let fmlalltt = Mnemonic(rawValue: 6943)
    static let luti2 = Mnemonic(rawValue: 6944)
    static let luti4 = Mnemonic(rawValue: 6945)
    static let bfcvtn = Mnemonic(rawValue: 6946)
    static let bfcvtn2 = Mnemonic(rawValue: 6947)
    static let f1cvtl = Mnemonic(rawValue: 6948)
    static let f1cvtl2 = Mnemonic(rawValue: 6949)
    static let f2cvtl = Mnemonic(rawValue: 6950)
    static let f2cvtl2 = Mnemonic(rawValue: 6951)
    static let bf1cvtl = Mnemonic(rawValue: 6952)
    static let bf1cvtl2 = Mnemonic(rawValue: 6953)
    static let bf2cvtl = Mnemonic(rawValue: 6954)
    static let bf2cvtl2 = Mnemonic(rawValue: 6955)
    static let scvtf = Mnemonic(rawValue: 6795)
    static let ucvtf = Mnemonic(rawValue: 6796)

    // MARK: - Slab 6832..6863 — FP compare / cond-compare / cond-select / immediate

    static let fcmp = Mnemonic(rawValue: 6832)
    static let fcmpe = Mnemonic(rawValue: 6833)
    static let fccmp = Mnemonic(rawValue: 6834)
    static let fccmpe = Mnemonic(rawValue: 6835)
    static let fcsel = Mnemonic(rawValue: 6836)

    // MARK: - Slab 6864..6927 — AdvSIMD load/store multi-structure mnemonics

    // LD1/LD2/LD3/LD4 cover both multi-structure and single-structure (with
    // element subscript) forms — same mnemonic, different operand shape.
    static let ld1 = Mnemonic(rawValue: 6864)
    static let ld2 = Mnemonic(rawValue: 6865)
    static let ld3 = Mnemonic(rawValue: 6866)
    static let ld4 = Mnemonic(rawValue: 6867)
    static let st1 = Mnemonic(rawValue: 6868)
    static let st2 = Mnemonic(rawValue: 6869)
    static let st3 = Mnemonic(rawValue: 6870)
    static let st4 = Mnemonic(rawValue: 6871)

    // FEAT_RCPC3 ordered SIMD single-element: load-acquire / store-release of
    // one .d lane (`ldap1`/`stl1 { Vt.d }[index], [Xn]`), distinct from ld1/st1
    // by their acquire/release ordering. Raw values continue past the current
    // SIMD maximum.
    static let ldap1 = Mnemonic(rawValue: 6956)
    static let stl1 = Mnemonic(rawValue: 6957)

    // MARK: - Slab 6928..6991 — AdvSIMD load/store single-structure replicate

    static let ld1r = Mnemonic(rawValue: 6928)
    static let ld2r = Mnemonic(rawValue: 6929)
    static let ld3r = Mnemonic(rawValue: 6930)
    static let ld4r = Mnemonic(rawValue: 6931)

    // MARK: - Slab 7168..7295 reserved sentinel (must be in-range; not directly emitted)

    // Held back for future SIMD/FP additions as a reserved tail.
}

extension Mnemonic {
    /// Canonical lowercase name for every SIMD & Floating-Point mnemonic constant —
    /// the family's slice of ``Mnemonic/name``, declared beside the
    /// constants it names so the two cannot drift. Unallocated raw
    /// values in the family's range return `"?<raw>"`.
    static func simdAndFPName(_ m: Mnemonic) -> String {
        switch m {
        case .sqadd: "sqadd"
        case .uqadd: "uqadd"
        case .sqsub: "sqsub"
        case .uqsub: "uqsub"
        case .cmtst: "cmtst"
        case .cmgt: "cmgt"
        case .cmge: "cmge"
        case .cmeq: "cmeq"
        case .cmhi: "cmhi"
        case .cmhs: "cmhs"
        case .cmle: "cmle"
        case .cmlt: "cmlt"
        case .sshl: "sshl"
        case .ushl: "ushl"
        case .sqshl: "sqshl"
        case .uqshl: "uqshl"
        case .srshl: "srshl"
        case .urshl: "urshl"
        case .sqrshl: "sqrshl"
        case .uqrshl: "uqrshl"
        case .sqdmulh: "sqdmulh"
        case .sqrdmulh: "sqrdmulh"
        case .sqrdmlah: "sqrdmlah"
        case .sqrdmlsh: "sqrdmlsh"
        case .sqdmlal: "sqdmlal"
        case .sqdmlsl: "sqdmlsl"
        case .sqdmull: "sqdmull"
        case .suqadd: "suqadd"
        case .usqadd: "usqadd"
        case .sqabs: "sqabs"
        case .sqneg: "sqneg"
        case .sqxtn: "sqxtn"
        case .sqxtn2: "sqxtn2"
        case .uqxtn: "uqxtn"
        case .uqxtn2: "uqxtn2"
        case .sqxtun: "sqxtun"
        case .sqxtun2: "sqxtun2"
        case .addp: "addp"
        case .abs: "abs"
        case .sshr: "sshr"
        case .ssra: "ssra"
        case .srshr: "srshr"
        case .srsra: "srsra"
        case .shl: "shl"
        case .ushr: "ushr"
        case .usra: "usra"
        case .urshr: "urshr"
        case .ursra: "ursra"
        case .sri: "sri"
        case .sli: "sli"
        case .sqshlu: "sqshlu"
        case .shrn: "shrn"
        case .shrn2: "shrn2"
        case .rshrn: "rshrn"
        case .rshrn2: "rshrn2"
        case .sqshrn: "sqshrn"
        case .sqshrn2: "sqshrn2"
        case .sqrshrn: "sqrshrn"
        case .sqrshrn2: "sqrshrn2"
        case .uqshrn: "uqshrn"
        case .uqshrn2: "uqshrn2"
        case .uqrshrn: "uqrshrn"
        case .uqrshrn2: "uqrshrn2"
        case .sqshrun: "sqshrun"
        case .sqshrun2: "sqshrun2"
        case .sqrshrun: "sqrshrun"
        case .sqrshrun2: "sqrshrun2"
        case .sshll: "sshll"
        case .sshll2: "sshll2"
        case .ushll: "ushll"
        case .ushll2: "ushll2"
        case .sxtl: "sxtl"
        case .sxtl2: "sxtl2"
        case .uxtl: "uxtl"
        case .uxtl2: "uxtl2"
        case .fmulx: "fmulx"
        case .frecps: "frecps"
        case .frsqrts: "frsqrts"
        case .fcmeq: "fcmeq"
        case .fcmge: "fcmge"
        case .fcmgt: "fcmgt"
        case .fcmle: "fcmle"
        case .fcmlt: "fcmlt"
        case .facge: "facge"
        case .facgt: "facgt"
        case .fabd: "fabd"
        case .frecpe: "frecpe"
        case .frecpx: "frecpx"
        case .frsqrte: "frsqrte"
        case .shadd: "shadd"
        case .srhadd: "srhadd"
        case .shsub: "shsub"
        case .uhadd: "uhadd"
        case .urhadd: "urhadd"
        case .uhsub: "uhsub"
        case .smax: "smax"
        case .smin: "smin"
        case .umax: "umax"
        case .umin: "umin"
        case .sabd: "sabd"
        case .uabd: "uabd"
        case .saba: "saba"
        case .uaba: "uaba"
        case .mla: "mla"
        case .mls: "mls"
        case .pmul: "pmul"
        case .smaxp: "smaxp"
        case .sminp: "sminp"
        case .umaxp: "umaxp"
        case .uminp: "uminp"
        case .bsl: "bsl"
        case .bit: "bit"
        case .bif: "bif"
        case .fmaxnm: "fmaxnm"
        case .fminnm: "fminnm"
        case .fmax: "fmax"
        case .fmin: "fmin"
        case .fmla: "fmla"
        case .fmls: "fmls"
        case .fadd: "fadd"
        case .fsub: "fsub"
        case .fmaxnmp: "fmaxnmp"
        case .fminnmp: "fminnmp"
        case .fmul: "fmul"
        case .fdiv: "fdiv"
        case .faddp: "faddp"
        case .fmaxp: "fmaxp"
        case .fminp: "fminp"
        case .saddl: "saddl"
        case .saddl2: "saddl2"
        case .saddw: "saddw"
        case .saddw2: "saddw2"
        case .ssubl: "ssubl"
        case .ssubl2: "ssubl2"
        case .ssubw: "ssubw"
        case .ssubw2: "ssubw2"
        case .addhn: "addhn"
        case .addhn2: "addhn2"
        case .sabal: "sabal"
        case .sabal2: "sabal2"
        case .subhn: "subhn"
        case .subhn2: "subhn2"
        case .sabdl: "sabdl"
        case .sabdl2: "sabdl2"
        case .smlal: "smlal"
        case .smlal2: "smlal2"
        case .smlsl: "smlsl"
        case .smlsl2: "smlsl2"
        case .smull2: "smull2"
        case .pmull: "pmull"
        case .pmull2: "pmull2"
        case .uaddl: "uaddl"
        case .uaddl2: "uaddl2"
        case .uaddw: "uaddw"
        case .uaddw2: "uaddw2"
        case .usubl: "usubl"
        case .usubl2: "usubl2"
        case .usubw: "usubw"
        case .usubw2: "usubw2"
        case .raddhn: "raddhn"
        case .raddhn2: "raddhn2"
        case .uabal: "uabal"
        case .uabal2: "uabal2"
        case .rsubhn: "rsubhn"
        case .rsubhn2: "rsubhn2"
        case .uabdl: "uabdl"
        case .uabdl2: "uabdl2"
        case .umlal: "umlal"
        case .umlal2: "umlal2"
        case .umlsl: "umlsl"
        case .umlsl2: "umlsl2"
        case .umull2: "umull2"
        case .sqdmlal2: "sqdmlal2"
        case .sqdmlsl2: "sqdmlsl2"
        case .sqdmull2: "sqdmull2"
        case .rev64: "rev64"
        case .saddlp: "saddlp"
        case .uaddlp: "uaddlp"
        case .sadalp: "sadalp"
        case .uadalp: "uadalp"
        case .cnt: "cnt"
        case .xtn: "xtn"
        case .xtn2: "xtn2"
        case .shll: "shll"
        case .shll2: "shll2"
        case .urecpe: "urecpe"
        case .ursqrte: "ursqrte"
        case .saddlv: "saddlv"
        case .smaxv: "smaxv"
        case .sminv: "sminv"
        case .addv: "addv"
        case .uaddlv: "uaddlv"
        case .umaxv: "umaxv"
        case .uminv: "uminv"
        case .fmaxnmv: "fmaxnmv"
        case .fmaxv: "fmaxv"
        case .fminnmv: "fminnmv"
        case .fminv: "fminv"
        case .not: "not"
        case .sdot: "sdot"
        case .udot: "udot"
        case .usdot: "usdot"
        case .sudot: "sudot"
        case .bfdot: "bfdot"
        case .bfmlalb: "bfmlalb"
        case .bfmlalt: "bfmlalt"
        case .bfmmla: "bfmmla"
        case .bfcvt: "bfcvt"
        case .smmla: "smmla"
        case .ummla: "ummla"
        case .usmmla: "usmmla"
        case .fmlal: "fmlal"
        case .fmlal2: "fmlal2"
        case .fmlsl: "fmlsl"
        case .fmlsl2: "fmlsl2"
        case .movi: "movi"
        case .mvni: "mvni"
        case .dup: "dup"
        case .ins: "ins"
        case .umov: "umov"
        case .smov: "smov"
        case .uzp1: "uzp1"
        case .uzp2: "uzp2"
        case .trn1: "trn1"
        case .trn2: "trn2"
        case .zip1: "zip1"
        case .zip2: "zip2"
        case .ext: "ext"
        case .tbl: "tbl"
        case .tbx: "tbx"
        case .fmov: "fmov"
        case .fabs: "fabs"
        case .fneg: "fneg"
        case .fsqrt: "fsqrt"
        case .fcvt: "fcvt"
        case .frintn: "frintn"
        case .frintp: "frintp"
        case .frintm: "frintm"
        case .frintz: "frintz"
        case .frinta: "frinta"
        case .frintx: "frintx"
        case .frinti: "frinti"
        case .frint32z: "frint32z"
        case .frint32x: "frint32x"
        case .frint64z: "frint64z"
        case .frint64x: "frint64x"
        case .fcvtl: "fcvtl"
        case .fcvtl2: "fcvtl2"
        case .fcvtn: "fcvtn"
        case .fcvtn2: "fcvtn2"
        case .fcvtxn: "fcvtxn"
        case .fcvtxn2: "fcvtxn2"
        case .fnmul: "fnmul"
        case .fmadd: "fmadd"
        case .fmsub: "fmsub"
        case .fnmadd: "fnmadd"
        case .fnmsub: "fnmsub"
        case .fcvtas: "fcvtas"
        case .fcvtau: "fcvtau"
        case .fcvtms: "fcvtms"
        case .fcvtmu: "fcvtmu"
        case .fcvtns: "fcvtns"
        case .fcvtnu: "fcvtnu"
        case .fcvtps: "fcvtps"
        case .fcvtpu: "fcvtpu"
        case .fcvtzs: "fcvtzs"
        case .fcvtzu: "fcvtzu"
        case .fjcvtzs: "fjcvtzs"
        case .scvtf: "scvtf"
        case .ucvtf: "ucvtf"
        case .fcmp: "fcmp"
        case .fcmpe: "fcmpe"
        case .fccmp: "fccmp"
        case .fccmpe: "fccmpe"
        case .fcsel: "fcsel"
        case .ld1: "ld1"
        case .ld2: "ld2"
        case .ld3: "ld3"
        case .ld4: "ld4"
        case .st1: "st1"
        case .st2: "st2"
        case .st3: "st3"
        case .st4: "st4"
        case .ld1r: "ld1r"
        case .ld2r: "ld2r"
        case .ld3r: "ld3r"
        case .ld4r: "ld4r"
        case .famax: "famax"
        case .famin: "famin"
        case .fscale: "fscale"
        case .fcmla: "fcmla"
        case .fcadd: "fcadd"
        case .fdot: "fdot"
        case .fmlalb: "fmlalb"
        case .fmlalt: "fmlalt"
        case .fmlallbb: "fmlallbb"
        case .fmlallbt: "fmlallbt"
        case .fmlalltb: "fmlalltb"
        case .fmlalltt: "fmlalltt"
        case .luti2: "luti2"
        case .luti4: "luti4"
        case .bfcvtn: "bfcvtn"
        case .bfcvtn2: "bfcvtn2"
        case .f1cvtl: "f1cvtl"
        case .f1cvtl2: "f1cvtl2"
        case .f2cvtl: "f2cvtl"
        case .f2cvtl2: "f2cvtl2"
        case .bf1cvtl: "bf1cvtl"
        case .bf1cvtl2: "bf1cvtl2"
        case .bf2cvtl: "bf2cvtl"
        case .bf2cvtl2: "bf2cvtl2"
        case .ldap1: "ldap1"
        case .stl1: "stl1"
        default: "?\(m.rawValue)"
        }
    }
}
