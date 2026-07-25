// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// SME2 multi-vector mnemonic tokens, continuing the SME/SME2
// slab (28672..<40960) at 28689. Shared architectural mnemonics (`mov`,
// `ldr`, `str`, `zero`, `add`, `sub`, the dot/mla/minmax/shift/convert/
// narrow families, the SVE-tier B16B16/FP8 tokens, `luti2`/`luti4`/`luti6`,
// the `ld1*`/`st1*`/`ldnt1*`/`stnt1*` loads, the `while*` conditions,
// `ptrue`, `cntp`, `sel`, and the SME-core outer-product tokens) are reused
// verbatim — the record's mnemonic is the preferred-alias-resolved identity,
// and the operand shape plus category disambiguate the SME2 forms from their
// same-named peers. Only the tokens no earlier family declared live here.

public extension Mnemonic {
    /// SME2p1 `MOVAZ` — move `ZA` slices to vectors, zeroing the source.
    static let movaz = Mnemonic(rawValue: 28689)
    /// SME2 `MOVT` — move between a GPR (or vector) and `ZT0`.
    static let movt = Mnemonic(rawValue: 28690)

    /// SME2 `ZIP` — interleave a multi-vector group.
    static let zip = Mnemonic(rawValue: 28691)
    /// SME2 `UZP` — de-interleave a multi-vector group.
    static let uzp = Mnemonic(rawValue: 28692)
    /// SME2 `SUNPK` — signed unpack into a multi-vector group.
    static let sunpk = Mnemonic(rawValue: 28693)
    /// SME2 `UUNPK` — unsigned unpack into a multi-vector group.
    static let uunpk = Mnemonic(rawValue: 28694)

    /// SME2 `BFMLAL` — BFloat16 widening multiply-add into `ZA`.
    static let bfmlal = Mnemonic(rawValue: 28695)
    /// SME2 `BFMLSL` — BFloat16 widening multiply-subtract into `ZA`.
    static let bfmlsl = Mnemonic(rawValue: 28696)
    /// SME2 `SMLALL` — signed quad-widening multiply-add into `ZA`.
    static let smlall = Mnemonic(rawValue: 28697)
    /// SME2 `UMLALL` — unsigned quad-widening multiply-add into `ZA`.
    static let umlall = Mnemonic(rawValue: 28698)
    /// SME2 `SMLSLL` — signed quad-widening multiply-subtract into `ZA`.
    static let smlsll = Mnemonic(rawValue: 28699)
    /// SME2 `UMLSLL` — unsigned quad-widening multiply-subtract into `ZA`.
    static let umlsll = Mnemonic(rawValue: 28700)
    /// SME2 `USMLALL` — unsigned-by-signed quad-widening multiply-add.
    static let usmlall = Mnemonic(rawValue: 28701)
    /// SME2 `SUMLALL` — signed-by-unsigned quad-widening multiply-add.
    static let sumlall = Mnemonic(rawValue: 28702)
    /// SME2 `FMLALL` (FP8) — quad-widening multiply-add into `ZA`.
    static let fmlall = Mnemonic(rawValue: 28703)

    /// SME2 `FVDOT` — floating-point vertical dot product into `ZA`.
    static let fvdot = Mnemonic(rawValue: 28704)
    /// SME2 `BFVDOT` — BFloat16 vertical dot product into `ZA`.
    static let bfvdot = Mnemonic(rawValue: 28705)
    /// SME2 `SVDOT` — signed vertical dot product into `ZA`.
    static let svdot = Mnemonic(rawValue: 28706)
    /// SME2 `UVDOT` — unsigned vertical dot product into `ZA`.
    static let uvdot = Mnemonic(rawValue: 28707)
    /// SME2 `SUVDOT` — signed-by-unsigned vertical dot product into `ZA`.
    static let suvdot = Mnemonic(rawValue: 28708)
    /// SME2 `USVDOT` — unsigned-by-signed vertical dot product into `ZA`.
    static let usvdot = Mnemonic(rawValue: 28709)
    /// SME2 `FVDOTB` (FP8) — vertical dot product, bottom half, into `ZA`.
    static let fvdotb = Mnemonic(rawValue: 28710)
    /// SME2 `FVDOTT` (FP8) — vertical dot product, top half, into `ZA`.
    static let fvdott = Mnemonic(rawValue: 28711)

    /// SME2 `SQCVT` — signed saturating narrowing convert of a group.
    static let sqcvt = Mnemonic(rawValue: 28712)
    /// SME2 `UQCVT` — unsigned saturating narrowing convert of a group.
    static let uqcvt = Mnemonic(rawValue: 28713)
    /// SME2 `SQCVTU` — signed-to-unsigned saturating narrowing convert.
    static let sqcvtu = Mnemonic(rawValue: 28714)
    /// SME2 `SQRSHR` — signed saturating rounding shift-right narrow.
    static let sqrshr = Mnemonic(rawValue: 28715)
    /// SME2 `UQRSHR` — unsigned saturating rounding shift-right narrow.
    static let uqrshr = Mnemonic(rawValue: 28716)
    /// SME2 `SQRSHRU` — signed-to-unsigned saturating rounding shift-right
    /// narrow.
    static let sqrshru = Mnemonic(rawValue: 28717)

    /// SME2 `PEXT` — extract a predicate (or pair) from a counter predicate.
    static let pext = Mnemonic(rawValue: 28718)
    /// SME `PSEL` — predicate select by indexed element.
    static let psel = Mnemonic(rawValue: 28719)
    /// SVE2p2 `FIRSTP` — index of the first active predicate element.
    static let firstp = Mnemonic(rawValue: 28720)
    /// SVE2p2 `LASTP` — index of the last active predicate element.
    static let lastp = Mnemonic(rawValue: 28721)

    /// SME `FMOP4A` — quarter-tile FP outer product, accumulating.
    static let fmop4a = Mnemonic(rawValue: 28722)
    /// SME `FMOP4S` — quarter-tile FP outer product, subtracting.
    static let fmop4s = Mnemonic(rawValue: 28723)
    /// SME `BFMOP4A` — quarter-tile BFloat16 outer product, accumulating.
    static let bfmop4a = Mnemonic(rawValue: 28724)
    /// SME `BFMOP4S` — quarter-tile BFloat16 outer product, subtracting.
    static let bfmop4s = Mnemonic(rawValue: 28725)
    /// SME `SMOP4A` — quarter-tile signed outer product, accumulating.
    static let smop4a = Mnemonic(rawValue: 28726)
    /// SME `SMOP4S` — quarter-tile signed outer product, subtracting.
    static let smop4s = Mnemonic(rawValue: 28727)
    /// SME `UMOP4A` — quarter-tile unsigned outer product, accumulating.
    static let umop4a = Mnemonic(rawValue: 28728)
    /// SME `UMOP4S` — quarter-tile unsigned outer product, subtracting.
    static let umop4s = Mnemonic(rawValue: 28729)
    /// SME `SUMOP4A` — quarter-tile signed-by-unsigned outer product,
    /// accumulating.
    static let sumop4a = Mnemonic(rawValue: 28730)
    /// SME `SUMOP4S` — quarter-tile signed-by-unsigned outer product,
    /// subtracting.
    static let sumop4s = Mnemonic(rawValue: 28731)
    /// SME `USMOP4A` — quarter-tile unsigned-by-signed outer product,
    /// accumulating.
    static let usmop4a = Mnemonic(rawValue: 28732)
    /// SME `USMOP4S` — quarter-tile unsigned-by-signed outer product,
    /// subtracting.
    static let usmop4s = Mnemonic(rawValue: 28733)

    /// SME `FTMOPA` — sparse FP outer product, accumulating into `ZA`.
    static let ftmopa = Mnemonic(rawValue: 28734)
    /// SME `BFTMOPA` — sparse BFloat16 outer product, accumulating.
    static let bftmopa = Mnemonic(rawValue: 28735)
    /// SME `STMOPA` — sparse signed outer product, accumulating.
    static let stmopa = Mnemonic(rawValue: 28736)
    /// SME `UTMOPA` — sparse unsigned outer product, accumulating.
    static let utmopa = Mnemonic(rawValue: 28737)
    /// SME `SUTMOPA` — sparse signed-by-unsigned outer product,
    /// accumulating.
    static let sutmopa = Mnemonic(rawValue: 28738)
    /// SME `USTMOPA` — sparse unsigned-by-signed outer product,
    /// accumulating.
    static let ustmopa = Mnemonic(rawValue: 28739)
}
