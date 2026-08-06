// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

public extension Mnemonic {
    /// SVE LD1B — contiguous / gather load of bytes (zero-extended).
    static let ld1b = Mnemonic(rawValue: 16684)
    /// SVE LD1H — contiguous / gather load of halfwords (zero-extended).
    static let ld1h = Mnemonic(rawValue: 16685)
    /// SVE LD1W — contiguous / gather load of words (zero-extended).
    static let ld1w = Mnemonic(rawValue: 16686)
    /// SVE LD1D — contiguous / gather load of doublewords.
    static let ld1d = Mnemonic(rawValue: 16687)
    /// SVE LD1SB — contiguous / gather load of bytes (sign-extended).
    static let ld1sb = Mnemonic(rawValue: 16688)
    /// SVE LD1SH — contiguous / gather load of halfwords (sign-extended).
    static let ld1sh = Mnemonic(rawValue: 16689)
    /// SVE LD1SW — contiguous / gather load of words (sign-extended).
    static let ld1sw = Mnemonic(rawValue: 16690)
    /// SVE2p1 LD1Q — quadword gather load.
    static let ld1q = Mnemonic(rawValue: 16691)
    /// SVE ST1B — contiguous / scatter store of bytes.
    static let st1b = Mnemonic(rawValue: 16692)
    /// SVE ST1H — contiguous / scatter store of halfwords.
    static let st1h = Mnemonic(rawValue: 16693)
    /// SVE ST1W — contiguous / scatter store of words.
    static let st1w = Mnemonic(rawValue: 16694)
    /// SVE ST1D — contiguous / scatter store of doublewords.
    static let st1d = Mnemonic(rawValue: 16695)
    /// SVE2p1 ST1Q — quadword scatter store.
    static let st1q = Mnemonic(rawValue: 16696)

    /// SVE LDFF1B — first-fault load of bytes (zero-extended).
    static let ldff1b = Mnemonic(rawValue: 16697)
    /// SVE LDFF1H — first-fault load of halfwords (zero-extended).
    static let ldff1h = Mnemonic(rawValue: 16698)
    /// SVE LDFF1W — first-fault load of words (zero-extended).
    static let ldff1w = Mnemonic(rawValue: 16699)
    /// SVE LDFF1D — first-fault load of doublewords.
    static let ldff1d = Mnemonic(rawValue: 16700)
    /// SVE LDFF1SB — first-fault load of bytes (sign-extended).
    static let ldff1sb = Mnemonic(rawValue: 16701)
    /// SVE LDFF1SH — first-fault load of halfwords (sign-extended).
    static let ldff1sh = Mnemonic(rawValue: 16702)
    /// SVE LDFF1SW — first-fault load of words (sign-extended).
    static let ldff1sw = Mnemonic(rawValue: 16703)
    /// SVE LDNF1B — non-fault load of bytes (zero-extended).
    static let ldnf1b = Mnemonic(rawValue: 16704)
    /// SVE LDNF1H — non-fault load of halfwords (zero-extended).
    static let ldnf1h = Mnemonic(rawValue: 16705)
    /// SVE LDNF1W — non-fault load of words (zero-extended).
    static let ldnf1w = Mnemonic(rawValue: 16706)
    /// SVE LDNF1D — non-fault load of doublewords.
    static let ldnf1d = Mnemonic(rawValue: 16707)
    /// SVE LDNF1SB — non-fault load of bytes (sign-extended).
    static let ldnf1sb = Mnemonic(rawValue: 16708)
    /// SVE LDNF1SH — non-fault load of halfwords (sign-extended).
    static let ldnf1sh = Mnemonic(rawValue: 16709)
    /// SVE LDNF1SW — non-fault load of words (sign-extended).
    static let ldnf1sw = Mnemonic(rawValue: 16710)
    /// SVE LDNT1B — non-temporal load of bytes.
    static let ldnt1b = Mnemonic(rawValue: 16711)
    /// SVE LDNT1H — non-temporal load of halfwords.
    static let ldnt1h = Mnemonic(rawValue: 16712)
    /// SVE LDNT1W — non-temporal load of words.
    static let ldnt1w = Mnemonic(rawValue: 16713)
    /// SVE LDNT1D — non-temporal load of doublewords.
    static let ldnt1d = Mnemonic(rawValue: 16714)
    /// SVE2 LDNT1SB — non-temporal gather load of bytes (sign-extended).
    static let ldnt1sb = Mnemonic(rawValue: 16715)
    /// SVE2 LDNT1SH — non-temporal gather load of halfwords (sign-extended).
    static let ldnt1sh = Mnemonic(rawValue: 16716)
    /// SVE2 LDNT1SW — non-temporal gather load of words (sign-extended).
    static let ldnt1sw = Mnemonic(rawValue: 16717)
    /// SVE STNT1B — non-temporal store of bytes.
    static let stnt1b = Mnemonic(rawValue: 16718)
    /// SVE STNT1H — non-temporal store of halfwords.
    static let stnt1h = Mnemonic(rawValue: 16719)
    /// SVE STNT1W — non-temporal store of words.
    static let stnt1w = Mnemonic(rawValue: 16720)
    /// SVE STNT1D — non-temporal store of doublewords.
    static let stnt1d = Mnemonic(rawValue: 16721)

    /// SVE LD1RB — load and replicate a byte (zero-extended).
    static let ld1rb = Mnemonic(rawValue: 16722)
    /// SVE LD1RH — load and replicate a halfword (zero-extended).
    static let ld1rh = Mnemonic(rawValue: 16723)
    /// SVE LD1RW — load and replicate a word (zero-extended).
    static let ld1rw = Mnemonic(rawValue: 16724)
    /// SVE LD1RD — load and replicate a doubleword.
    static let ld1rd = Mnemonic(rawValue: 16725)
    /// SVE LD1RSB — load and replicate a byte (sign-extended).
    static let ld1rsb = Mnemonic(rawValue: 16726)
    /// SVE LD1RSH — load and replicate a halfword (sign-extended).
    static let ld1rsh = Mnemonic(rawValue: 16727)
    /// SVE LD1RSW — load and replicate a word (sign-extended).
    static let ld1rsw = Mnemonic(rawValue: 16728)
    /// SVE LD1RQB — load and replicate a quadword (bytes).
    static let ld1rqb = Mnemonic(rawValue: 16729)
    /// SVE LD1RQH — load and replicate a quadword (halfwords).
    static let ld1rqh = Mnemonic(rawValue: 16730)
    /// SVE LD1RQW — load and replicate a quadword (words).
    static let ld1rqw = Mnemonic(rawValue: 16731)
    /// SVE LD1RQD — load and replicate a quadword (doublewords).
    static let ld1rqd = Mnemonic(rawValue: 16732)
    /// SVE (F64MM) LD1ROB — load and replicate an octoword (bytes).
    static let ld1rob = Mnemonic(rawValue: 16733)
    /// SVE (F64MM) LD1ROH — load and replicate an octoword (halfwords).
    static let ld1roh = Mnemonic(rawValue: 16734)
    /// SVE (F64MM) LD1ROW — load and replicate an octoword (words).
    static let ld1row = Mnemonic(rawValue: 16735)
    /// SVE (F64MM) LD1ROD — load and replicate an octoword (doublewords).
    static let ld1rod = Mnemonic(rawValue: 16736)

    /// SVE LD2B — 2-vector deinterleaving load of bytes.
    static let ld2b = Mnemonic(rawValue: 16737)
    /// SVE LD2H — 2-vector deinterleaving load of halfwords.
    static let ld2h = Mnemonic(rawValue: 16738)
    /// SVE LD2W — 2-vector deinterleaving load of words.
    static let ld2w = Mnemonic(rawValue: 16739)
    /// SVE LD2D — 2-vector deinterleaving load of doublewords.
    static let ld2d = Mnemonic(rawValue: 16740)
    /// SVE2p1 LD2Q — 2-vector deinterleaving load of quadwords.
    static let ld2q = Mnemonic(rawValue: 16741)
    /// SVE LD3B — 3-vector deinterleaving load of bytes.
    static let ld3b = Mnemonic(rawValue: 16742)
    /// SVE LD3H — 3-vector deinterleaving load of halfwords.
    static let ld3h = Mnemonic(rawValue: 16743)
    /// SVE LD3W — 3-vector deinterleaving load of words.
    static let ld3w = Mnemonic(rawValue: 16744)
    /// SVE LD3D — 3-vector deinterleaving load of doublewords.
    static let ld3d = Mnemonic(rawValue: 16745)
    /// SVE2p1 LD3Q — 3-vector deinterleaving load of quadwords.
    static let ld3q = Mnemonic(rawValue: 16746)
    /// SVE LD4B — 4-vector deinterleaving load of bytes.
    static let ld4b = Mnemonic(rawValue: 16747)
    /// SVE LD4H — 4-vector deinterleaving load of halfwords.
    static let ld4h = Mnemonic(rawValue: 16748)
    /// SVE LD4W — 4-vector deinterleaving load of words.
    static let ld4w = Mnemonic(rawValue: 16749)
    /// SVE LD4D — 4-vector deinterleaving load of doublewords.
    static let ld4d = Mnemonic(rawValue: 16750)
    /// SVE2p1 LD4Q — 4-vector deinterleaving load of quadwords.
    static let ld4q = Mnemonic(rawValue: 16751)
    /// SVE ST2B — 2-vector interleaving store of bytes.
    static let st2b = Mnemonic(rawValue: 16752)
    /// SVE ST2H — 2-vector interleaving store of halfwords.
    static let st2h = Mnemonic(rawValue: 16753)
    /// SVE ST2W — 2-vector interleaving store of words.
    static let st2w = Mnemonic(rawValue: 16754)
    /// SVE ST2D — 2-vector interleaving store of doublewords.
    static let st2d = Mnemonic(rawValue: 16755)
    /// SVE2p1 ST2Q — 2-vector interleaving store of quadwords.
    static let st2q = Mnemonic(rawValue: 16756)
    /// SVE ST3B — 3-vector interleaving store of bytes.
    static let st3b = Mnemonic(rawValue: 16757)
    /// SVE ST3H — 3-vector interleaving store of halfwords.
    static let st3h = Mnemonic(rawValue: 16758)
    /// SVE ST3W — 3-vector interleaving store of words.
    static let st3w = Mnemonic(rawValue: 16759)
    /// SVE ST3D — 3-vector interleaving store of doublewords.
    static let st3d = Mnemonic(rawValue: 16760)
    /// SVE2p1 ST3Q — 3-vector interleaving store of quadwords.
    static let st3q = Mnemonic(rawValue: 16761)
    /// SVE ST4B — 4-vector interleaving store of bytes.
    static let st4b = Mnemonic(rawValue: 16762)
    /// SVE ST4H — 4-vector interleaving store of halfwords.
    static let st4h = Mnemonic(rawValue: 16763)
    /// SVE ST4W — 4-vector interleaving store of words.
    static let st4w = Mnemonic(rawValue: 16764)
    /// SVE ST4D — 4-vector interleaving store of doublewords.
    static let st4d = Mnemonic(rawValue: 16765)
    /// SVE2p1 ST4Q — 4-vector interleaving store of quadwords.
    static let st4q = Mnemonic(rawValue: 16766)

    /// SVE PRFB — prefetch bytes.
    static let prfb = Mnemonic(rawValue: 16767)
    /// SVE PRFH — prefetch halfwords.
    static let prfh = Mnemonic(rawValue: 16768)
    /// SVE PRFW — prefetch words.
    static let prfw = Mnemonic(rawValue: 16769)
    /// SVE PRFD — prefetch doublewords.
    static let prfd = Mnemonic(rawValue: 16770)

    /// SVE INSR — insert scalar/SIMD&FP register, shifting the vector.
    static let insr = Mnemonic(rawValue: 16771)
    /// SVE SPLICE — splice two vectors under predicate control.
    static let splice = Mnemonic(rawValue: 16772)
    /// SVE COMPACT — compact active elements to the bottom.
    static let compact = Mnemonic(rawValue: 16773)
    /// SVE2p2 EXPAND — expand active elements from the bottom.
    static let expand = Mnemonic(rawValue: 16774)
    /// SVE LASTA — extract the element after the last active into a scalar.
    static let lasta = Mnemonic(rawValue: 16775)
    /// SVE LASTB — extract the last active element into a scalar.
    static let lastb = Mnemonic(rawValue: 16776)
    /// SVE CLASTA — conditionally extract the element after the last active.
    static let clasta = Mnemonic(rawValue: 16777)
    /// SVE CLASTB — conditionally extract the last active element.
    static let clastb = Mnemonic(rawValue: 16778)
    /// SVE SUNPKHI — signed unpack and extend the high half.
    static let sunpkhi = Mnemonic(rawValue: 16779)
    /// SVE SUNPKLO — signed unpack and extend the low half.
    static let sunpklo = Mnemonic(rawValue: 16780)
    /// SVE UUNPKHI — unsigned unpack and extend the high half.
    static let uunpkhi = Mnemonic(rawValue: 16781)
    /// SVE UUNPKLO — unsigned unpack and extend the low half.
    static let uunpklo = Mnemonic(rawValue: 16782)
    /// SVE PUNPKHI — unpack and widen the high half of a predicate.
    static let punpkhi = Mnemonic(rawValue: 16783)
    /// SVE PUNPKLO — unpack and widen the low half of a predicate.
    static let punpklo = Mnemonic(rawValue: 16784)
    /// SVE REVB — reverse bytes within elements (predicated).
    static let revb = Mnemonic(rawValue: 16785)
    /// SVE REVH — reverse halfwords within elements (predicated).
    static let revh = Mnemonic(rawValue: 16786)
    /// SVE REVW — reverse words within elements (predicated).
    static let revw = Mnemonic(rawValue: 16787)
    /// SVE2p1 REVD — reverse 128-bit doublewords within elements (predicated).
    static let revd = Mnemonic(rawValue: 16788)

    /// SVE2p1 DUPQ — broadcast an indexed element within each 128-bit segment.
    static let dupq = Mnemonic(rawValue: 16789)
    /// SVE2p1 EXTQ — extract from a pair of 128-bit segments by byte offset.
    static let extq = Mnemonic(rawValue: 16790)
    /// SVE2p1 TBLQ — table lookup within 128-bit segments.
    static let tblq = Mnemonic(rawValue: 16791)
    /// SVE2p1 TBXQ — table lookup within 128-bit segments, merging.
    static let tbxq = Mnemonic(rawValue: 16792)
    /// SVE2p1 UZPQ1 — concatenate even elements within 128-bit segments.
    static let uzpq1 = Mnemonic(rawValue: 16793)
    /// SVE2p1 UZPQ2 — concatenate odd elements within 128-bit segments.
    static let uzpq2 = Mnemonic(rawValue: 16794)
    /// SVE2p1 ZIPQ1 — interleave low elements within 128-bit segments.
    static let zipq1 = Mnemonic(rawValue: 16795)
    /// SVE2p1 ZIPQ2 — interleave high elements within 128-bit segments.
    static let zipq2 = Mnemonic(rawValue: 16796)
    /// SVE2p1 PMOV — move between a predicate and a vector (both directions).
    static let pmov = Mnemonic(rawValue: 16797)

    /// SVE2 (SVE-AES2) PMLAL — polynomial multiply-accumulate long, 128-bit
    /// multi-vector result. `pmull` and `luti2`/`luti4` are reused from the SIMD
    /// slabs; category and operand shape disambiguate.
    static let pmlal = Mnemonic(rawValue: 16798)
    /// SVE2 (SVE-AES2) AESEMC — AES single-round encrypt then mix-columns,
    /// multi-vector.
    static let aesemc = Mnemonic(rawValue: 16799)
    /// SVE2 (SVE-AES2) AESDIMC — AES single-round decrypt then inverse
    /// mix-columns, multi-vector.
    static let aesdimc = Mnemonic(rawValue: 16800)
    /// SVE2 LUTI6 — lookup table with 6-bit indices (2-register table).
    static let luti6 = Mnemonic(rawValue: 16801)
}
