// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// mnemonic constants — SVE predicate & control. Raw values
// from the SVE / SVE2 slab (16384 ..< 28672) reserved by the scalable core; SVE-predicate is the
// first family to allocate in it. Shared mnemonics whose text token is
// identical to an earlier family's (AND/ORR/EOR/BIC/ORN/MOV/NOT/ADD/SUB)
// are REUSED from their owning family per the shared-mnemonic ownership
// rule — the Mnemonic is the token; the operand shape and `category == .sve`
// distinguish the predicate form from the integer form at canonicalization.
// Only the SVE-unique tokens are declared here.

public extension Mnemonic {
    // MARK: Predicate initialise / test (G1)

    /// `PTRUE` — initialise predicate from a pattern (no NZCV).
    static let ptrue = Mnemonic(rawValue: 16384)
    /// `PTRUES` — initialise predicate, setting NZCV.
    static let ptrues = Mnemonic(rawValue: 16385)
    /// `PFALSE` — set all predicate lanes false.
    static let pfalse = Mnemonic(rawValue: 16386)
    /// `PTEST` — set NZCV from a predicate under a governing predicate.
    static let ptest = Mnemonic(rawValue: 16387)

    // MARK: Predicate logical (G2) — SVE-unique tokens only

    /// `ORRS` — predicate OR, setting NZCV.
    static let orrs = Mnemonic(rawValue: 16388)
    /// `EORS` — predicate XOR, setting NZCV.
    static let eors = Mnemonic(rawValue: 16389)
    /// `ORNS` — predicate OR-NOT, setting NZCV.
    static let orns = Mnemonic(rawValue: 16390)
    /// `NAND` — predicate NAND.
    static let nand = Mnemonic(rawValue: 16391)
    /// `NANDS` — predicate NAND, setting NZCV.
    static let nands = Mnemonic(rawValue: 16392)
    /// `NOR` — predicate NOR.
    static let nor = Mnemonic(rawValue: 16393)
    /// `NORS` — predicate NOR, setting NZCV.
    static let nors = Mnemonic(rawValue: 16394)
    /// `SEL` — predicate per-lane select.
    static let sel = Mnemonic(rawValue: 16395)
    /// `MOVS` — predicate move alias (of ORRS / ANDS), setting NZCV.
    static let movs = Mnemonic(rawValue: 16396)
    /// `NOTS` — predicate NOT alias (of EORS), setting NZCV.
    static let nots = Mnemonic(rawValue: 16397)

    // MARK: Predicate break / partition (G3)

    /// `BRKA` — break after the first true lane (propagating).
    static let brka = Mnemonic(rawValue: 16398)
    /// `BRKAS` — `BRKA` setting NZCV.
    static let brkas = Mnemonic(rawValue: 16399)
    /// `BRKB` — break before the first true lane.
    static let brkb = Mnemonic(rawValue: 16400)
    /// `BRKBS` — `BRKB` setting NZCV.
    static let brkbs = Mnemonic(rawValue: 16401)
    /// `BRKN` — propagate break into the next partition.
    static let brkn = Mnemonic(rawValue: 16402)
    /// `BRKNS` — `BRKN` setting NZCV.
    static let brkns = Mnemonic(rawValue: 16403)
    /// `BRKPA` — break after, on a pair of predicates.
    static let brkpa = Mnemonic(rawValue: 16404)
    /// `BRKPAS` — `BRKPA` setting NZCV.
    static let brkpas = Mnemonic(rawValue: 16405)
    /// `BRKPB` — break before, on a pair of predicates.
    static let brkpb = Mnemonic(rawValue: 16406)
    /// `BRKPBS` — `BRKPB` setting NZCV.
    static let brkpbs = Mnemonic(rawValue: 16407)
    /// `PFIRST` — set the first active lane, setting NZCV.
    static let pfirst = Mnemonic(rawValue: 16408)
    /// `PNEXT` — advance to the next active lane, setting NZCV.
    static let pnext = Mnemonic(rawValue: 16409)

    // MARK: First-fault register (G4)

    /// `RDFFR` — read the first-fault register into a predicate.
    static let rdffr = Mnemonic(rawValue: 16410)
    /// `RDFFRS` — `RDFFR` setting NZCV.
    static let rdffrs = Mnemonic(rawValue: 16411)
    /// `WRFFR` — write the first-fault register from a predicate.
    static let wrffr = Mnemonic(rawValue: 16412)
    /// `SETFFR` — set the first-fault register all-true.
    static let setffr = Mnemonic(rawValue: 16413)

    // MARK: Predicate count (G5)

    /// `CNTP` — count active predicate lanes into a scalar.
    static let cntp = Mnemonic(rawValue: 16414)
    /// `INCP` — increment scalar/vector by active predicate count.
    static let incp = Mnemonic(rawValue: 16415)
    /// `DECP` — decrement scalar/vector by active predicate count.
    static let decp = Mnemonic(rawValue: 16416)
    /// `SQINCP` — signed-saturating increment by predicate count.
    static let sqincp = Mnemonic(rawValue: 16417)
    /// `UQINCP` — unsigned-saturating increment by predicate count.
    static let uqincp = Mnemonic(rawValue: 16418)
    /// `SQDECP` — signed-saturating decrement by predicate count.
    static let sqdecp = Mnemonic(rawValue: 16419)
    /// `UQDECP` — unsigned-saturating decrement by predicate count.
    static let uqdecp = Mnemonic(rawValue: 16420)

    // MARK: Loop predicates (G6)

    /// `WHILEGE` — signed while-greater-or-equal loop predicate.
    static let whilege = Mnemonic(rawValue: 16421)
    /// `WHILEGT` — signed while-greater-than loop predicate.
    static let whilegt = Mnemonic(rawValue: 16422)
    /// `WHILELT` — signed while-less-than loop predicate.
    static let whilelt = Mnemonic(rawValue: 16423)
    /// `WHILELE` — signed while-less-or-equal loop predicate.
    static let whilele = Mnemonic(rawValue: 16424)
    /// `WHILEHS` — unsigned while-higher-or-same loop predicate.
    static let whilehs = Mnemonic(rawValue: 16425)
    /// `WHILEHI` — unsigned while-higher loop predicate.
    static let whilehi = Mnemonic(rawValue: 16426)
    /// `WHILELO` — unsigned while-lower loop predicate.
    static let whilelo = Mnemonic(rawValue: 16427)
    /// `WHILELS` — unsigned while-lower-or-same loop predicate.
    static let whilels = Mnemonic(rawValue: 16428)
    /// `WHILERW` — memory-hazard while-read-write loop predicate.
    static let whilerw = Mnemonic(rawValue: 16429)
    /// `WHILEWR` — memory-hazard while-write-read loop predicate.
    static let whilewr = Mnemonic(rawValue: 16430)
    /// `CTERMEQ` — conditionally-terminate-equal (sets N,V; reads C).
    static let ctermeq = Mnemonic(rawValue: 16431)
    /// `CTERMNE` — conditionally-terminate-not-equal (sets N,V; reads C).
    static let ctermne = Mnemonic(rawValue: 16432)

    // MARK: Element count + stack-frame adjust (G7)

    /// `RDVL` — read the vector length in bytes into a scalar.
    static let rdvl = Mnemonic(rawValue: 16433)
    /// `RDSVL` — read the streaming vector length (SME).
    static let rdsvl = Mnemonic(rawValue: 16434)
    /// `ADDVL` — add a multiple of the vector length in bytes.
    static let addvl = Mnemonic(rawValue: 16435)
    /// `ADDSVL` — add a multiple of the streaming vector length (SME).
    static let addsvl = Mnemonic(rawValue: 16436)
    /// `ADDPL` — add a multiple of the predicate length in bytes.
    static let addpl = Mnemonic(rawValue: 16437)
    /// `ADDSPL` — add a multiple of the streaming predicate length (SME).
    static let addspl = Mnemonic(rawValue: 16438)
    /// `CNTB` — count byte-element count into a scalar.
    static let cntb = Mnemonic(rawValue: 16439)
    /// `CNTH` — count halfword-element count.
    static let cnth = Mnemonic(rawValue: 16440)
    /// `CNTW` — count word-element count.
    static let cntw = Mnemonic(rawValue: 16441)
    /// `CNTD` — count doubleword-element count.
    static let cntd = Mnemonic(rawValue: 16442)
    /// `INCB` — increment scalar by byte-element count.
    static let incb = Mnemonic(rawValue: 16443)
    /// `INCH` — increment scalar/vector by halfword-element count.
    static let inch = Mnemonic(rawValue: 16444)
    /// `INCW` — increment scalar/vector by word-element count.
    static let incw = Mnemonic(rawValue: 16445)
    /// `INCD` — increment scalar/vector by doubleword-element count.
    static let incd = Mnemonic(rawValue: 16446)
    /// `DECB` — decrement scalar by byte-element count.
    static let decb = Mnemonic(rawValue: 16447)
    /// `DECH` — decrement scalar/vector by halfword-element count.
    static let dech = Mnemonic(rawValue: 16448)
    /// `DECW` — decrement scalar/vector by word-element count.
    static let decw = Mnemonic(rawValue: 16449)
    /// `DECD` — decrement scalar/vector by doubleword-element count.
    static let decd = Mnemonic(rawValue: 16450)
    /// `SQINCB` — signed-saturating increment by byte-element count.
    static let sqincb = Mnemonic(rawValue: 16451)
    /// `SQINCH` — signed-saturating increment by halfword-element count.
    static let sqinch = Mnemonic(rawValue: 16452)
    /// `SQINCW` — signed-saturating increment by word-element count.
    static let sqincw = Mnemonic(rawValue: 16453)
    /// `SQINCD` — signed-saturating increment by doubleword-element count.
    static let sqincd = Mnemonic(rawValue: 16454)
    /// `UQINCB` — unsigned-saturating increment by byte-element count.
    static let uqincb = Mnemonic(rawValue: 16455)
    /// `UQINCH` — unsigned-saturating increment by halfword-element count.
    static let uqinch = Mnemonic(rawValue: 16456)
    /// `UQINCW` — unsigned-saturating increment by word-element count.
    static let uqincw = Mnemonic(rawValue: 16457)
    /// `UQINCD` — unsigned-saturating increment by doubleword-element count.
    static let uqincd = Mnemonic(rawValue: 16458)
    /// `SQDECB` — signed-saturating decrement by byte-element count.
    static let sqdecb = Mnemonic(rawValue: 16459)
    /// `SQDECH` — signed-saturating decrement by halfword-element count.
    static let sqdech = Mnemonic(rawValue: 16460)
    /// `SQDECW` — signed-saturating decrement by word-element count.
    static let sqdecw = Mnemonic(rawValue: 16461)
    /// `SQDECD` — signed-saturating decrement by doubleword-element count.
    static let sqdecd = Mnemonic(rawValue: 16462)
    /// `UQDECB` — unsigned-saturating decrement by byte-element count.
    static let uqdecb = Mnemonic(rawValue: 16463)
    /// `UQDECH` — unsigned-saturating decrement by halfword-element count.
    static let uqdech = Mnemonic(rawValue: 16464)
    /// `UQDECW` — unsigned-saturating decrement by word-element count.
    static let uqdecw = Mnemonic(rawValue: 16465)
    /// `UQDECD` — unsigned-saturating decrement by doubleword-element count.
    static let uqdecd = Mnemonic(rawValue: 16466)

    // MARK: Index generation (G8)

    /// `INDEX` — generate a vector of monotonically-stepped indices.
    static let index = Mnemonic(rawValue: 16467)

    // MARK: MOVPRFX (G9)

    /// `MOVPRFX` — constructive-prefix copy (predicated or unpredicated).
    static let movprfx = Mnemonic(rawValue: 16468)
}
