// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// SYS / SYSL / SYSP alias tables. Shared between the per-encoding decoders
// (which gate `semanticReads` / `semanticWrites` on whether the alias takes
// an Rt operand) and the text canonicalizer (which renders the friendly
// `ic iallu` / `dc cvac, xN` / `tlbi vae1is, xN` / `tlbip vae1, xN, xN+1`
// forms).
//
// The (op1, CRn, CRm, op2) → operation-name mappings are sourced from ARM's
// machine-readable architecture spec (the A64 ISA SystemOp data: IC / DC /
// AT / TLBI / TLBIP groups plus the dedicated CFP / DVP / COSP / CPP /
// TRCIT / APAS / GCS* / GCSPOP* operations). NOT sourced from any
// disassembler, so the parity sweep stays an independent check. The table is
// limited to the operations enabled at the parity sweep's maximal feature
// set; operations gated behind disabled features fall through to the generic
// `sys #op1, c<n>, c<m>, #op2 {, xN}` form, matching the oracle.

/// How an alias renders its operand(s) and how the decoder models Rt.
enum BESSysAliasKind: Sendable {
    /// `name, xN` — Rt is always part of the syntax (xzr when Rt == 31).
    case reg
    /// `name xN` — single-op alias with a space separator (no operation
    /// operand, e.g. `trcit x0`, `apas x0`, `gcspushm x0`).
    case bareReg
    /// Alias used only when Rt == 31 (renders bare, e.g. `tlbi vmalle1`);
    /// any other Rt falls back to the generic `sys` form.
    case noreg
    /// SYSL-only: alias always used; renders `name xN` when Rt != 31 and
    /// bare `name` when Rt == 31 (e.g. `gcspopm` / `gcspopm x0`).
    case optReg
}

/// One entry in the SYS / SYSL / SYSP alias tables.
struct BESSysAlias: Sendable {
    /// Lowercase canonical text up to (but excluding) any Rt operand
    /// (e.g. "ic iallu", "dc cvac", "cfp rctx", "tlbip vae1").
    let name: String
    /// How the alias renders Rt and how the decoder models the operand.
    let kind: BESSysAliasKind

    /// Whether the alias reads/writes Rt for a given encoded Rt value.
    /// `.reg` / `.bareReg` always touch Rt; `.noreg` never does (it's only
    /// selected when Rt == 31 = XZR); `.optReg` touches Rt only when != 31.
    func touchesRt(_ rt: UInt8) -> Bool {
        switch kind {
        case .reg, .bareReg: true
        case .noreg: false
        case .optReg: rt != 31
        }
    }
}

/// SYS alias lookup (L == 0), keyed by (op1, CRn, CRm, op2).
enum BESSysAliasTable {
    @_effects(readonly)
    static func lookup(
        op1: UInt8, CRn: UInt8, CRm: UInt8, op2: UInt8,
    ) -> BESSysAlias? {
        switch (op1, CRn, CRm, op2) {
        case (0, 7, 1, 0): BESSysAlias(name: "ic ialluis", kind: .noreg)
        case (0, 7, 5, 0): BESSysAlias(name: "ic iallu", kind: .noreg)
        case (0, 7, 6, 1): BESSysAlias(name: "dc ivac", kind: .reg)
        case (0, 7, 6, 2): BESSysAlias(name: "dc isw", kind: .reg)
        case (0, 7, 6, 3): BESSysAlias(name: "dc igvac", kind: .reg)
        case (0, 7, 6, 4): BESSysAlias(name: "dc igsw", kind: .reg)
        case (0, 7, 6, 5): BESSysAlias(name: "dc igdvac", kind: .reg)
        case (0, 7, 6, 6): BESSysAlias(name: "dc igdsw", kind: .reg)
        case (0, 7, 7, 4): BESSysAlias(name: "gcspushx", kind: .noreg)
        case (0, 7, 7, 5): BESSysAlias(name: "gcspopcx", kind: .noreg)
        case (0, 7, 7, 6): BESSysAlias(name: "gcspopx", kind: .noreg)
        case (0, 7, 8, 0): BESSysAlias(name: "at s1e1r", kind: .reg)
        case (0, 7, 8, 1): BESSysAlias(name: "at s1e1w", kind: .reg)
        case (0, 7, 8, 2): BESSysAlias(name: "at s1e0r", kind: .reg)
        case (0, 7, 8, 3): BESSysAlias(name: "at s1e0w", kind: .reg)
        case (0, 7, 9, 0): BESSysAlias(name: "at s1e1rp", kind: .reg)
        case (0, 7, 9, 1): BESSysAlias(name: "at s1e1wp", kind: .reg)
        case (0, 7, 9, 2): BESSysAlias(name: "at s1e1a", kind: .reg)
        case (0, 7, 10, 2): BESSysAlias(name: "dc csw", kind: .reg)
        case (0, 7, 10, 4): BESSysAlias(name: "dc cgsw", kind: .reg)
        case (0, 7, 10, 6): BESSysAlias(name: "dc cgdsw", kind: .reg)
        case (0, 7, 14, 2): BESSysAlias(name: "dc cisw", kind: .reg)
        case (0, 7, 14, 4): BESSysAlias(name: "dc cigsw", kind: .reg)
        case (0, 7, 14, 6): BESSysAlias(name: "dc cigdsw", kind: .reg)
        case (0, 8, 1, 0): BESSysAlias(name: "tlbi vmalle1os", kind: .noreg)
        case (0, 8, 1, 1): BESSysAlias(name: "tlbi vae1os", kind: .reg)
        case (0, 8, 1, 2): BESSysAlias(name: "tlbi aside1os", kind: .reg)
        case (0, 8, 1, 3): BESSysAlias(name: "tlbi vaae1os", kind: .reg)
        case (0, 8, 1, 5): BESSysAlias(name: "tlbi vale1os", kind: .reg)
        case (0, 8, 1, 7): BESSysAlias(name: "tlbi vaale1os", kind: .reg)
        case (0, 8, 2, 1): BESSysAlias(name: "tlbi rvae1is", kind: .reg)
        case (0, 8, 2, 3): BESSysAlias(name: "tlbi rvaae1is", kind: .reg)
        case (0, 8, 2, 5): BESSysAlias(name: "tlbi rvale1is", kind: .reg)
        case (0, 8, 2, 7): BESSysAlias(name: "tlbi rvaale1is", kind: .reg)
        case (0, 8, 3, 0): BESSysAlias(name: "tlbi vmalle1is", kind: .noreg)
        case (0, 8, 3, 1): BESSysAlias(name: "tlbi vae1is", kind: .reg)
        case (0, 8, 3, 2): BESSysAlias(name: "tlbi aside1is", kind: .reg)
        case (0, 8, 3, 3): BESSysAlias(name: "tlbi vaae1is", kind: .reg)
        case (0, 8, 3, 5): BESSysAlias(name: "tlbi vale1is", kind: .reg)
        case (0, 8, 3, 7): BESSysAlias(name: "tlbi vaale1is", kind: .reg)
        case (0, 8, 5, 1): BESSysAlias(name: "tlbi rvae1os", kind: .reg)
        case (0, 8, 5, 3): BESSysAlias(name: "tlbi rvaae1os", kind: .reg)
        case (0, 8, 5, 5): BESSysAlias(name: "tlbi rvale1os", kind: .reg)
        case (0, 8, 5, 7): BESSysAlias(name: "tlbi rvaale1os", kind: .reg)
        case (0, 8, 6, 1): BESSysAlias(name: "tlbi rvae1", kind: .reg)
        case (0, 8, 6, 3): BESSysAlias(name: "tlbi rvaae1", kind: .reg)
        case (0, 8, 6, 5): BESSysAlias(name: "tlbi rvale1", kind: .reg)
        case (0, 8, 6, 7): BESSysAlias(name: "tlbi rvaale1", kind: .reg)
        case (0, 8, 7, 0): BESSysAlias(name: "tlbi vmalle1", kind: .noreg)
        case (0, 8, 7, 1): BESSysAlias(name: "tlbi vae1", kind: .reg)
        case (0, 8, 7, 2): BESSysAlias(name: "tlbi aside1", kind: .reg)
        case (0, 8, 7, 3): BESSysAlias(name: "tlbi vaae1", kind: .reg)
        case (0, 8, 7, 5): BESSysAlias(name: "tlbi vale1", kind: .reg)
        case (0, 8, 7, 7): BESSysAlias(name: "tlbi vaale1", kind: .reg)
        case (0, 9, 1, 0): BESSysAlias(name: "tlbi vmalle1osnxs", kind: .noreg)
        case (0, 9, 1, 1): BESSysAlias(name: "tlbi vae1osnxs", kind: .reg)
        case (0, 9, 1, 2): BESSysAlias(name: "tlbi aside1osnxs", kind: .reg)
        case (0, 9, 1, 3): BESSysAlias(name: "tlbi vaae1osnxs", kind: .reg)
        case (0, 9, 1, 5): BESSysAlias(name: "tlbi vale1osnxs", kind: .reg)
        case (0, 9, 1, 7): BESSysAlias(name: "tlbi vaale1osnxs", kind: .reg)
        case (0, 9, 2, 1): BESSysAlias(name: "tlbi rvae1isnxs", kind: .reg)
        case (0, 9, 2, 3): BESSysAlias(name: "tlbi rvaae1isnxs", kind: .reg)
        case (0, 9, 2, 5): BESSysAlias(name: "tlbi rvale1isnxs", kind: .reg)
        case (0, 9, 2, 7): BESSysAlias(name: "tlbi rvaale1isnxs", kind: .reg)
        case (0, 9, 3, 0): BESSysAlias(name: "tlbi vmalle1isnxs", kind: .noreg)
        case (0, 9, 3, 1): BESSysAlias(name: "tlbi vae1isnxs", kind: .reg)
        case (0, 9, 3, 2): BESSysAlias(name: "tlbi aside1isnxs", kind: .reg)
        case (0, 9, 3, 3): BESSysAlias(name: "tlbi vaae1isnxs", kind: .reg)
        case (0, 9, 3, 5): BESSysAlias(name: "tlbi vale1isnxs", kind: .reg)
        case (0, 9, 3, 7): BESSysAlias(name: "tlbi vaale1isnxs", kind: .reg)
        case (0, 9, 5, 1): BESSysAlias(name: "tlbi rvae1osnxs", kind: .reg)
        case (0, 9, 5, 3): BESSysAlias(name: "tlbi rvaae1osnxs", kind: .reg)
        case (0, 9, 5, 5): BESSysAlias(name: "tlbi rvale1osnxs", kind: .reg)
        case (0, 9, 5, 7): BESSysAlias(name: "tlbi rvaale1osnxs", kind: .reg)
        case (0, 9, 6, 1): BESSysAlias(name: "tlbi rvae1nxs", kind: .reg)
        case (0, 9, 6, 3): BESSysAlias(name: "tlbi rvaae1nxs", kind: .reg)
        case (0, 9, 6, 5): BESSysAlias(name: "tlbi rvale1nxs", kind: .reg)
        case (0, 9, 6, 7): BESSysAlias(name: "tlbi rvaale1nxs", kind: .reg)
        case (0, 9, 7, 0): BESSysAlias(name: "tlbi vmalle1nxs", kind: .noreg)
        case (0, 9, 7, 1): BESSysAlias(name: "tlbi vae1nxs", kind: .reg)
        case (0, 9, 7, 2): BESSysAlias(name: "tlbi aside1nxs", kind: .reg)
        case (0, 9, 7, 3): BESSysAlias(name: "tlbi vaae1nxs", kind: .reg)
        case (0, 9, 7, 5): BESSysAlias(name: "tlbi vale1nxs", kind: .reg)
        case (0, 9, 7, 7): BESSysAlias(name: "tlbi vaale1nxs", kind: .reg)
        case (3, 7, 2, 7): BESSysAlias(name: "trcit", kind: .bareReg)
        case (3, 7, 3, 4): BESSysAlias(name: "cfp rctx", kind: .reg)
        case (3, 7, 3, 5): BESSysAlias(name: "dvp rctx", kind: .reg)
        case (3, 7, 3, 6): BESSysAlias(name: "cosp rctx", kind: .reg)
        case (3, 7, 3, 7): BESSysAlias(name: "cpp rctx", kind: .reg)
        case (3, 7, 4, 1): BESSysAlias(name: "dc zva", kind: .reg)
        case (3, 7, 4, 3): BESSysAlias(name: "dc gva", kind: .reg)
        case (3, 7, 4, 4): BESSysAlias(name: "dc gzva", kind: .reg)
        case (3, 7, 5, 1): BESSysAlias(name: "ic ivau", kind: .reg)
        case (3, 7, 7, 0): BESSysAlias(name: "gcspushm", kind: .bareReg)
        case (3, 7, 7, 2): BESSysAlias(name: "gcsss1", kind: .bareReg)
        case (3, 7, 10, 1): BESSysAlias(name: "dc cvac", kind: .reg)
        case (3, 7, 10, 3): BESSysAlias(name: "dc cgvac", kind: .reg)
        case (3, 7, 10, 5): BESSysAlias(name: "dc cgdvac", kind: .reg)
        case (3, 7, 11, 0): BESSysAlias(name: "dc cvaoc", kind: .reg)
        case (3, 7, 11, 1): BESSysAlias(name: "dc cvau", kind: .reg)
        case (3, 7, 11, 7): BESSysAlias(name: "dc cgdvaoc", kind: .reg)
        case (3, 7, 12, 1): BESSysAlias(name: "dc cvap", kind: .reg)
        case (3, 7, 12, 3): BESSysAlias(name: "dc cgvap", kind: .reg)
        case (3, 7, 12, 5): BESSysAlias(name: "dc cgdvap", kind: .reg)
        case (3, 7, 13, 1): BESSysAlias(name: "dc cvadp", kind: .reg)
        case (3, 7, 13, 3): BESSysAlias(name: "dc cgvadp", kind: .reg)
        case (3, 7, 13, 5): BESSysAlias(name: "dc cgdvadp", kind: .reg)
        case (3, 7, 14, 1): BESSysAlias(name: "dc civac", kind: .reg)
        case (3, 7, 14, 3): BESSysAlias(name: "dc cigvac", kind: .reg)
        case (3, 7, 14, 5): BESSysAlias(name: "dc cigdvac", kind: .reg)
        case (3, 7, 15, 0): BESSysAlias(name: "dc civaoc", kind: .reg)
        case (3, 7, 15, 7): BESSysAlias(name: "dc cigdvaoc", kind: .reg)
        case (4, 7, 8, 0): BESSysAlias(name: "at s1e2r", kind: .reg)
        case (4, 7, 8, 1): BESSysAlias(name: "at s1e2w", kind: .reg)
        case (4, 7, 8, 4): BESSysAlias(name: "at s12e1r", kind: .reg)
        case (4, 7, 8, 5): BESSysAlias(name: "at s12e1w", kind: .reg)
        case (4, 7, 8, 6): BESSysAlias(name: "at s12e0r", kind: .reg)
        case (4, 7, 8, 7): BESSysAlias(name: "at s12e0w", kind: .reg)
        case (4, 7, 9, 2): BESSysAlias(name: "at s1e2a", kind: .reg)
        case (4, 8, 0, 1): BESSysAlias(name: "tlbi ipas2e1is", kind: .reg)
        case (4, 8, 0, 2): BESSysAlias(name: "tlbi ripas2e1is", kind: .reg)
        case (4, 8, 0, 5): BESSysAlias(name: "tlbi ipas2le1is", kind: .reg)
        case (4, 8, 0, 6): BESSysAlias(name: "tlbi ripas2le1is", kind: .reg)
        case (4, 8, 1, 0): BESSysAlias(name: "tlbi alle2os", kind: .noreg)
        case (4, 8, 1, 1): BESSysAlias(name: "tlbi vae2os", kind: .reg)
        case (4, 8, 1, 4): BESSysAlias(name: "tlbi alle1os", kind: .noreg)
        case (4, 8, 1, 5): BESSysAlias(name: "tlbi vale2os", kind: .reg)
        case (4, 8, 1, 6): BESSysAlias(name: "tlbi vmalls12e1os", kind: .noreg)
        case (4, 8, 2, 1): BESSysAlias(name: "tlbi rvae2is", kind: .reg)
        case (4, 8, 2, 2): BESSysAlias(name: "tlbi vmallws2e1is", kind: .noreg)
        case (4, 8, 2, 5): BESSysAlias(name: "tlbi rvale2is", kind: .reg)
        case (4, 8, 3, 0): BESSysAlias(name: "tlbi alle2is", kind: .noreg)
        case (4, 8, 3, 1): BESSysAlias(name: "tlbi vae2is", kind: .reg)
        case (4, 8, 3, 4): BESSysAlias(name: "tlbi alle1is", kind: .noreg)
        case (4, 8, 3, 5): BESSysAlias(name: "tlbi vale2is", kind: .reg)
        case (4, 8, 3, 6): BESSysAlias(name: "tlbi vmalls12e1is", kind: .noreg)
        case (4, 8, 4, 0): BESSysAlias(name: "tlbi ipas2e1os", kind: .reg)
        case (4, 8, 4, 1): BESSysAlias(name: "tlbi ipas2e1", kind: .reg)
        case (4, 8, 4, 2): BESSysAlias(name: "tlbi ripas2e1", kind: .reg)
        case (4, 8, 4, 3): BESSysAlias(name: "tlbi ripas2e1os", kind: .reg)
        case (4, 8, 4, 4): BESSysAlias(name: "tlbi ipas2le1os", kind: .reg)
        case (4, 8, 4, 5): BESSysAlias(name: "tlbi ipas2le1", kind: .reg)
        case (4, 8, 4, 6): BESSysAlias(name: "tlbi ripas2le1", kind: .reg)
        case (4, 8, 4, 7): BESSysAlias(name: "tlbi ripas2le1os", kind: .reg)
        case (4, 8, 5, 1): BESSysAlias(name: "tlbi rvae2os", kind: .reg)
        case (4, 8, 5, 2): BESSysAlias(name: "tlbi vmallws2e1os", kind: .noreg)
        case (4, 8, 5, 5): BESSysAlias(name: "tlbi rvale2os", kind: .reg)
        case (4, 8, 6, 1): BESSysAlias(name: "tlbi rvae2", kind: .reg)
        case (4, 8, 6, 2): BESSysAlias(name: "tlbi vmallws2e1", kind: .noreg)
        case (4, 8, 6, 5): BESSysAlias(name: "tlbi rvale2", kind: .reg)
        case (4, 8, 7, 0): BESSysAlias(name: "tlbi alle2", kind: .noreg)
        case (4, 8, 7, 1): BESSysAlias(name: "tlbi vae2", kind: .reg)
        case (4, 8, 7, 4): BESSysAlias(name: "tlbi alle1", kind: .noreg)
        case (4, 8, 7, 5): BESSysAlias(name: "tlbi vale2", kind: .reg)
        case (4, 8, 7, 6): BESSysAlias(name: "tlbi vmalls12e1", kind: .noreg)
        case (4, 9, 0, 1): BESSysAlias(name: "tlbi ipas2e1isnxs", kind: .reg)
        case (4, 9, 0, 2): BESSysAlias(name: "tlbi ripas2e1isnxs", kind: .reg)
        case (4, 9, 0, 5): BESSysAlias(name: "tlbi ipas2le1isnxs", kind: .reg)
        case (4, 9, 0, 6): BESSysAlias(name: "tlbi ripas2le1isnxs", kind: .reg)
        case (4, 9, 1, 0): BESSysAlias(name: "tlbi alle2osnxs", kind: .noreg)
        case (4, 9, 1, 1): BESSysAlias(name: "tlbi vae2osnxs", kind: .reg)
        case (4, 9, 1, 4): BESSysAlias(name: "tlbi alle1osnxs", kind: .noreg)
        case (4, 9, 1, 5): BESSysAlias(name: "tlbi vale2osnxs", kind: .reg)
        case (4, 9, 1, 6): BESSysAlias(name: "tlbi vmalls12e1osnxs", kind: .noreg)
        case (4, 9, 2, 1): BESSysAlias(name: "tlbi rvae2isnxs", kind: .reg)
        case (4, 9, 2, 2): BESSysAlias(name: "tlbi vmallws2e1isnxs", kind: .noreg)
        case (4, 9, 2, 5): BESSysAlias(name: "tlbi rvale2isnxs", kind: .reg)
        case (4, 9, 3, 0): BESSysAlias(name: "tlbi alle2isnxs", kind: .noreg)
        case (4, 9, 3, 1): BESSysAlias(name: "tlbi vae2isnxs", kind: .reg)
        case (4, 9, 3, 4): BESSysAlias(name: "tlbi alle1isnxs", kind: .noreg)
        case (4, 9, 3, 5): BESSysAlias(name: "tlbi vale2isnxs", kind: .reg)
        case (4, 9, 3, 6): BESSysAlias(name: "tlbi vmalls12e1isnxs", kind: .noreg)
        case (4, 9, 4, 0): BESSysAlias(name: "tlbi ipas2e1osnxs", kind: .reg)
        case (4, 9, 4, 1): BESSysAlias(name: "tlbi ipas2e1nxs", kind: .reg)
        case (4, 9, 4, 2): BESSysAlias(name: "tlbi ripas2e1nxs", kind: .reg)
        case (4, 9, 4, 3): BESSysAlias(name: "tlbi ripas2e1osnxs", kind: .reg)
        case (4, 9, 4, 4): BESSysAlias(name: "tlbi ipas2le1osnxs", kind: .reg)
        case (4, 9, 4, 5): BESSysAlias(name: "tlbi ipas2le1nxs", kind: .reg)
        case (4, 9, 4, 6): BESSysAlias(name: "tlbi ripas2le1nxs", kind: .reg)
        case (4, 9, 4, 7): BESSysAlias(name: "tlbi ripas2le1osnxs", kind: .reg)
        case (4, 9, 5, 1): BESSysAlias(name: "tlbi rvae2osnxs", kind: .reg)
        case (4, 9, 5, 2): BESSysAlias(name: "tlbi vmallws2e1osnxs", kind: .noreg)
        case (4, 9, 5, 5): BESSysAlias(name: "tlbi rvale2osnxs", kind: .reg)
        case (4, 9, 6, 1): BESSysAlias(name: "tlbi rvae2nxs", kind: .reg)
        case (4, 9, 6, 2): BESSysAlias(name: "tlbi vmallws2e1nxs", kind: .noreg)
        case (4, 9, 6, 5): BESSysAlias(name: "tlbi rvale2nxs", kind: .reg)
        case (4, 9, 7, 0): BESSysAlias(name: "tlbi alle2nxs", kind: .noreg)
        case (4, 9, 7, 1): BESSysAlias(name: "tlbi vae2nxs", kind: .reg)
        case (4, 9, 7, 4): BESSysAlias(name: "tlbi alle1nxs", kind: .noreg)
        case (4, 9, 7, 5): BESSysAlias(name: "tlbi vale2nxs", kind: .reg)
        case (4, 9, 7, 6): BESSysAlias(name: "tlbi vmalls12e1nxs", kind: .noreg)
        case (6, 7, 0, 0): BESSysAlias(name: "apas", kind: .bareReg)
        case (6, 7, 8, 0): BESSysAlias(name: "at s1e3r", kind: .reg)
        case (6, 7, 8, 1): BESSysAlias(name: "at s1e3w", kind: .reg)
        case (6, 7, 9, 2): BESSysAlias(name: "at s1e3a", kind: .reg)
        case (6, 8, 1, 0): BESSysAlias(name: "tlbi alle3os", kind: .noreg)
        case (6, 8, 1, 1): BESSysAlias(name: "tlbi vae3os", kind: .reg)
        case (6, 8, 1, 5): BESSysAlias(name: "tlbi vale3os", kind: .reg)
        case (6, 8, 2, 1): BESSysAlias(name: "tlbi rvae3is", kind: .reg)
        case (6, 8, 2, 5): BESSysAlias(name: "tlbi rvale3is", kind: .reg)
        case (6, 8, 3, 0): BESSysAlias(name: "tlbi alle3is", kind: .noreg)
        case (6, 8, 3, 1): BESSysAlias(name: "tlbi vae3is", kind: .reg)
        case (6, 8, 3, 5): BESSysAlias(name: "tlbi vale3is", kind: .reg)
        case (6, 8, 5, 1): BESSysAlias(name: "tlbi rvae3os", kind: .reg)
        case (6, 8, 5, 5): BESSysAlias(name: "tlbi rvale3os", kind: .reg)
        case (6, 8, 6, 1): BESSysAlias(name: "tlbi rvae3", kind: .reg)
        case (6, 8, 6, 5): BESSysAlias(name: "tlbi rvale3", kind: .reg)
        case (6, 8, 7, 0): BESSysAlias(name: "tlbi alle3", kind: .noreg)
        case (6, 8, 7, 1): BESSysAlias(name: "tlbi vae3", kind: .reg)
        case (6, 8, 7, 5): BESSysAlias(name: "tlbi vale3", kind: .reg)
        case (6, 9, 1, 0): BESSysAlias(name: "tlbi alle3osnxs", kind: .noreg)
        case (6, 9, 1, 1): BESSysAlias(name: "tlbi vae3osnxs", kind: .reg)
        case (6, 9, 1, 5): BESSysAlias(name: "tlbi vale3osnxs", kind: .reg)
        case (6, 9, 2, 1): BESSysAlias(name: "tlbi rvae3isnxs", kind: .reg)
        case (6, 9, 2, 5): BESSysAlias(name: "tlbi rvale3isnxs", kind: .reg)
        case (6, 9, 3, 0): BESSysAlias(name: "tlbi alle3isnxs", kind: .noreg)
        case (6, 9, 3, 1): BESSysAlias(name: "tlbi vae3isnxs", kind: .reg)
        case (6, 9, 3, 5): BESSysAlias(name: "tlbi vale3isnxs", kind: .reg)
        case (6, 9, 5, 1): BESSysAlias(name: "tlbi rvae3osnxs", kind: .reg)
        case (6, 9, 5, 5): BESSysAlias(name: "tlbi rvale3osnxs", kind: .reg)
        case (6, 9, 6, 1): BESSysAlias(name: "tlbi rvae3nxs", kind: .reg)
        case (6, 9, 6, 5): BESSysAlias(name: "tlbi rvale3nxs", kind: .reg)
        case (6, 9, 7, 0): BESSysAlias(name: "tlbi alle3nxs", kind: .noreg)
        case (6, 9, 7, 1): BESSysAlias(name: "tlbi vae3nxs", kind: .reg)
        case (6, 9, 7, 5): BESSysAlias(name: "tlbi vale3nxs", kind: .reg)
        default:
            nil
        }
    }
}

/// SYSL alias lookup (L == 1), keyed by (op1, CRn, CRm, op2).
enum BESSyslAliasTable {
    @_effects(readonly)
    static func lookup(
        op1: UInt8, CRn: UInt8, CRm: UInt8, op2: UInt8,
    ) -> BESSysAlias? {
        switch (op1, CRn, CRm, op2) {
        case (3, 7, 7, 1): BESSysAlias(name: "gcspopm", kind: .optReg)
        case (3, 7, 7, 3): BESSysAlias(name: "gcsss2", kind: .reg)
        default:
            nil
        }
    }
}

/// SYSP (128-bit SYS pair) alias lookup, keyed by (op1, CRn, CRm, op2).
/// All entries render `name, xN, xN+1` (a consecutive X-register pair).
enum BESSyspAliasTable {
    @_effects(readonly)
    static func lookup(
        op1: UInt8, CRn: UInt8, CRm: UInt8, op2: UInt8,
    ) -> BESSysAlias? {
        switch (op1, CRn, CRm, op2) {
        case (0, 8, 1, 1): BESSysAlias(name: "tlbip vae1os", kind: .reg)
        case (0, 8, 1, 3): BESSysAlias(name: "tlbip vaae1os", kind: .reg)
        case (0, 8, 1, 5): BESSysAlias(name: "tlbip vale1os", kind: .reg)
        case (0, 8, 1, 7): BESSysAlias(name: "tlbip vaale1os", kind: .reg)
        case (0, 8, 2, 1): BESSysAlias(name: "tlbip rvae1is", kind: .reg)
        case (0, 8, 2, 3): BESSysAlias(name: "tlbip rvaae1is", kind: .reg)
        case (0, 8, 2, 5): BESSysAlias(name: "tlbip rvale1is", kind: .reg)
        case (0, 8, 2, 7): BESSysAlias(name: "tlbip rvaale1is", kind: .reg)
        case (0, 8, 3, 1): BESSysAlias(name: "tlbip vae1is", kind: .reg)
        case (0, 8, 3, 3): BESSysAlias(name: "tlbip vaae1is", kind: .reg)
        case (0, 8, 3, 5): BESSysAlias(name: "tlbip vale1is", kind: .reg)
        case (0, 8, 3, 7): BESSysAlias(name: "tlbip vaale1is", kind: .reg)
        case (0, 8, 5, 1): BESSysAlias(name: "tlbip rvae1os", kind: .reg)
        case (0, 8, 5, 3): BESSysAlias(name: "tlbip rvaae1os", kind: .reg)
        case (0, 8, 5, 5): BESSysAlias(name: "tlbip rvale1os", kind: .reg)
        case (0, 8, 5, 7): BESSysAlias(name: "tlbip rvaale1os", kind: .reg)
        case (0, 8, 6, 1): BESSysAlias(name: "tlbip rvae1", kind: .reg)
        case (0, 8, 6, 3): BESSysAlias(name: "tlbip rvaae1", kind: .reg)
        case (0, 8, 6, 5): BESSysAlias(name: "tlbip rvale1", kind: .reg)
        case (0, 8, 6, 7): BESSysAlias(name: "tlbip rvaale1", kind: .reg)
        case (0, 8, 7, 1): BESSysAlias(name: "tlbip vae1", kind: .reg)
        case (0, 8, 7, 3): BESSysAlias(name: "tlbip vaae1", kind: .reg)
        case (0, 8, 7, 5): BESSysAlias(name: "tlbip vale1", kind: .reg)
        case (0, 8, 7, 7): BESSysAlias(name: "tlbip vaale1", kind: .reg)
        case (0, 9, 1, 1): BESSysAlias(name: "tlbip vae1osnxs", kind: .reg)
        case (0, 9, 1, 3): BESSysAlias(name: "tlbip vaae1osnxs", kind: .reg)
        case (0, 9, 1, 5): BESSysAlias(name: "tlbip vale1osnxs", kind: .reg)
        case (0, 9, 1, 7): BESSysAlias(name: "tlbip vaale1osnxs", kind: .reg)
        case (0, 9, 2, 1): BESSysAlias(name: "tlbip rvae1isnxs", kind: .reg)
        case (0, 9, 2, 3): BESSysAlias(name: "tlbip rvaae1isnxs", kind: .reg)
        case (0, 9, 2, 5): BESSysAlias(name: "tlbip rvale1isnxs", kind: .reg)
        case (0, 9, 2, 7): BESSysAlias(name: "tlbip rvaale1isnxs", kind: .reg)
        case (0, 9, 3, 1): BESSysAlias(name: "tlbip vae1isnxs", kind: .reg)
        case (0, 9, 3, 3): BESSysAlias(name: "tlbip vaae1isnxs", kind: .reg)
        case (0, 9, 3, 5): BESSysAlias(name: "tlbip vale1isnxs", kind: .reg)
        case (0, 9, 3, 7): BESSysAlias(name: "tlbip vaale1isnxs", kind: .reg)
        case (0, 9, 5, 1): BESSysAlias(name: "tlbip rvae1osnxs", kind: .reg)
        case (0, 9, 5, 3): BESSysAlias(name: "tlbip rvaae1osnxs", kind: .reg)
        case (0, 9, 5, 5): BESSysAlias(name: "tlbip rvale1osnxs", kind: .reg)
        case (0, 9, 5, 7): BESSysAlias(name: "tlbip rvaale1osnxs", kind: .reg)
        case (0, 9, 6, 1): BESSysAlias(name: "tlbip rvae1nxs", kind: .reg)
        case (0, 9, 6, 3): BESSysAlias(name: "tlbip rvaae1nxs", kind: .reg)
        case (0, 9, 6, 5): BESSysAlias(name: "tlbip rvale1nxs", kind: .reg)
        case (0, 9, 6, 7): BESSysAlias(name: "tlbip rvaale1nxs", kind: .reg)
        case (0, 9, 7, 1): BESSysAlias(name: "tlbip vae1nxs", kind: .reg)
        case (0, 9, 7, 3): BESSysAlias(name: "tlbip vaae1nxs", kind: .reg)
        case (0, 9, 7, 5): BESSysAlias(name: "tlbip vale1nxs", kind: .reg)
        case (0, 9, 7, 7): BESSysAlias(name: "tlbip vaale1nxs", kind: .reg)
        case (4, 8, 0, 1): BESSysAlias(name: "tlbip ipas2e1is", kind: .reg)
        case (4, 8, 0, 2): BESSysAlias(name: "tlbip ripas2e1is", kind: .reg)
        case (4, 8, 0, 5): BESSysAlias(name: "tlbip ipas2le1is", kind: .reg)
        case (4, 8, 0, 6): BESSysAlias(name: "tlbip ripas2le1is", kind: .reg)
        case (4, 8, 1, 1): BESSysAlias(name: "tlbip vae2os", kind: .reg)
        case (4, 8, 1, 5): BESSysAlias(name: "tlbip vale2os", kind: .reg)
        case (4, 8, 2, 1): BESSysAlias(name: "tlbip rvae2is", kind: .reg)
        case (4, 8, 2, 5): BESSysAlias(name: "tlbip rvale2is", kind: .reg)
        case (4, 8, 3, 1): BESSysAlias(name: "tlbip vae2is", kind: .reg)
        case (4, 8, 3, 5): BESSysAlias(name: "tlbip vale2is", kind: .reg)
        case (4, 8, 4, 0): BESSysAlias(name: "tlbip ipas2e1os", kind: .reg)
        case (4, 8, 4, 1): BESSysAlias(name: "tlbip ipas2e1", kind: .reg)
        case (4, 8, 4, 2): BESSysAlias(name: "tlbip ripas2e1", kind: .reg)
        case (4, 8, 4, 3): BESSysAlias(name: "tlbip ripas2e1os", kind: .reg)
        case (4, 8, 4, 4): BESSysAlias(name: "tlbip ipas2le1os", kind: .reg)
        case (4, 8, 4, 5): BESSysAlias(name: "tlbip ipas2le1", kind: .reg)
        case (4, 8, 4, 6): BESSysAlias(name: "tlbip ripas2le1", kind: .reg)
        case (4, 8, 4, 7): BESSysAlias(name: "tlbip ripas2le1os", kind: .reg)
        case (4, 8, 5, 1): BESSysAlias(name: "tlbip rvae2os", kind: .reg)
        case (4, 8, 5, 5): BESSysAlias(name: "tlbip rvale2os", kind: .reg)
        case (4, 8, 6, 1): BESSysAlias(name: "tlbip rvae2", kind: .reg)
        case (4, 8, 6, 5): BESSysAlias(name: "tlbip rvale2", kind: .reg)
        case (4, 8, 7, 1): BESSysAlias(name: "tlbip vae2", kind: .reg)
        case (4, 8, 7, 5): BESSysAlias(name: "tlbip vale2", kind: .reg)
        case (4, 9, 0, 1): BESSysAlias(name: "tlbip ipas2e1isnxs", kind: .reg)
        case (4, 9, 0, 2): BESSysAlias(name: "tlbip ripas2e1isnxs", kind: .reg)
        case (4, 9, 0, 5): BESSysAlias(name: "tlbip ipas2le1isnxs", kind: .reg)
        case (4, 9, 0, 6): BESSysAlias(name: "tlbip ripas2le1isnxs", kind: .reg)
        case (4, 9, 1, 1): BESSysAlias(name: "tlbip vae2osnxs", kind: .reg)
        case (4, 9, 1, 5): BESSysAlias(name: "tlbip vale2osnxs", kind: .reg)
        case (4, 9, 2, 1): BESSysAlias(name: "tlbip rvae2isnxs", kind: .reg)
        case (4, 9, 2, 5): BESSysAlias(name: "tlbip rvale2isnxs", kind: .reg)
        case (4, 9, 3, 1): BESSysAlias(name: "tlbip vae2isnxs", kind: .reg)
        case (4, 9, 3, 5): BESSysAlias(name: "tlbip vale2isnxs", kind: .reg)
        case (4, 9, 4, 0): BESSysAlias(name: "tlbip ipas2e1osnxs", kind: .reg)
        case (4, 9, 4, 1): BESSysAlias(name: "tlbip ipas2e1nxs", kind: .reg)
        case (4, 9, 4, 2): BESSysAlias(name: "tlbip ripas2e1nxs", kind: .reg)
        case (4, 9, 4, 3): BESSysAlias(name: "tlbip ripas2e1osnxs", kind: .reg)
        case (4, 9, 4, 4): BESSysAlias(name: "tlbip ipas2le1osnxs", kind: .reg)
        case (4, 9, 4, 5): BESSysAlias(name: "tlbip ipas2le1nxs", kind: .reg)
        case (4, 9, 4, 6): BESSysAlias(name: "tlbip ripas2le1nxs", kind: .reg)
        case (4, 9, 4, 7): BESSysAlias(name: "tlbip ripas2le1osnxs", kind: .reg)
        case (4, 9, 5, 1): BESSysAlias(name: "tlbip rvae2osnxs", kind: .reg)
        case (4, 9, 5, 5): BESSysAlias(name: "tlbip rvale2osnxs", kind: .reg)
        case (4, 9, 6, 1): BESSysAlias(name: "tlbip rvae2nxs", kind: .reg)
        case (4, 9, 6, 5): BESSysAlias(name: "tlbip rvale2nxs", kind: .reg)
        case (4, 9, 7, 1): BESSysAlias(name: "tlbip vae2nxs", kind: .reg)
        case (4, 9, 7, 5): BESSysAlias(name: "tlbip vale2nxs", kind: .reg)
        case (6, 8, 1, 1): BESSysAlias(name: "tlbip vae3os", kind: .reg)
        case (6, 8, 1, 5): BESSysAlias(name: "tlbip vale3os", kind: .reg)
        case (6, 8, 2, 1): BESSysAlias(name: "tlbip rvae3is", kind: .reg)
        case (6, 8, 2, 5): BESSysAlias(name: "tlbip rvale3is", kind: .reg)
        case (6, 8, 3, 1): BESSysAlias(name: "tlbip vae3is", kind: .reg)
        case (6, 8, 3, 5): BESSysAlias(name: "tlbip vale3is", kind: .reg)
        case (6, 8, 5, 1): BESSysAlias(name: "tlbip rvae3os", kind: .reg)
        case (6, 8, 5, 5): BESSysAlias(name: "tlbip rvale3os", kind: .reg)
        case (6, 8, 6, 1): BESSysAlias(name: "tlbip rvae3", kind: .reg)
        case (6, 8, 6, 5): BESSysAlias(name: "tlbip rvale3", kind: .reg)
        case (6, 8, 7, 1): BESSysAlias(name: "tlbip vae3", kind: .reg)
        case (6, 8, 7, 5): BESSysAlias(name: "tlbip vale3", kind: .reg)
        case (6, 9, 1, 1): BESSysAlias(name: "tlbip vae3osnxs", kind: .reg)
        case (6, 9, 1, 5): BESSysAlias(name: "tlbip vale3osnxs", kind: .reg)
        case (6, 9, 2, 1): BESSysAlias(name: "tlbip rvae3isnxs", kind: .reg)
        case (6, 9, 2, 5): BESSysAlias(name: "tlbip rvale3isnxs", kind: .reg)
        case (6, 9, 3, 1): BESSysAlias(name: "tlbip vae3isnxs", kind: .reg)
        case (6, 9, 3, 5): BESSysAlias(name: "tlbip vale3isnxs", kind: .reg)
        case (6, 9, 5, 1): BESSysAlias(name: "tlbip rvae3osnxs", kind: .reg)
        case (6, 9, 5, 5): BESSysAlias(name: "tlbip rvale3osnxs", kind: .reg)
        case (6, 9, 6, 1): BESSysAlias(name: "tlbip rvae3nxs", kind: .reg)
        case (6, 9, 6, 5): BESSysAlias(name: "tlbip rvale3nxs", kind: .reg)
        case (6, 9, 7, 1): BESSysAlias(name: "tlbip vae3nxs", kind: .reg)
        case (6, 9, 7, 5): BESSysAlias(name: "tlbip vale3nxs", kind: .reg)
        default:
            nil
        }
    }
}
