// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// SYS / SYSL.
// Encoding: 1101 0101 0000 L 01 op1 CRn CRm op2 Rt   (L=0 → SYS, L=1 → SYSL)
// The decoder carries the entire 32-bit encoding via .systemOp(SystemOp),
// preserving op1/CRn/CRm/op2/Rt verbatim. The canonicalizer extracts the
// fields and renders against the IC/DC/AT/TLBI alias table
// (Disassembler/BESCanonicalizer.swift) — friendly-name lookup is
// purely a text-rendering concern.
//
// `semanticReads` covers Rt when L=0 (SYS may read the operand register),
// `semanticWrites` covers Rt when L=1 (SYSL returns the result there).
// Whether Rt is actually used for a given alias is the canonicalizer's
// concern; here we conservatively populate the side that matches L.

enum SystemInstructionDecode {
    @inline(__always)
    static func decode(
        encoding: UInt32, address: UInt64, L: UInt8, Rt: UInt8,
    ) -> DecodedDraft {
        let rtRef: RegisterRef = (Rt == 31) ? .xzr() : .x(Rt)
        let mnemonic: Mnemonic = (L == 0) ? .sys : .sysl
        // Gate the Rt semantic side on whether the matched alias touches Rt
        // for the encoded value. Aliases that don't take an Rt operand
        // (e.g. `ic iallu`, `tlbi vmalle1`) encode Rt as XZR; the
        // architectural semantics don't read XZR in that case. Generic
        // SYS/SYSL without a matching alias uses Rt when Rt != 31 (a
        // settable Rt would be a real register).
        let op1 = UInt8((encoding >> 16) & 0x7)
        let CRn = UInt8((encoding >> 12) & 0xF)
        let CRm = UInt8((encoding >> 8) & 0xF)
        let op2 = UInt8((encoding >> 5) & 0x7)
        let alias = (L == 0)
            ? BESSysAliasTable.lookup(op1: op1, CRn: CRn, CRm: CRm, op2: op2)
            : BESSyslAliasTable.lookup(op1: op1, CRn: CRn, CRm: CRm, op2: op2)
        // SYS may read Rt; SYSL writes Rt. A matched alias gates Rt on its
        // kind. Generic SYS (no alias) omits Rt when it's XZR, so it only
        // reads Rt when Rt != 31; generic SYSL always renders Rt verbatim
        // (including xzr), so it always writes Rt.
        let sysTouchesRt = alias.map { $0.touchesRt(Rt) } ?? (Rt != 31)
        let syslTouchesRt = alias.map { $0.touchesRt(Rt) } ?? true
        let reads: RegisterSet = (L == 0 && sysTouchesRt)
            ? RegisterSet.empty.inserting(rtRef)
            : .empty
        let writes: RegisterSet = (L == 1 && syslTouchesRt)
            ? RegisterSet.empty.inserting(rtRef)
            : .empty
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: writes,
            category: .branchesExceptionSystem,
            operands: [.systemOp(SystemOp(rawEncoding: encoding))],
        )
    }

    /// FEAT_D128 SYSP — 128-bit SYS pair. Rt must be even or 31
    /// (Rt<0> == 1 && Rt != 31 is UNDEFINED). Reads the (Rt, Rt+1) pair when
    /// a TLBIP alias matches (always rendered) or when Rt != 31 (generic
    /// form renders the pair); a generic SYSP with Rt == 31 reads nothing.
    @inline(__always)
    static func decodeSysp(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let Rt = UInt8(encoding & 0x1F)
        if Rt & 1 != 0, Rt != 31 {
            return .undefined(at: address, encoding: encoding)
        }
        let op1 = UInt8((encoding >> 16) & 0x7)
        let CRn = UInt8((encoding >> 12) & 0xF)
        let CRm = UInt8((encoding >> 8) & 0xF)
        let op2 = UInt8((encoding >> 5) & 0x7)
        let aliased = BESSyspAliasTable.lookup(op1: op1, CRn: CRn, CRm: CRm, op2: op2) != nil
        let readsPair = aliased || Rt != 31
        let rt2: UInt8 = (Rt == 31) ? 31 : (Rt &+ 1)
        let reads: RegisterSet = readsPair
            ? RegisterSet.empty.inserting(.x(Rt)).inserting(.x(rt2))
            : .empty
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .sysp,
            semanticReads: reads,
            category: .branchesExceptionSystem,
            operands: [.systemOp(SystemOp(rawEncoding: encoding))],
        )
    }
}
