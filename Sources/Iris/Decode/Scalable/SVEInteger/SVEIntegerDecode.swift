// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// SVE / SVE2 integer decoder. Entry + top sub-dispatch
// split on the top byte (one of 0x04/0x05/0x24/0x25/0x44/
// 0x45) and then on bits[23:10] (which provably determine the decode group,
// ) into the 21 per-group decoders that live in sibling files.
// Called only from `SVEDecoder.decode` when `isSVEIntegerEncoding` holds, so
// `decode` is total over SVE-integer's domain: every path returns a real record or
// a well-formed UNDEFINED (`.undefined`, `.sve`) for the genuine in-scope
// holes (reserved opc, illegal size, reserved bitmask immediate).
//
// Shared field extraction and draft-building helpers used by every group
// decoder live here.

/// The SVE / SVE2 integer decoder for SVE-integer.
enum SVEIntegerDecode {
    /// Decode an in-scope SVE integer word. Precondition (by construction,
    /// not asserted): `isSVEIntegerEncoding(encoding)`.
    @_optimize(speed)
    static func decode(encoding e: UInt32, address a: UInt64) -> DecodedDraft {
        switch (e >> 24) & 0xFF {
        case 0x24: decodeCompare(e, a) // G7 vector/wide + ucmp-immediate
        case 0x04: decodeCompute(e, a) // G1-G6 predicated + G6/G17 unpredicated
        case 0x05: decodeMove(e, a) // G8 move/copy + G9 logical-immediate
        case 0x25: decodeImmediate(e, a) // G7 scmp-imm + G10 wide-imm + G8 dup-imm
        case 0x44: decodeSVE2Low(e, a) // G11/G12/G13/G18/G19/G20
        // 0x45 — the sixth and last top byte `isSVEIntegerEncoding` admits, so
        // the dispatch needs no unreachable UNDEFINED arm.
        default: decodeSVE2High(e, a) // G12/G14/G15/G16/G18
        }
    }

    // MARK: 0x04 compute sub-dispatch (predicated bit21=0 / unpredicated bit21=1)

    //
    // Group routing verified against the tblgen encodings. Predicated
    // (bit21=0), by bits[15:13]: 000 arith/log (G1); 001 reductions (G5); 010/011
    // MLA/MLS (G4); 100 shifts (G2); 101 unary (G3); 110/111 MAD/MSB (G4).
    // Unpredicated (bit21=1), by bits[15:12]: 0000/0001 arith (G6); 0011 logical +
    // ternary/XAR (G6/G17); 0110/0111 mul (G6); 1000 shift-wide, 1001 shift-imm,
    // 1010 ADR (G6).

    @inline(__always)
    static func decodeCompute(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        if (e >> 21) & 1 == 0 {
            switch (e >> 13) & 0b111 {
            case 0b000: return decodePredicatedArithLog(e, a) // G1
            case 0b001: return decodeReduction(e, a) // G5
            case 0b010, 0b011: return decodeMultiplyAddMLA(e, a) // G4 MLA/MLS
            case 0b100: return decodePredicatedShift(e, a) // G2
            case 0b101: return decodePredicatedUnary(e, a) // G3
            default: return decodeMultiplyAddMAD(e, a) // 110/111 → G4 MAD/MSB
            }
        }
        return decodeUnpredicated(e, a) // G6 + G17
    }

    // MARK: shared field extraction

    /// Element size from a 2-bit `sz` value (already shifted to the low 2 bits).
    @inline(__always)
    static func elementSize(_ sz: UInt32) -> ScalarSize {
        switch sz & 0b11 {
        case 0: .b
        case 1: .h
        case 2: .s
        default: .d
        }
    }

    /// The element size one step below `size` — the source width of a widening
    /// form (and the destination width of a narrowing one). Nil for `.b`, which
    /// has nothing below it.
    @inline(__always)
    static func narrower(_ size: ScalarSize) -> ScalarSize? {
        switch size {
        case .b: nil
        case .h: .b
        case .s: .h
        case .d: .s
        case .q: .d
        }
    }

    /// Sign-extend the low `bits` of `value` to a signed 64-bit integer.
    @inline(__always)
    static func signExtend(_ value: UInt32, bits: UInt32) -> Int64 {
        let v = Int64(value & ((UInt32(1) << bits) - 1))
        let signBit = Int64(1) << (bits - 1)
        return (v ^ signBit) &- signBit
    }

    /// Append the operand(s) for a shifted imm8 (`#imm8{, lsl #8}`). llvm-mc folds
    /// the LSL #8 into the printed value (`#imm8 << 8`) for every nonzero imm8,
    /// but renders `#0, lsl #8` for imm8=0 (folding would lose the shift) — so
    /// that one case appends two operands instead of one. Appends into the
    /// caller's array rather than returning a fresh one: this is on the decode
    /// hot path, and building `[a, b] + helper()` would allocate three times.
    @inline(__always)
    static func appendShiftedImmediate(
        raw: UInt32, shift: UInt32, signed: Bool, to operands: inout [Operand],
    ) {
        if shift != 0, raw == 0 {
            operands.append(signed
                ? .immediate(value: 0, width: 8)
                : .unsignedImmediate(value: 0, width: 8))
            operands.append(.shiftAmount(kind: .lsl, amount: UInt8(shift)))
            return
        }
        let width: UInt8 = shift == 0 ? 8 : 16
        operands.append(signed
            ? .immediate(value: signExtend(raw, bits: 8) << Int64(shift), width: width)
            : .unsignedImmediate(value: UInt64(raw) << shift, width: width))
    }

    /// Decode the SVE **shift-immediate** `tsz` scheme. The concatenation
    /// `tszHigh : low` (with `low` being `lowBits` wide) forms a value whose
    /// HIGHEST set bit selects the element size — bit 3 → .b, 4 → .h, 5 → .s,
    /// 6 → .d — and the remaining low bits carry the shift amount. Returns
    /// `(element, esize, tsz)` or nil when the field is reserved (all-zero, or a
    /// size the caller has excluded).
    ///
    /// This is **not** the element-*index* scheme: the DUP-indexed broadcast uses
    /// the LOWEST set bit and has a `.q` arm, and is decoded separately in
    /// ``decodeDupIndexed(_:_:)``. The two are not interchangeable.
    @inline(__always)
    static func decodeTsz(tszHigh: UInt32, low: UInt32, lowBits: UInt32) -> (element: ScalarSize, esize: Int, tsz: UInt32)? {
        let tsz = (tszHigh << lowBits) | low
        guard tsz != 0 else { return nil }
        switch 31 - tsz.leadingZeroBitCount {
        case 3: return (.b, 8, tsz)
        case 4: return (.h, 16, tsz)
        case 5: return (.s, 32, tsz)
        case 6: return (.d, 64, tsz)
        default: return nil
        }
    }

    @inline(__always) static func zd(_ e: UInt32) -> UInt8 {
        UInt8(e & 0x1F)
    }

    @inline(__always) static func zn(_ e: UInt32) -> UInt8 {
        UInt8((e >> 5) & 0x1F)
    }

    @inline(__always) static func zm(_ e: UInt32) -> UInt8 {
        UInt8((e >> 16) & 0x1F)
    }

    @inline(__always) static func pg3(_ e: UInt32) -> UInt8 {
        UInt8((e >> 10) & 0x7)
    }

    @inline(__always) static func sz(_ e: UInt32) -> ScalarSize {
        elementSize(e >> 22)
    }

    // MARK: shared operand + mask builders

    @inline(__always)
    static func vec(_ index: UInt8, _ element: ScalarSize) -> Operand {
        .scalableVector(ScalableVectorRef(registerIndex: index, element: element))
    }

    @inline(__always)
    static func govern(_ index: UInt8, _ qualifier: PredicateQualifier) -> Operand {
        .scalablePredicate(ScalablePredicateRef(registerIndex: index, qualifier: qualifier, role: .governing))
    }

    @inline(__always)
    static func vecMask(_ index: UInt8) -> RegisterSet {
        RegisterSet.empty.inserting(ScalableVectorRef(registerIndex: index))
    }

    /// A well-formed in-scope UNDEFINED SVE record (`category = .sve`, raw
    /// encoding preserved), matching llvm-mc's empty output for rejected words.
    @inline(__always)
    static func undefined(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        DecodedDraft(address: a, encoding: e, mnemonic: .undefined, category: .sve)
    }
}
