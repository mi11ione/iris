// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// the move/lookup families in cell 110|0|x (top byte 0xC0):
// MOVA/MOVAZ multi-slice (ZA <-> vector list), the ZA-array and ZT0 ZERO
// forms, MOVT (GPR/vector <-> ZT0), and the ZT0-table LUTI2/LUTI4/LUTI6
// lookups. Routed by bits[23:16]: 0x0C-0x0F ZERO-array,
// 0x48 ZERO-ZT0, 0x4C/0x4E/0x4F MOVT, 0x02/0x04/0x06/… MOVA/MOVAZ,
// 0x8A-0x9C/0xC8-0xCC LUTI. MOVA renders `mov` (unconditional alias);
// MOVAZ renders `movaz`.

/// SME2 move/lookup decoders.
enum SME2MoveLookupDecode {
    /// Decode a cell-`110|0|x` word (top byte 0xC0).
    @_optimize(speed)
    static func decode(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        if let d = decodeMovaArray(e, a) { return d }
        if let d = decodeMovaTileSlice(e, a) { return d }
        return switch (e >> 16) & 0xFF {
        case 0x0C, 0x0D, 0x0E, 0x0F: decodeZeroArray(e, a)
        case 0x48: decodeZeroZT0(e, a)
        case 0x4C, 0x4E, 0x4F: decodeMovt(e, a)
        // LUTI index bits bleed into bits[17:16], so its region byte is not a
        // stable key — the table match (below) handles it directly.
        default: decodeLuti(e, a)
        }
    }

    // MARK: - LUTI2 / LUTI4 / LUTI6 (ZT0 table lookup)

    /// The destination/source shape of a LUTI record.
    private enum LutiForm {
        /// Single `Zd`, single `Zn[i]` source (LUTI2/4).
        case single
        /// Multi `{Zd}` (2- or 4-way), single `Zn[i]` source (LUTI2/4).
        case multi
        /// 4-way `{Zd}`, consecutive `Zn` pair source, no index (LUTv2).
        case lutv2
        /// Single `Zd`, single plain `Zn` source, no index (LUTI6).
        case luti6single
        /// 4-way `{Zd}`, `Zn` triple source, no index (LUTI6).
        case luti6multi
    }

    /// One LUTI record — exact `(mask, value)`, the form, element, `.S`-stride,
    /// destination width, and the table-index field. Generated from the ARM
    /// records so the mask rejects reserved-bit holes by construction.
    private struct LutiRow {
        let mask: UInt32
        let value: UInt32
        let mnemonic: Mnemonic
        let form: LutiForm
        let element: ScalarSize
        let strided: Bool
        let count: UInt8
        let indexShift: UInt8
        let indexWidth: UInt8
    }

    /// The LUTI record table (`ZT0`-lookup forms; the `0xC1` LUTI6 no-`ZT0`
    /// form is decoded in ``SME2VectorOpsDecode``).
    private static let lutiTable: [LutiRow] = [
        LutiRow(mask: 0xFFFF_FC63, value: 0xC08A_0000, mnemonic: .luti6, form: .luti6multi, element: .b, strided: false, count: 4, indexShift: 0, indexWidth: 0),
        LutiRow(mask: 0xFFFE_7C01, value: 0xC08A_4000, mnemonic: .luti4, form: .multi, element: .b, strided: false, count: 2, indexShift: 15, indexWidth: 2),
        LutiRow(mask: 0xFFFE_7C01, value: 0xC08A_5000, mnemonic: .luti4, form: .multi, element: .h, strided: false, count: 2, indexShift: 15, indexWidth: 2),
        LutiRow(mask: 0xFFFE_7C01, value: 0xC08A_6000, mnemonic: .luti4, form: .multi, element: .s, strided: false, count: 2, indexShift: 15, indexWidth: 2),
        LutiRow(mask: 0xFFFE_FC03, value: 0xC08A_9000, mnemonic: .luti4, form: .multi, element: .h, strided: false, count: 4, indexShift: 16, indexWidth: 1),
        LutiRow(mask: 0xFFFE_FC03, value: 0xC08A_A000, mnemonic: .luti4, form: .multi, element: .s, strided: false, count: 4, indexShift: 16, indexWidth: 1),
        LutiRow(mask: 0xFFFF_FC23, value: 0xC08B_0000, mnemonic: .luti4, form: .lutv2, element: .b, strided: false, count: 4, indexShift: 0, indexWidth: 0),
        LutiRow(mask: 0xFFFC_7C01, value: 0xC08C_4000, mnemonic: .luti2, form: .multi, element: .b, strided: false, count: 2, indexShift: 15, indexWidth: 3),
        LutiRow(mask: 0xFFFC_7C01, value: 0xC08C_5000, mnemonic: .luti2, form: .multi, element: .h, strided: false, count: 2, indexShift: 15, indexWidth: 3),
        LutiRow(mask: 0xFFFC_7C01, value: 0xC08C_6000, mnemonic: .luti2, form: .multi, element: .s, strided: false, count: 2, indexShift: 15, indexWidth: 3),
        LutiRow(mask: 0xFFFC_FC03, value: 0xC08C_8000, mnemonic: .luti2, form: .multi, element: .b, strided: false, count: 4, indexShift: 16, indexWidth: 2),
        LutiRow(mask: 0xFFFC_FC03, value: 0xC08C_9000, mnemonic: .luti2, form: .multi, element: .h, strided: false, count: 4, indexShift: 16, indexWidth: 2),
        LutiRow(mask: 0xFFFC_FC03, value: 0xC08C_A000, mnemonic: .luti2, form: .multi, element: .s, strided: false, count: 4, indexShift: 16, indexWidth: 2),
        LutiRow(mask: 0xFFFF_FC6C, value: 0xC09A_0000, mnemonic: .luti6, form: .luti6multi, element: .b, strided: true, count: 4, indexShift: 0, indexWidth: 0),
        LutiRow(mask: 0xFFFE_7C08, value: 0xC09A_4000, mnemonic: .luti4, form: .multi, element: .b, strided: true, count: 2, indexShift: 15, indexWidth: 2),
        LutiRow(mask: 0xFFFE_7C08, value: 0xC09A_5000, mnemonic: .luti4, form: .multi, element: .h, strided: true, count: 2, indexShift: 15, indexWidth: 2),
        LutiRow(mask: 0xFFFE_FC0C, value: 0xC09A_9000, mnemonic: .luti4, form: .multi, element: .h, strided: true, count: 4, indexShift: 16, indexWidth: 1),
        LutiRow(mask: 0xFFFF_FC2C, value: 0xC09B_0000, mnemonic: .luti4, form: .lutv2, element: .b, strided: true, count: 4, indexShift: 0, indexWidth: 0),
        LutiRow(mask: 0xFFFC_7C08, value: 0xC09C_4000, mnemonic: .luti2, form: .multi, element: .b, strided: true, count: 2, indexShift: 15, indexWidth: 3),
        LutiRow(mask: 0xFFFC_7C08, value: 0xC09C_5000, mnemonic: .luti2, form: .multi, element: .h, strided: true, count: 2, indexShift: 15, indexWidth: 3),
        LutiRow(mask: 0xFFFC_FC0C, value: 0xC09C_8000, mnemonic: .luti2, form: .multi, element: .b, strided: true, count: 4, indexShift: 16, indexWidth: 2),
        LutiRow(mask: 0xFFFC_FC0C, value: 0xC09C_9000, mnemonic: .luti2, form: .multi, element: .h, strided: true, count: 4, indexShift: 16, indexWidth: 2),
        LutiRow(mask: 0xFFFF_FC00, value: 0xC0C8_4000, mnemonic: .luti6, form: .luti6single, element: .b, strided: false, count: 1, indexShift: 0, indexWidth: 0),
        LutiRow(mask: 0xFFFE_3C00, value: 0xC0CA_0000, mnemonic: .luti4, form: .single, element: .b, strided: false, count: 1, indexShift: 14, indexWidth: 3),
        LutiRow(mask: 0xFFFE_3C00, value: 0xC0CA_1000, mnemonic: .luti4, form: .single, element: .h, strided: false, count: 1, indexShift: 14, indexWidth: 3),
        LutiRow(mask: 0xFFFE_3C00, value: 0xC0CA_2000, mnemonic: .luti4, form: .single, element: .s, strided: false, count: 1, indexShift: 14, indexWidth: 3),
        LutiRow(mask: 0xFFFC_3C00, value: 0xC0CC_0000, mnemonic: .luti2, form: .single, element: .b, strided: false, count: 1, indexShift: 14, indexWidth: 4),
        LutiRow(mask: 0xFFFC_3C00, value: 0xC0CC_1000, mnemonic: .luti2, form: .single, element: .h, strided: false, count: 1, indexShift: 14, indexWidth: 4),
        LutiRow(mask: 0xFFFC_3C00, value: 0xC0CC_2000, mnemonic: .luti2, form: .single, element: .s, strided: false, count: 1, indexShift: 14, indexWidth: 4),
    ]

    /// LUTI2/LUTI4/LUTI6 lookups from `ZT0` into a Z destination, matched by
    /// exact `(mask, value)` — the mask rejects reserved encodings and the
    /// index bits that bleed into the region byte.
    @_optimize(speed)
    private static func decodeLuti(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        for row in lutiTable where e & row.mask == row.value {
            return buildLuti(e, a, row)
        }
        return SME2Decode.undefined(e, a)
    }

    @inline(__always)
    private static func buildLuti(_ e: UInt32, _ a: UInt64, _ row: LutiRow) -> DecodedDraft {
        let index = row.indexWidth == 0
            ? nil : UInt8((e >> row.indexShift) & ((1 << row.indexWidth) - 1))
        let zn = UInt8((e >> 5) & 0x1F)
        let dest: Operand
        let destWrites: RegisterSet
        var source: Operand
        var sourceReads: RegisterSet

        switch row.form {
        case .single, .luti6single:
            let zd = SME2Decode.zd5(e)
            dest = SME2Decode.vec(zd, row.element)
            destWrites = SME2Decode.vecMask(zd)
            source = SME2Decode.vec(zn, nil, index: index)
            sourceReads = SME2Decode.vecMask(zn)
        default:
            let zFirst = lutiDestFirst(e, row.count, strided: row.strided)
            dest = SME2Decode.group(zFirst, row.count, row.element, strided: row.strided)
            destWrites = SME2Decode.groupMask(zFirst, row.count, strided: row.strided)
            source = SME2Decode.vec(zn, nil, index: index)
            sourceReads = SME2Decode.vecMask(zn)
        }
        switch row.form {
        case .lutv2:
            let znPair = UInt8((e >> 6) & 0xF) &* 2
            source = SME2Decode.group(znPair, 2, nil)
            sourceReads = SME2Decode.groupMask(znPair, 2)
        case .luti6multi:
            let znTriple = UInt8((e >> 7) & 0x7)
            source = SME2Decode.group(znTriple, 3, nil)
            sourceReads = SME2Decode.groupMask(znTriple, 3)
        default:
            break
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: row.mnemonic,
            semanticReads: sourceReads, semanticWrites: destWrites, category: .sme,
            operands: [dest, .zt0(elementIndex: nil), source],
            scalableReads: SME2Decode.zt0Mask(),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// The first destination register of a LUTI multi group — consecutive
    /// (`field×n` at bits[4:1]/[4:2]) or strided (`16·D + low`, stride `16/n`).
    @inline(__always)
    private static func lutiDestFirst(_ e: UInt32, _ count: UInt8, strided: Bool) -> UInt8 {
        if strided {
            let low: UInt8 = count == 4 ? UInt8(e & 0x3) : UInt8(e & 0x7)
            return UInt8((e >> 4) & 0x1) &* 16 &+ low
        }
        return count == 4 ? UInt8(e & 0x1C) : UInt8(e & 0x1E)
    }

    // MARK: - MOVA / MOVAZ (tile-slice multi-vector forms)

    /// MOVA/MOVAZ between a `ZA` tile-slice range and a vector group (list↔tile
    /// and single-slice MOVAZ). MOVA renders `mov`; MOVAZ renders `movaz`.
    /// Returns `nil` for a non-tile-slice-MOVA word. The tile/offset packing is
    /// at bits[8:5] (per element), the range spans the group width, and the
    /// select register is `W12+Rs`.
    @inline(__always)
    private static func decodeMovaTileSlice(_ e: UInt32, _ a: UInt64) -> DecodedDraft? {
        // Single-slice MOVAZ: `movaz Zd, za<t>{h|v}.<T>[Ws, off]` (no range).
        // The b/h/s/d forms free the size bits (bit16=0); `.q` is the exact
        // size-11 + bit16=1 encoding.
        if e & 0xFF3F_1E00 == 0xC002_0200 || e & 0xFFFF_1E00 == 0xC0C3_0200 {
            let element: ScalarSize = e & 0x10000 != 0 ? .q : sizeElement(e)
            let (tile, slot) = singleSliceTileSlot(e, element)
            let slice = tileSliceOperand(e, tile: tile, element: element, offset: slot, offsetHigh: nil)
            let zd = SME2Decode.zd5(e)
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .movaz,
                semanticReads: SME2Decode.selectMask(SME2Decode.selectW12(e)),
                semanticWrites: SME2Decode.vecMask(zd), category: .sme,
                operands: [SME2Decode.vec(zd, element), slice],
                scalableReads: SME2Decode.zaWholeMask(), scalableWrites: SME2Decode.zaWholeMask(),
                scalableEffect: [.readsStreamingMode, .partialWrite],
            )
        }
        // Multi list↔tile: bit17=0 write (list→tile), bit17=1 read (tile→list);
        // bit10=1 is 4-way; bit9=1 is MOVAZ (read direction only). The opcode
        // fixes bits[12:11]=0 (bit11=1 is the array form) and bit16=0.
        guard e & 0xFF01_1800 == 0xC000_0000 else { return nil }
        let op = (e >> 17) & 0x7F
        guard op == 0x02 || op == 0x03 || op == 0x22 || op == 0x23
            || op == 0x42 || op == 0x43 || op == 0x62 || op == 0x63 else { return nil }
        let read = e & 0x0002_0000 != 0
        let movaz = read && e & 0x200 != 0
        let count: UInt8 = e & 0x400 != 0 ? 4 : 2
        let element = sizeElement(e)
        // The tile:slot field is bits[2:0] (write) / bits[7:5] (read); the list
        // is at bits[9:6]/[9:7] (write) or bits[4:0] (read).
        guard let (tile, lo, hi) = multiTileSlice(e, count: count, read: read) else { return nil }
        let zFirst: UInt8
        if read {
            // Zd at bits[4:1] (×2, bit0 reserved) / bits[4:2] (×4, bits[1:0]
            // reserved).
            if e & (count == 4 ? 0x3 : 0x1) != 0 { return nil }
            zFirst = count == 4 ? UInt8(e & 0x1C) : UInt8(e & 0x1E)
        } else {
            // Write: tile/offset is bits[2:0], so bits[5:3] are reserved; Zn is
            // at bits[9:6] (×2) / bits[9:7] (×4), with bit6 reserved for 4-way.
            if e & 0x38 != 0 { return nil }
            if count == 4, e & 0x40 != 0 { return nil }
            zFirst = count == 4 ? UInt8((e >> 7) & 0x7) &* 4 : UInt8((e >> 6) & 0xF) &* 2
        }
        let slice = tileSliceOperand(e, tile: tile, element: element, offset: lo, offsetHigh: hi)
        let list = SME2Decode.group(zFirst, count, element)
        let listMask = SME2Decode.groupMask(zFirst, count)
        let za = SME2Decode.zaWholeMask()
        return DecodedDraft(
            address: a, encoding: e, mnemonic: read ? (movaz ? .movaz : .mov) : .mov,
            semanticReads: (read ? .empty : listMask).union(SME2Decode.selectMask(SME2Decode.selectW12(e))),
            semanticWrites: read ? listMask : .empty,
            category: .sme,
            operands: read ? [list, slice] : [slice, list],
            scalableReads: za, scalableWrites: read && !movaz ? .empty : za,
            // Partial only when this record writes ZA (write direction, or
            // MOVAZ zeroing); the MOVA-read direction fully writes its Z list.
            scalableEffect: read && !movaz
                ? .readsStreamingMode : [.readsStreamingMode, .partialWrite],
        )
    }

    /// The `(tile, offset-lo, offset-hi)` of a multi-vector MOVA tile-slice.
    /// The tile:slot field sits in the 3-bit region bits[2:0] (write) /
    /// bits[7:5] (read); its width is `max(tileBits, 3-way-base)` — `log2(N)`
    /// tile bits plus `base − tileBits` offset bits (base 3 for 2-way, 2 for
    /// 4-way), clamped so `.d`/`.s` keep their full tile index. The offset
    /// scales by the group width. Any set bit above the field width in the
    /// region, or `bit8` on a read, is reserved and rejects.
    @inline(__always)
    private static func multiTileSlice(
        _ e: UInt32, count: UInt8, read: Bool,
    ) -> (tile: UInt8, lo: UInt8, hi: UInt8)? {
        if read, e & 0x100 != 0 { return nil } // read bit8 reserved
        // Tile-index bit count = the size field (`.b`/`.h`/`.s`/`.d` -> 0/1/2/3);
        // the multi tile-slice form is never `.q`.
        let tb = UInt8((e >> 22) & 0x3)
        let base: UInt8 = count == 4 ? 2 : 3
        let offsetBits: UInt8 = tb < base ? base - tb : 0
        // fieldWidth is `base` (when tb < base) or `tb` (otherwise) — both ≤ 3,
        // so the 3-bit region always has room.
        let fieldWidth = tb + offsetBits
        let region = read ? UInt8((e >> 5) & 0x7) : UInt8(e & 0x7)
        if region & ~((1 << fieldWidth) - 1) != 0 { return nil } // reserved high bits
        let slot = region & ((1 << offsetBits) - 1)
        let lo = slot &* count
        return (region >> offsetBits, lo, lo &+ count &- 1)
    }

    /// Split the `bits[8:5]` tile/offset field for a single-slice MOVAZ (`Zd`
    /// is `bits[4:0]`, so the tile/offset moves up to `bits[8:5]`).
    @inline(__always)
    private static func singleSliceTileSlot(_ e: UInt32, _ element: ScalarSize) -> (UInt8, UInt8) {
        let field = UInt8((e >> 5) & 0xF)
        switch element {
        case .b: return (0, field)
        case .h: return ((field >> 3) & 0x1, field & 0x7)
        case .s: return ((field >> 2) & 0x3, field & 0x3)
        case .d: return ((field >> 1) & 0x7, field & 0x1)
        case .q: return (field, 0)
        }
    }

    /// A `ZA` tile-slice operand `za<t>{h|v}.<T>[W12+Rs, off{:hi}]`.
    @inline(__always)
    private static func tileSliceOperand(
        _ e: UInt32, tile: UInt8, element: ScalarSize, offset: UInt8, offsetHigh: UInt8?,
    ) -> Operand {
        .zaTileSlice(ZATileSliceOperand(
            tileIndex: tile, element: element,
            direction: e & 0x8000 != 0 ? .vertical : .horizontal,
            selectRegister: SME2Decode.selectW12(e), offset: offset, offsetHigh: offsetHigh,
        ))
    }

    /// Element size from bits[23:22].
    @inline(__always)
    private static func sizeElement(_ e: UInt32) -> ScalarSize {
        switch (e >> 22) & 0x3 {
        case 0: .b
        case 1: .h
        case 2: .s
        default: .d
        }
    }

    // MARK: - MOVA / MOVAZ (ZA-array multi-vector forms)

    /// MOVA/MOVAZ between a `.d` `ZA`-array vector `za.d[W8+Rv, off, vgxN]` and
    /// a `.d` vector group. MOVA renders `mov` (the always-preferred alias);
    /// MOVAZ (which zeroes the read `ZA` slices) renders `movaz`. Returns `nil`
    /// for a non-array-MOVA word (the tile-slice forms are handled by
    /// ``decodeMovaTileSlice``).
    @inline(__always)
    private static func decodeMovaArray(_ e: UInt32, _ a: UInt64) -> DecodedDraft? {
        // Array WRITE (`mov za.d[Wv, off, vgxN], {Zn}`): the offset is bits[2:0]
        // and the source list `Zn` is bits[9:6] (×2) / bits[9:7] (×4).
        if e & 0xFFFF_9C38 == 0xC004_0800 {
            return arrayMova(e, a, .mov, write: true, count: 2,
                             offset: UInt8(e & 0x7), zFirst: UInt8((e >> 6) & 0xF) &* 2)
        }
        if e & 0xFFFF_9C78 == 0xC004_0C00 {
            return arrayMova(e, a, .mov, write: true, count: 4,
                             offset: UInt8(e & 0x7), zFirst: UInt8((e >> 7) & 0x7) &* 4)
        }
        // Array READ (`mov`/`movaz {Zd}, za.d[Wv, off, vgxN]`): the offset is
        // bits[7:5] and the dest list `Zd` is bits[4:0].
        let readOffset = UInt8((e >> 5) & 0x7)
        switch e & 0xFFFF_9F01 {
        case 0xC006_0800: return arrayMova(e, a, .mov, write: false, count: 2, offset: readOffset, zFirst: UInt8(e & 0x1E))
        case 0xC006_0A00: return arrayMova(e, a, .movaz, write: false, count: 2, offset: readOffset, zFirst: UInt8(e & 0x1E))
        default: break
        }
        switch e & 0xFFFF_9F03 {
        case 0xC006_0C00: return arrayMova(e, a, .mov, write: false, count: 4, offset: readOffset, zFirst: UInt8(e & 0x1C))
        case 0xC006_0E00: return arrayMova(e, a, .movaz, write: false, count: 4, offset: readOffset, zFirst: UInt8(e & 0x1C))
        default: return nil
        }
    }

    @inline(__always)
    private static func arrayMova(
        _ e: UInt32, _ a: UInt64, _ mnemonic: Mnemonic, write: Bool, count: UInt8,
        offset: UInt8, zFirst: UInt8,
    ) -> DecodedDraft {
        let vg: ZAArrayVectorOperand.VectorGroup = count == 4 ? .vgx4 : .vgx2
        let array = SME2Decode.zaVector(e, .d, offset: offset, group: vg)
        let list = SME2Decode.group(zFirst, count, .d)
        let groupMask = SME2Decode.groupMask(zFirst, count)
        // MOVAZ zeroes the read ZA slices (a ZA write); MOVA read does not.
        let za = SME2Decode.zaWholeMask()
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: (write ? groupMask : .empty).union(SME2Decode.selectMask(SME2Decode.selectW8(e))),
            semanticWrites: write ? .empty : groupMask,
            category: .sme,
            operands: write ? [array, list] : [list, array],
            scalableReads: za,
            scalableWrites: write || mnemonic == .movaz ? za : .empty,
            // Partial only when this record writes ZA (write direction, or
            // MOVAZ zeroing); the MOVA-read direction fully writes its Z list.
            scalableEffect: write || mnemonic == .movaz
                ? [.readsStreamingMode, .partialWrite] : .readsStreamingMode,
        )
    }

    // MARK: - ZERO (ZA array)

    /// `ZERO za.d[Wv, off{:hi}{, vgxN}]` — the eight SME2p1 array forms
    /// (always `.d`, write-only).
    @_optimize(speed)
    private static func decodeZeroArray(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let (offset, offsetHigh, group): (UInt8, UInt8?, ZAArrayVectorOperand.VectorGroup)
        switch e & 0xFFFF_9FF8 {
        case 0xC00C_0000: // za.d[Wv, off3, vgx2]
            (offset, offsetHigh, group) = (UInt8(e & 0x7), nil, .vgx2)
        case 0xC00E_0000: // za.d[Wv, off3, vgx4]
            (offset, offsetHigh, group) = (UInt8(e & 0x7), nil, .vgx4)
        default:
            return decodeZeroArrayRanges(e, a)
        }
        return zeroArrayDraft(e, a, offset: offset, offsetHigh: offsetHigh, group: group)
    }

    @inline(__always)
    private static func decodeZeroArrayRanges(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // Range forms: off×span, with narrower group fields.
        if e & 0xFFFF_9FF8 == 0xC00C_8000 { // za.d[Wv, o1:o2]
            let lo = UInt8(e & 0x7) &* 2
            return zeroArrayDraft(e, a, offset: lo, offsetHigh: lo &+ 1, group: .none)
        }
        switch e & 0xFFFF_9FFC {
        case 0xC00D_0000: // vgx2, o1:o2
            let lo = UInt8(e & 0x3) &* 2
            return zeroArrayDraft(e, a, offset: lo, offsetHigh: lo &+ 1, group: .vgx2)
        case 0xC00D_8000: // vgx4, o1:o2
            let lo = UInt8(e & 0x3) &* 2
            return zeroArrayDraft(e, a, offset: lo, offsetHigh: lo &+ 1, group: .vgx4)
        case 0xC00E_8000: // o1:o4 (whole)
            let lo = UInt8(e & 0x3) &* 4
            return zeroArrayDraft(e, a, offset: lo, offsetHigh: lo &+ 3, group: .none)
        default: break
        }
        switch e & 0xFFFF_9FFE {
        case 0xC00F_0000: // vgx2, o1:o4
            let lo = UInt8(e & 0x1) &* 4
            return zeroArrayDraft(e, a, offset: lo, offsetHigh: lo &+ 3, group: .vgx2)
        case 0xC00F_8000: // vgx4, o1:o4
            let lo = UInt8(e & 0x1) &* 4
            return zeroArrayDraft(e, a, offset: lo, offsetHigh: lo &+ 3, group: .vgx4)
        default: return SME2Decode.undefined(e, a)
        }
    }

    @inline(__always)
    private static func zeroArrayDraft(
        _ e: UInt32, _ a: UInt64, offset: UInt8, offsetHigh: UInt8?,
        group: ZAArrayVectorOperand.VectorGroup,
    ) -> DecodedDraft {
        DecodedDraft(
            address: a, encoding: e, mnemonic: .zero,
            semanticReads: SME2Decode.selectMask(SME2Decode.selectW8(e)),
            category: .sme,
            operands: [SME2Decode.zaVector(
                e, .d, offset: offset, offsetHigh: offsetHigh, group: group,
            )],
            scalableWrites: SME2Decode.zaWholeMask(),
            // ZERO za-array is streaming-gated (HasSME2p1, not IsNonStreamingSafe
            // like the ZT0 ZERO) and writes a dynamic ZA slice range.
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    // MARK: - ZERO / MOVT (ZT0)

    /// `ZERO { zt0 }`.
    @inline(__always)
    private static func decodeZeroZT0(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        guard e == 0xC048_0001 else { return SME2Decode.undefined(e, a) }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .zero, category: .sme,
            operands: [.zt0(elementIndex: nil)],
            scalableWrites: SME2Decode.zt0Mask(),
        )
    }

    /// `MOVT Xt, zt0[off]` / `MOVT zt0[off], Xt` (scalar, off = field × 8,
    /// 0-56) and the LUTv2 vector form `MOVT zt0{[off, mul vl]}, Zt`. The masks
    /// below fix the full opcode (`bits[9:5]=0b11111` scalar, `Zt` for vector)
    /// so the region's holes stay UNDEFINED.
    @inline(__always)
    private static func decodeMovt(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let rt = UInt8(e & 0x1F)
        let offset = UInt8((e >> 12) & 0x7) &* 8
        if e & 0xFFFF_8FE0 == 0xC04C_03E0 { // movt Xt, zt0[off]
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .movt,
                semanticWrites: SME2Decode.dataMask(rt), category: .sme,
                operands: [gpr64(rt), .zt0(elementIndex: offset)],
                scalableReads: SME2Decode.zt0Mask(),
                scalableEffect: .readsStreamingMode, // MOVT is streaming-gated (HasSME2)
            )
        }
        if e & 0xFFFF_8FE0 == 0xC04E_03E0 { // movt zt0[off], Xt
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .movt,
                semanticReads: SME2Decode.dataMask(rt), category: .sme,
                operands: [.zt0(elementIndex: offset), gpr64(rt)],
                scalableWrites: SME2Decode.zt0Mask(),
                scalableEffect: [.readsStreamingMode, .partialWrite], // writes an 8-byte ZT0 slice
            )
        }
        if e & 0xFFFF_CFE0 == 0xC04F_03E0 { // movt zt0{[off, mul vl]}, Zt (LUTv2)
            let zt = UInt8(e & 0x1F)
            let off2 = UInt8((e >> 12) & 0x3)
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .movt,
                semanticReads: SME2Decode.vecMask(zt), category: .sme,
                operands: [.zt0(elementIndex: off2 == 0 ? nil : off2),
                           .scalableVector(ScalableVectorRef(registerIndex: zt))],
                scalableWrites: SME2Decode.zt0Mask(),
                scalableEffect: [.readsStreamingMode, .partialWrite],
            )
        }
        return SME2Decode.undefined(e, a)
    }

    @inline(__always)
    private static func gpr64(_ index: UInt8) -> Operand {
        .register(index == 31 ? .xzr() : .x(index))
    }
}
