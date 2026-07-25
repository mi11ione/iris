// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// SME MOVA / ZERO / ADDHA / ADDVA decoder (cells 110|0|x).
// MOVA (rendered `mov`, the always-preferred alias) moves a Z vector to a ZA
// tile slice (insert) or a tile slice to a Z vector (extract), both predicated
// merging. ZERO zeroes a set of ZA tiles selected by an 8-bit mask. ADDHA /
// ADDVA accumulate a predicated horizontal / vertical sum into a ZA tile.
// The dense SME2 residue sharing these cells (multi-vector MOVA/MOVAZ, ZERO_MXI,
// MOVT, LUTI) matches no block here and falls through to UNDEFINED.

extension SMECoreDecode {
    /// Decode an SME move / zero / accumulate word.
    @inline(__always)
    static func decodeMoveZero(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        if e & 0xFFFF_FF00 == 0xC008_0000 { return decodeZero(e, a) }
        let addS = e & 0xFFFF_001C
        if addS == 0xC090_0000 { return decodeAddHV(e, a, .s, .addha) }
        if addS == 0xC091_0000 { return decodeAddHV(e, a, .s, .addva) }
        let addD = e & 0xFFFF_0018
        if addD == 0xC0D0_0000 { return decodeAddHV(e, a, .d, .addha) }
        if addD == 0xC0D1_0000 { return decodeAddHV(e, a, .d, .addva) }
        if let element = movaInsertElement(e) { return decodeMovaInsert(e, a, element) }
        // The core claim for these cells (`smeIsCoreMoveZero`) admits exactly
        // the five blocks tested here, and the four above are ruled out, so
        // what remains is a MOVA extract — no UNDEFINED fallthrough is
        // reachable. (The dense SME2 residue sharing the cells never arrives:
        // it fails the core claim and decodes in SME2.)
        return decodeMovaExtract(e, a, movaExtractElement(e))
    }

    // MARK: - MOVA (rendered `mov`)

    /// The tile element of a MOVA insert (vector → tile) encoding, or `nil`.
    @inline(__always)
    static func movaInsertElement(_ e: UInt32) -> ScalarSize? {
        switch e & 0xFFFF_0010 {
        case 0xC000_0000: .b
        case 0xC040_0000: .h
        case 0xC080_0000: .s
        case 0xC0C0_0000: .d
        case 0xC0C1_0000: .q
        default: nil
        }
    }

    /// The tile element of a MOVA extract (tile → vector) encoding. Total over
    /// the extract block the core claim admits — the caller has already ruled
    /// out the other four blocks in these cells, so one of these patterns
    /// holds. The mask fixes bit9=0, so the SME2p1 MOVAZ twin (bit9=1) is
    /// excluded (it decodes in SME2).
    @inline(__always)
    static func movaExtractElement(_ e: UInt32) -> ScalarSize {
        switch e & 0xFFFF_0200 {
        case 0xC002_0000: .b
        case 0xC042_0000: .h
        case 0xC082_0000: .s
        case 0xC0C2_0000: .d
        default: .q // 0xC0C3_0000 — the last pattern in the claim.
        }
    }

    /// MOVA insert — `mov <ZAd><h|v>.<T>[Wv, off], Pg/m, Zn.<T>`. Reads `Zn`
    /// and the select `Wv`; reads+writes the tile (merging).
    @inline(__always)
    static func decodeMovaInsert(_ e: UInt32, _ a: UInt64, _ element: ScalarSize) -> DecodedDraft {
        let slice = tileSlice(e, element, UInt8(e & 0xF))
        let znIndex = zn(e), pg = pn3(e)
        let tileMask = slice.zaMask
        let operands: [Operand] = [
            .zaTileSlice(slice),
            govern(pg, .merging),
            vec(znIndex, element),
        ]
        let reads = vecMask(znIndex).union(gprMask(12 &+ rv(e)))
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .mov,
            semanticReads: reads,
            category: .sme,
            operands: operands,
            scalableReads: predRead(pg).inserting(tileMask),
            scalableWrites: ScalableRegisterSet.empty.inserting(tileMask),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    /// MOVA extract — `mov Zd.<T>, Pg/m, <ZAn><h|v>.<T>[Wv, off]`. Reads the
    /// tile, the select `Wv`, and `Zd` (merging preserves inactive lanes);
    /// writes `Zd` (partial).
    @inline(__always)
    static func decodeMovaExtract(_ e: UInt32, _ a: UInt64, _ element: ScalarSize) -> DecodedDraft {
        let slice = tileSlice(e, element, UInt8((e >> 5) & 0xF))
        let zdIndex = zd(e), pg = pn3(e)
        let tileMask = slice.zaMask
        let operands: [Operand] = [
            vec(zdIndex, element),
            govern(pg, .merging),
            .zaTileSlice(slice),
        ]
        let reads = vecMask(zdIndex).union(gprMask(12 &+ rv(e)))
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .mov,
            semanticReads: reads,
            semanticWrites: vecMask(zdIndex),
            category: .sme,
            operands: operands,
            scalableReads: predRead(pg).inserting(tileMask),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    // MARK: - ZERO

    /// Decode `ZERO { <tile-list> }` — the imm8 mask selects which `ZA` tiles
    /// zero; the operands mirror the rendered list. The write is
    /// exact (not partial): imm8 replicated into a 16-bit residue mask.
    @inline(__always)
    static func decodeZero(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let imm8 = UInt8(e & 0xFF)
        let operands = zeroTileList(imm8).map { Operand.zaTile(index: $0.index, element: $0.element) }
        let mask = ZATileMask(bits: UInt16(imm8) | (UInt16(imm8) << 8))
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .zero,
            category: .sme,
            operands: operands,
            scalableWrites: ScalableRegisterSet.empty.inserting(mask),
        )
    }

    /// The `ZERO` tile list for an imm8 mask: whole `za` (0xFF),
    /// the two `.h` aliases (0x55 / 0xAA), an ascending `.s` list for any other
    /// equal-nibble mask, else an ascending `.d` list per set bit. Empty for 0.
    @inline(__always)
    static func zeroTileList(_ imm8: UInt8) -> [(index: UInt8, element: ScalarSize?)] {
        if imm8 == 0 { return [] }
        if imm8 == 0xFF { return [(0, nil)] } // whole za
        if imm8 == 0x55 { return [(0, .h)] }
        if imm8 == 0xAA { return [(1, .h)] }
        var list: [(index: UInt8, element: ScalarSize?)] = []
        if (imm8 >> 4) == (imm8 & 0xF) { // equal-nibble → .s tiles
            let lo = imm8 & 0xF
            for j: UInt8 in 0 ..< 4 where (lo >> j) & 1 == 1 {
                list.append((j, .s))
            }
            return list
        }
        for i: UInt8 in 0 ..< 8 where (imm8 >> i) & 1 == 1 {
            list.append((i, .d))
        }
        return list
    }

    // MARK: - ADDHA / ADDVA

    /// Decode `ADDHA` / `ADDVA <ZAda>.<T>, Pn/m, Pm/m, Zn.<T>` — a predicated
    /// horizontal / vertical accumulate into a `ZA` tile.
    @inline(__always)
    static func decodeAddHV(_ e: UInt32, _ a: UInt64, _ element: ScalarSize, _ mnemonic: Mnemonic) -> DecodedDraft {
        let tileIndex = element == .s ? UInt8(e & 0x3) : UInt8(e & 0x7)
        let znIndex = zn(e), pn = pn3(e), pm = pm3(e)
        let tileMask = ZATileMask(tile: tileIndex, element: element)
        let operands: [Operand] = [
            .zaTile(index: tileIndex, element: element),
            govern(pn, .merging),
            govern(pm, .merging),
            vec(znIndex, element),
        ]
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(znIndex),
            category: .sme,
            operands: operands,
            scalableReads: predRead(pn).union(predRead(pm)).inserting(tileMask),
            scalableWrites: ScalableRegisterSet.empty.inserting(tileMask),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }
}
