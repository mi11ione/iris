// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// the cell-110|1|x (top byte 0xC1) dispatcher and the
// ZA-accumulating multi-vector families. bits[15:13] partition the cell
// 000 and 100 are the ZA-array accumulators (add/sub, dots,
// fmla/fmls, the widening L and quad-widening LL mla families, and vertical
// dots), which this file owns; 101/110/111 (destructive elementwise, clamp/
// narrow/permute, convert/fmul/frint/unpk) and the SEL exception in the 100
// group route to `SME2VectorOpsDecode`. Every ZA-array access reads+writes
// the whole-ZA mask (dynamic row selection) and the W8+Rv select register.
// The accumulate/single-Zm/multi-Zm/indexed shapes are all decoded from the
// generated (mask,value) table below (transcribed from the investigation
// tblgen records, tightest-mask-first), the indexed forms via the per-element
// index-field kinds in `accumIndex`.

/// SME2 0xC1 dispatcher + ZA-accumulate decoders.
enum SME2ArithmeticDecode {
    /// Decode a cell-`110|1|x` word (top byte 0xC1). The ZA-array accumulators
    /// hold `Rv` in bits[14:13], so bits[15:13] is not a stable discriminator
    /// for them — the accumulate table (whose masks fix the full opcode) is
    /// tried first, and the non-ZA remainder ({Zd}-targeting) then routes by
    /// bits[15:13] (100 SEL, 101 destructive, 110 clamp/narrow/permute, 111
    /// convert/fmul/frint/unpk).
    @_optimize(speed)
    static func decode(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        if let spec = accumulateSpec(e) {
            return buildAccumulate(e, a, spec)
        }
        // The accumulate table above already claimed every ZA-targeting form
        // (including the indexed ones); the remainder is {Zd}-targeting, routed
        // by bits[15:13], with SEL peeled out of the 100 group.
        return switch (e >> 13) & 0x7 {
        case 0b100:
            e & 0xFF21_E021 == 0xC120_8000 || e & 0xFF23_E063 == 0xC121_8000
                ? SME2VectorOpsDecode.decodeSel(e, a)
                : SME2Decode.undefined(e, a) // 100-group hole
        case 0b101: SME2VectorOpsDecode.decodeDestructive(e, a)
        case 0b110: SME2VectorOpsDecode.decodeClampNarrowPermute(e, a)
        case 0b111: SME2VectorOpsDecode.decodeConvertMisc(e, a)
        default: SME2Decode.undefined(e, a) // 000-group hole (accumulates matched above)
        }
    }

    /// The shape of a ZA-accumulate record's sources.
    private enum AccumShape { case accum, single, multi, idx }

    /// The `Zm` element-index bit layout of an indexed ZA-accumulate form.
    private enum IndexKind {
        case i1, i2, i2vt, i3s, i3L1, i3L2, i3LLd2, i4LL1, i4LL2, i4f8L1, i4f8L2
    }

    /// A decoded ZA-accumulate record identity — mnemonic, vector-group
    /// width, source shape, tile/source element sizes, offset tier (1 =
    /// single slot, 2 = widening `L` range, 4 = quad-widening `LL` range),
    /// and (for indexed forms) the `Zm` index layout.
    private struct AccumSpec {
        let mnemonic: Mnemonic
        let vg: UInt8
        let shape: AccumShape
        let tile: ScalarSize
        let src: ScalarSize
        let tier: UInt8
        let index: IndexKind
        init(
            // `index` is meaningful only for indexed (`.idx`) shapes; other
            // shapes take the placeholder default, which is never read.
            _ mnemonic: Mnemonic, vg: UInt8, shape: AccumShape, tile: ScalarSize,
            src: ScalarSize, tier: UInt8, index: IndexKind = .i1,
        ) {
            self.mnemonic = mnemonic; self.vg = vg; self.shape = shape
            self.tile = tile; self.src = src; self.tier = tier; self.index = index
        }
    }

    /// Build the record for a matched non-indexed ZA-accumulate spec.
    @inline(__always)
    private static func buildAccumulate(_ e: UInt32, _ a: UInt64, _ spec: AccumSpec) -> DecodedDraft {
        let (offset, offsetHigh) = accumOffset(e, spec)
        let vgGroup: ZAArrayVectorOperand.VectorGroup = spec.vg == 1 ? .none : (spec.vg == 4 ? .vgx4 : .vgx2)
        let dest = SME2Decode.zaVector(e, spec.tile, offset: offset, offsetHigh: offsetHigh, group: vgGroup)

        var operands: [Operand] = [dest]
        var sourceReads = RegisterSet.empty

        switch spec.shape {
        case .accum:
            let zn = znGroupFirst(e, spec.vg)
            operands.append(SME2Decode.group(zn, spec.vg, spec.src))
            sourceReads = SME2Decode.groupMask(zn, spec.vg)
        case .single where spec.vg == 1:
            // Single-vector widening form: `za.<T>[Wv, lo:hi], Zn.<Ts>, Zm.<Ts>`.
            let zn = UInt8((e >> 5) & 0x1F)
            let zm = SME2Decode.zm4(e)
            operands.append(SME2Decode.vec(zn, spec.src))
            operands.append(SME2Decode.vec(zm, spec.src))
            sourceReads = SME2Decode.vecMask(zn).union(SME2Decode.vecMask(zm))
        case .single:
            // {Zn} (5-bit wrapping group) then a single broadcast Zm (z0-z15).
            let zn = UInt8((e >> 5) & 0x1F)
            let zm = SME2Decode.zm4(e)
            operands.append(SME2Decode.group(zn, spec.vg, spec.src))
            operands.append(SME2Decode.vec(zm, spec.src))
            sourceReads = SME2Decode.groupMask(zn, spec.vg).union(SME2Decode.vecMask(zm))
        case .multi:
            let zn = znGroupFirst(e, spec.vg)
            let zm = zmGroupFirst(e, spec.vg)
            operands.append(SME2Decode.group(zn, spec.vg, spec.src))
            operands.append(SME2Decode.group(zm, spec.vg, spec.src))
            sourceReads = SME2Decode.groupMask(zn, spec.vg).union(SME2Decode.groupMask(zm, spec.vg))
        case .idx where spec.vg == 1:
            // Single-vector indexed widening: `za[...], Zn.<Ts>, Zm.<Ts>[i]`.
            let zn = UInt8((e >> 5) & 0x1F)
            let zm = SME2Decode.zm4(e)
            operands.append(SME2Decode.vec(zn, spec.src))
            operands.append(SME2Decode.vec(zm, spec.src, index: accumIndex(e, spec.index)))
            sourceReads = SME2Decode.vecMask(zn).union(SME2Decode.vecMask(zm))
        case .idx:
            // FVDOTB/FVDOTT have vgx4 ZA semantics but a 2-register Zn list.
            let znCount: UInt8 = spec.index == .i2vt ? 2 : spec.vg
            let zn = znGroupFirst(e, znCount)
            let zm = SME2Decode.zm4(e)
            operands.append(SME2Decode.group(zn, znCount, spec.src))
            operands.append(SME2Decode.vec(zm, spec.src, index: accumIndex(e, spec.index)))
            sourceReads = SME2Decode.groupMask(zn, znCount).union(SME2Decode.vecMask(zm))
        }
        return SME2Decode.zaAccumulate(e, a, spec.mnemonic, operands: operands, sourceReads: sourceReads)
    }

    /// The ZA slice offset (and range high end) for an accumulate record. The
    /// offset field is the low bits below `Zn`; single-slot forms print the
    /// value plain, `L`/`LL` forms print an `off*tier : off*tier+tier-1` range.
    @inline(__always)
    private static func accumOffset(_ e: UInt32, _ spec: AccumSpec) -> (UInt8, UInt8?) {
        let width: UInt32 = spec.tier == 1 ? 3 : (spec.vg == 1 ? (spec.tier == 2 ? 3 : 2) : (spec.tier == 2 ? 2 : 1))
        let field = UInt8(e & ((1 << width) - 1))
        let lo = field &* spec.tier
        return spec.tier == 1 ? (lo, nil) : (lo, lo &+ spec.tier &- 1)
    }

    /// The first register of a `Zn`/`Zm` even/quad group (`field*2` for a pair
    /// at bits[9:6], `field*4` for a quad at bits[9:7]).
    @inline(__always)
    private static func znGroupFirst(_ e: UInt32, _ vg: UInt8) -> UInt8 {
        vg == 4 ? UInt8((e >> 7) & 0x7) &* 4 : UInt8((e >> 6) & 0xF) &* 2
    }

    /// The first register of a multi-`Zm` group (bits[20:17] pair / [20:18] quad).
    @inline(__always)
    private static func zmGroupFirst(_ e: UInt32, _ vg: UInt8) -> UInt8 {
        vg == 4 ? UInt8((e >> 18) & 0x7) &* 4 : UInt8((e >> 17) & 0xF) &* 2
    }

    /// The `Zm` element index for an indexed accumulate form, per its layout.
    ///
    /// The arms are pinned to `UInt32` and narrowed once at the end. Left
    /// as a switch of bare `UInt8(…)` conversions, the whole expression is
    /// one constraint system over every integer type at once, which the
    /// type checker solves slowly enough to time out on a cold CI host.
    @inline(__always)
    private static func accumIndex(_ e: UInt32, _ kind: IndexKind) -> UInt8 {
        let bits: UInt32 = switch kind {
        case .i1: (e >> 10) & 0x1
        case .i2: (e >> 10) & 0x3
        case .i2vt: ((e >> 10) & 0x1) << 1 | ((e >> 3) & 0x1)
        case .i3s: ((e >> 10) & 0x3) << 1 | ((e >> 3) & 0x1)
        case .i3L1: ((e >> 15) & 0x1) << 2 | ((e >> 10) & 0x3)
        case .i3L2: ((e >> 10) & 0x3) << 1 | ((e >> 2) & 0x1)
        case .i3LLd2: ((e >> 10) & 0x1) << 2 | ((e >> 1) & 0x3)
        case .i4LL1: ((e >> 15) & 0x1) << 3 | ((e >> 10) & 0x7)
        case .i4LL2: ((e >> 10) & 0x3) << 2 | ((e >> 1) & 0x3)
        case .i4f8L1: ((e >> 15) & 0x1) << 3 | ((e >> 10) & 0x3) << 1 | ((e >> 3) & 0x1)
        case .i4f8L2: ((e >> 10) & 0x3) << 2 | ((e >> 2) & 0x3)
        }
        return UInt8(bits)
    }

    /// Look up a ZA-accumulate record identity by its (mask,value),
    /// tightest mask first. Generated from the investigation tblgen records.
    @inline(__always)
    private static func accumulateSpec(_ e: UInt32) -> AccumSpec? {
        switch e & 0xFFFF_9C78 {
        case 0xC1A1_1C00: return AccumSpec(.fadd, vg: 4, shape: .accum, tile: .s, src: .s, tier: 1)
        case 0xC1A1_1C08: return AccumSpec(.fsub, vg: 4, shape: .accum, tile: .s, src: .s, tier: 1)
        case 0xC1A1_1C10: return AccumSpec(.add, vg: 4, shape: .accum, tile: .s, src: .s, tier: 1)
        case 0xC1A1_1C18: return AccumSpec(.sub, vg: 4, shape: .accum, tile: .s, src: .s, tier: 1)
        case 0xC1A5_1C00: return AccumSpec(.fadd, vg: 4, shape: .accum, tile: .h, src: .h, tier: 1)
        case 0xC1A5_1C08: return AccumSpec(.fsub, vg: 4, shape: .accum, tile: .h, src: .h, tier: 1)
        case 0xC1E1_1C00: return AccumSpec(.fadd, vg: 4, shape: .accum, tile: .d, src: .d, tier: 1)
        case 0xC1E1_1C08: return AccumSpec(.fsub, vg: 4, shape: .accum, tile: .d, src: .d, tier: 1)
        case 0xC1E1_1C10: return AccumSpec(.add, vg: 4, shape: .accum, tile: .d, src: .d, tier: 1)
        case 0xC1E1_1C18: return AccumSpec(.sub, vg: 4, shape: .accum, tile: .d, src: .d, tier: 1)
        case 0xC1E5_1C00: return AccumSpec(.bfadd, vg: 4, shape: .accum, tile: .h, src: .h, tier: 1)
        case 0xC1E5_1C08: return AccumSpec(.bfsub, vg: 4, shape: .accum, tile: .h, src: .h, tier: 1)
        default: break
        }
        switch e & 0xFFE3_9C7E {
        case 0xC1A1_0000: return AccumSpec(.smlall, vg: 4, shape: .multi, tile: .s, src: .b, tier: 4)
        case 0xC1A1_0004: return AccumSpec(.usmlall, vg: 4, shape: .multi, tile: .s, src: .b, tier: 4)
        case 0xC1A1_0008: return AccumSpec(.smlsll, vg: 4, shape: .multi, tile: .s, src: .b, tier: 4)
        case 0xC1A1_0010: return AccumSpec(.umlall, vg: 4, shape: .multi, tile: .s, src: .b, tier: 4)
        case 0xC1A1_0018: return AccumSpec(.umlsll, vg: 4, shape: .multi, tile: .s, src: .b, tier: 4)
        case 0xC1A1_0020: return AccumSpec(.fmlall, vg: 4, shape: .multi, tile: .s, src: .b, tier: 4)
        case 0xC1E1_0000: return AccumSpec(.smlall, vg: 4, shape: .multi, tile: .d, src: .h, tier: 4)
        case 0xC1E1_0008: return AccumSpec(.smlsll, vg: 4, shape: .multi, tile: .d, src: .h, tier: 4)
        case 0xC1E1_0010: return AccumSpec(.umlall, vg: 4, shape: .multi, tile: .d, src: .h, tier: 4)
        case 0xC1E1_0018: return AccumSpec(.umlsll, vg: 4, shape: .multi, tile: .d, src: .h, tier: 4)
        default: break
        }
        switch e & 0xFFFF_9C38 {
        case 0xC1A0_1C00: return AccumSpec(.fadd, vg: 2, shape: .accum, tile: .s, src: .s, tier: 1)
        case 0xC1A0_1C08: return AccumSpec(.fsub, vg: 2, shape: .accum, tile: .s, src: .s, tier: 1)
        case 0xC1A0_1C10: return AccumSpec(.add, vg: 2, shape: .accum, tile: .s, src: .s, tier: 1)
        case 0xC1A0_1C18: return AccumSpec(.sub, vg: 2, shape: .accum, tile: .s, src: .s, tier: 1)
        case 0xC1A4_1C00: return AccumSpec(.fadd, vg: 2, shape: .accum, tile: .h, src: .h, tier: 1)
        case 0xC1A4_1C08: return AccumSpec(.fsub, vg: 2, shape: .accum, tile: .h, src: .h, tier: 1)
        case 0xC1E0_1C00: return AccumSpec(.fadd, vg: 2, shape: .accum, tile: .d, src: .d, tier: 1)
        case 0xC1E0_1C08: return AccumSpec(.fsub, vg: 2, shape: .accum, tile: .d, src: .d, tier: 1)
        case 0xC1E0_1C10: return AccumSpec(.add, vg: 2, shape: .accum, tile: .d, src: .d, tier: 1)
        case 0xC1E0_1C18: return AccumSpec(.sub, vg: 2, shape: .accum, tile: .d, src: .d, tier: 1)
        case 0xC1E4_1C00: return AccumSpec(.bfadd, vg: 2, shape: .accum, tile: .h, src: .h, tier: 1)
        case 0xC1E4_1C08: return AccumSpec(.bfsub, vg: 2, shape: .accum, tile: .h, src: .h, tier: 1)
        default: break
        }
        switch e & 0xFFE3_9C7C {
        case 0xC1A1_0800: return AccumSpec(.fmlal, vg: 4, shape: .multi, tile: .s, src: .h, tier: 2)
        case 0xC1A1_0808: return AccumSpec(.fmlsl, vg: 4, shape: .multi, tile: .s, src: .h, tier: 2)
        case 0xC1A1_0810: return AccumSpec(.bfmlal, vg: 4, shape: .multi, tile: .s, src: .h, tier: 2)
        case 0xC1A1_0818: return AccumSpec(.bfmlsl, vg: 4, shape: .multi, tile: .s, src: .h, tier: 2)
        case 0xC1A1_0820: return AccumSpec(.fmlal, vg: 4, shape: .multi, tile: .h, src: .b, tier: 2)
        case 0xC1E1_0800: return AccumSpec(.smlal, vg: 4, shape: .multi, tile: .s, src: .h, tier: 2)
        case 0xC1E1_0808: return AccumSpec(.smlsl, vg: 4, shape: .multi, tile: .s, src: .h, tier: 2)
        case 0xC1E1_0810: return AccumSpec(.umlal, vg: 4, shape: .multi, tile: .s, src: .h, tier: 2)
        case 0xC1E1_0818: return AccumSpec(.umlsl, vg: 4, shape: .multi, tile: .s, src: .h, tier: 2)
        default: break
        }
        switch e & 0xFFE1_9C3E {
        case 0xC1A0_0000: return AccumSpec(.smlall, vg: 2, shape: .multi, tile: .s, src: .b, tier: 4)
        case 0xC1A0_0004: return AccumSpec(.usmlall, vg: 2, shape: .multi, tile: .s, src: .b, tier: 4)
        case 0xC1A0_0008: return AccumSpec(.smlsll, vg: 2, shape: .multi, tile: .s, src: .b, tier: 4)
        case 0xC1A0_0010: return AccumSpec(.umlall, vg: 2, shape: .multi, tile: .s, src: .b, tier: 4)
        case 0xC1A0_0018: return AccumSpec(.umlsll, vg: 2, shape: .multi, tile: .s, src: .b, tier: 4)
        case 0xC1A0_0020: return AccumSpec(.fmlall, vg: 2, shape: .multi, tile: .s, src: .b, tier: 4)
        case 0xC1E0_0000: return AccumSpec(.smlall, vg: 2, shape: .multi, tile: .d, src: .h, tier: 4)
        case 0xC1E0_0008: return AccumSpec(.smlsll, vg: 2, shape: .multi, tile: .d, src: .h, tier: 4)
        case 0xC1E0_0010: return AccumSpec(.umlall, vg: 2, shape: .multi, tile: .d, src: .h, tier: 4)
        case 0xC1E0_0018: return AccumSpec(.umlsll, vg: 2, shape: .multi, tile: .d, src: .h, tier: 4)
        default: break
        }
        switch e & 0xFFE3_9C78 {
        case 0xC1A1_1000: return AccumSpec(.fdot, vg: 4, shape: .multi, tile: .s, src: .h, tier: 1)
        case 0xC1A1_1008: return AccumSpec(.fmla, vg: 4, shape: .multi, tile: .h, src: .h, tier: 1)
        case 0xC1A1_1010: return AccumSpec(.bfdot, vg: 4, shape: .multi, tile: .s, src: .h, tier: 1)
        case 0xC1A1_1018: return AccumSpec(.fmls, vg: 4, shape: .multi, tile: .h, src: .h, tier: 1)
        case 0xC1A1_1020: return AccumSpec(.fdot, vg: 4, shape: .multi, tile: .h, src: .b, tier: 1)
        case 0xC1A1_1030: return AccumSpec(.fdot, vg: 4, shape: .multi, tile: .s, src: .b, tier: 1)
        case 0xC1A1_1400: return AccumSpec(.sdot, vg: 4, shape: .multi, tile: .s, src: .b, tier: 1)
        case 0xC1A1_1408: return AccumSpec(.usdot, vg: 4, shape: .multi, tile: .s, src: .b, tier: 1)
        case 0xC1A1_1410: return AccumSpec(.udot, vg: 4, shape: .multi, tile: .s, src: .b, tier: 1)
        case 0xC1A1_1800: return AccumSpec(.fmla, vg: 4, shape: .multi, tile: .s, src: .s, tier: 1)
        case 0xC1A1_1808: return AccumSpec(.fmls, vg: 4, shape: .multi, tile: .s, src: .s, tier: 1)
        case 0xC1A1_1810: return AccumSpec(.add, vg: 4, shape: .multi, tile: .s, src: .s, tier: 1)
        case 0xC1A1_1818: return AccumSpec(.sub, vg: 4, shape: .multi, tile: .s, src: .s, tier: 1)
        case 0xC1E1_1008: return AccumSpec(.bfmla, vg: 4, shape: .multi, tile: .h, src: .h, tier: 1)
        case 0xC1E1_1018: return AccumSpec(.bfmls, vg: 4, shape: .multi, tile: .h, src: .h, tier: 1)
        case 0xC1E1_1400: return AccumSpec(.sdot, vg: 4, shape: .multi, tile: .d, src: .h, tier: 1)
        case 0xC1E1_1408: return AccumSpec(.sdot, vg: 4, shape: .multi, tile: .s, src: .h, tier: 1)
        case 0xC1E1_1410: return AccumSpec(.udot, vg: 4, shape: .multi, tile: .d, src: .h, tier: 1)
        case 0xC1E1_1418: return AccumSpec(.udot, vg: 4, shape: .multi, tile: .s, src: .h, tier: 1)
        case 0xC1E1_1800: return AccumSpec(.fmla, vg: 4, shape: .multi, tile: .d, src: .d, tier: 1)
        case 0xC1E1_1808: return AccumSpec(.fmls, vg: 4, shape: .multi, tile: .d, src: .d, tier: 1)
        case 0xC1E1_1810: return AccumSpec(.add, vg: 4, shape: .multi, tile: .d, src: .d, tier: 1)
        case 0xC1E1_1818: return AccumSpec(.sub, vg: 4, shape: .multi, tile: .d, src: .d, tier: 1)
        default: break
        }
        switch e & 0xFFE1_9C3C {
        case 0xC1A0_0800: return AccumSpec(.fmlal, vg: 2, shape: .multi, tile: .s, src: .h, tier: 2)
        case 0xC1A0_0808: return AccumSpec(.fmlsl, vg: 2, shape: .multi, tile: .s, src: .h, tier: 2)
        case 0xC1A0_0810: return AccumSpec(.bfmlal, vg: 2, shape: .multi, tile: .s, src: .h, tier: 2)
        case 0xC1A0_0818: return AccumSpec(.bfmlsl, vg: 2, shape: .multi, tile: .s, src: .h, tier: 2)
        case 0xC1A0_0820: return AccumSpec(.fmlal, vg: 2, shape: .multi, tile: .h, src: .b, tier: 2)
        case 0xC1E0_0800: return AccumSpec(.smlal, vg: 2, shape: .multi, tile: .s, src: .h, tier: 2)
        case 0xC1E0_0808: return AccumSpec(.smlsl, vg: 2, shape: .multi, tile: .s, src: .h, tier: 2)
        case 0xC1E0_0810: return AccumSpec(.umlal, vg: 2, shape: .multi, tile: .s, src: .h, tier: 2)
        case 0xC1E0_0818: return AccumSpec(.umlsl, vg: 2, shape: .multi, tile: .s, src: .h, tier: 2)
        default: break
        }
        switch e & 0xFFF0_9C1E {
        case 0xC120_0000: return AccumSpec(.smlall, vg: 2, shape: .single, tile: .s, src: .b, tier: 4)
        case 0xC120_0002: return AccumSpec(.fmlall, vg: 2, shape: .single, tile: .s, src: .b, tier: 4)
        case 0xC120_0004: return AccumSpec(.usmlall, vg: 2, shape: .single, tile: .s, src: .b, tier: 4)
        case 0xC120_0008: return AccumSpec(.smlsll, vg: 2, shape: .single, tile: .s, src: .b, tier: 4)
        case 0xC120_0010: return AccumSpec(.umlall, vg: 2, shape: .single, tile: .s, src: .b, tier: 4)
        case 0xC120_0014: return AccumSpec(.sumlall, vg: 2, shape: .single, tile: .s, src: .b, tier: 4)
        case 0xC120_0018: return AccumSpec(.umlsll, vg: 2, shape: .single, tile: .s, src: .b, tier: 4)
        case 0xC130_0000: return AccumSpec(.smlall, vg: 4, shape: .single, tile: .s, src: .b, tier: 4)
        case 0xC130_0002: return AccumSpec(.fmlall, vg: 4, shape: .single, tile: .s, src: .b, tier: 4)
        case 0xC130_0004: return AccumSpec(.usmlall, vg: 4, shape: .single, tile: .s, src: .b, tier: 4)
        case 0xC130_0008: return AccumSpec(.smlsll, vg: 4, shape: .single, tile: .s, src: .b, tier: 4)
        case 0xC130_0010: return AccumSpec(.umlall, vg: 4, shape: .single, tile: .s, src: .b, tier: 4)
        case 0xC130_0014: return AccumSpec(.sumlall, vg: 4, shape: .single, tile: .s, src: .b, tier: 4)
        case 0xC130_0018: return AccumSpec(.umlsll, vg: 4, shape: .single, tile: .s, src: .b, tier: 4)
        case 0xC160_0000: return AccumSpec(.smlall, vg: 2, shape: .single, tile: .d, src: .h, tier: 4)
        case 0xC160_0008: return AccumSpec(.smlsll, vg: 2, shape: .single, tile: .d, src: .h, tier: 4)
        case 0xC160_0010: return AccumSpec(.umlall, vg: 2, shape: .single, tile: .d, src: .h, tier: 4)
        case 0xC160_0018: return AccumSpec(.umlsll, vg: 2, shape: .single, tile: .d, src: .h, tier: 4)
        case 0xC170_0000: return AccumSpec(.smlall, vg: 4, shape: .single, tile: .d, src: .h, tier: 4)
        case 0xC170_0008: return AccumSpec(.smlsll, vg: 4, shape: .single, tile: .d, src: .h, tier: 4)
        case 0xC170_0010: return AccumSpec(.umlall, vg: 4, shape: .single, tile: .d, src: .h, tier: 4)
        case 0xC170_0018: return AccumSpec(.umlsll, vg: 4, shape: .single, tile: .d, src: .h, tier: 4)
        default: break
        }
        switch e & 0xFFE1_9C38 {
        case 0xC1A0_1000: return AccumSpec(.fdot, vg: 2, shape: .multi, tile: .s, src: .h, tier: 1)
        case 0xC1A0_1008: return AccumSpec(.fmla, vg: 2, shape: .multi, tile: .h, src: .h, tier: 1)
        case 0xC1A0_1010: return AccumSpec(.bfdot, vg: 2, shape: .multi, tile: .s, src: .h, tier: 1)
        case 0xC1A0_1018: return AccumSpec(.fmls, vg: 2, shape: .multi, tile: .h, src: .h, tier: 1)
        case 0xC1A0_1020: return AccumSpec(.fdot, vg: 2, shape: .multi, tile: .h, src: .b, tier: 1)
        case 0xC1A0_1030: return AccumSpec(.fdot, vg: 2, shape: .multi, tile: .s, src: .b, tier: 1)
        case 0xC1A0_1400: return AccumSpec(.sdot, vg: 2, shape: .multi, tile: .s, src: .b, tier: 1)
        case 0xC1A0_1408: return AccumSpec(.usdot, vg: 2, shape: .multi, tile: .s, src: .b, tier: 1)
        case 0xC1A0_1410: return AccumSpec(.udot, vg: 2, shape: .multi, tile: .s, src: .b, tier: 1)
        case 0xC1A0_1800: return AccumSpec(.fmla, vg: 2, shape: .multi, tile: .s, src: .s, tier: 1)
        case 0xC1A0_1808: return AccumSpec(.fmls, vg: 2, shape: .multi, tile: .s, src: .s, tier: 1)
        case 0xC1A0_1810: return AccumSpec(.add, vg: 2, shape: .multi, tile: .s, src: .s, tier: 1)
        case 0xC1A0_1818: return AccumSpec(.sub, vg: 2, shape: .multi, tile: .s, src: .s, tier: 1)
        case 0xC1E0_1008: return AccumSpec(.bfmla, vg: 2, shape: .multi, tile: .h, src: .h, tier: 1)
        case 0xC1E0_1018: return AccumSpec(.bfmls, vg: 2, shape: .multi, tile: .h, src: .h, tier: 1)
        case 0xC1E0_1400: return AccumSpec(.sdot, vg: 2, shape: .multi, tile: .d, src: .h, tier: 1)
        case 0xC1E0_1408: return AccumSpec(.sdot, vg: 2, shape: .multi, tile: .s, src: .h, tier: 1)
        case 0xC1E0_1410: return AccumSpec(.udot, vg: 2, shape: .multi, tile: .d, src: .h, tier: 1)
        case 0xC1E0_1418: return AccumSpec(.udot, vg: 2, shape: .multi, tile: .s, src: .h, tier: 1)
        case 0xC1E0_1800: return AccumSpec(.fmla, vg: 2, shape: .multi, tile: .d, src: .d, tier: 1)
        case 0xC1E0_1808: return AccumSpec(.fmls, vg: 2, shape: .multi, tile: .d, src: .d, tier: 1)
        case 0xC1E0_1810: return AccumSpec(.add, vg: 2, shape: .multi, tile: .d, src: .d, tier: 1)
        case 0xC1E0_1818: return AccumSpec(.sub, vg: 2, shape: .multi, tile: .d, src: .d, tier: 1)
        default: break
        }
        switch e & 0xFFF0_9878 {
        case 0xC190_8000: return AccumSpec(.smlall, vg: 4, shape: .idx, tile: .d, src: .h, tier: 4, index: .i3LLd2)
        case 0xC190_8008: return AccumSpec(.smlsll, vg: 4, shape: .idx, tile: .d, src: .h, tier: 4, index: .i3LLd2)
        case 0xC190_8010: return AccumSpec(.umlall, vg: 4, shape: .idx, tile: .d, src: .h, tier: 4, index: .i3LLd2)
        case 0xC190_8018: return AccumSpec(.umlsll, vg: 4, shape: .idx, tile: .d, src: .h, tier: 4, index: .i3LLd2)
        case 0xC1D0_8000: return AccumSpec(.fmla, vg: 4, shape: .idx, tile: .d, src: .d, tier: 1, index: .i1)
        case 0xC1D0_8008: return AccumSpec(.sdot, vg: 4, shape: .idx, tile: .d, src: .h, tier: 1, index: .i1)
        case 0xC1D0_8010: return AccumSpec(.fmls, vg: 4, shape: .idx, tile: .d, src: .d, tier: 1, index: .i1)
        case 0xC1D0_8018: return AccumSpec(.udot, vg: 4, shape: .idx, tile: .d, src: .h, tier: 1, index: .i1)
        case 0xC1D0_8808: return AccumSpec(.svdot, vg: 4, shape: .idx, tile: .d, src: .h, tier: 1, index: .i1)
        case 0xC1D0_8818: return AccumSpec(.uvdot, vg: 4, shape: .idx, tile: .d, src: .h, tier: 1, index: .i1)
        default: break
        }
        switch e & 0xFFF0_9C1C {
        case 0xC120_0400: return AccumSpec(.smlall, vg: 1, shape: .single, tile: .s, src: .b, tier: 4)
        case 0xC120_0404: return AccumSpec(.usmlall, vg: 1, shape: .single, tile: .s, src: .b, tier: 4)
        case 0xC120_0408: return AccumSpec(.smlsll, vg: 1, shape: .single, tile: .s, src: .b, tier: 4)
        case 0xC120_0410: return AccumSpec(.umlall, vg: 1, shape: .single, tile: .s, src: .b, tier: 4)
        case 0xC120_0418: return AccumSpec(.umlsll, vg: 1, shape: .single, tile: .s, src: .b, tier: 4)
        case 0xC120_0800: return AccumSpec(.fmlal, vg: 2, shape: .single, tile: .s, src: .h, tier: 2)
        case 0xC120_0804: return AccumSpec(.fmlal, vg: 2, shape: .single, tile: .h, src: .b, tier: 2)
        case 0xC120_0808: return AccumSpec(.fmlsl, vg: 2, shape: .single, tile: .s, src: .h, tier: 2)
        case 0xC120_0810: return AccumSpec(.bfmlal, vg: 2, shape: .single, tile: .s, src: .h, tier: 2)
        case 0xC120_0818: return AccumSpec(.bfmlsl, vg: 2, shape: .single, tile: .s, src: .h, tier: 2)
        case 0xC130_0400: return AccumSpec(.fmlall, vg: 1, shape: .single, tile: .s, src: .b, tier: 4)
        case 0xC130_0800: return AccumSpec(.fmlal, vg: 4, shape: .single, tile: .s, src: .h, tier: 2)
        case 0xC130_0804: return AccumSpec(.fmlal, vg: 4, shape: .single, tile: .h, src: .b, tier: 2)
        case 0xC130_0808: return AccumSpec(.fmlsl, vg: 4, shape: .single, tile: .s, src: .h, tier: 2)
        case 0xC130_0810: return AccumSpec(.bfmlal, vg: 4, shape: .single, tile: .s, src: .h, tier: 2)
        case 0xC130_0818: return AccumSpec(.bfmlsl, vg: 4, shape: .single, tile: .s, src: .h, tier: 2)
        case 0xC160_0400: return AccumSpec(.smlall, vg: 1, shape: .single, tile: .d, src: .h, tier: 4)
        case 0xC160_0408: return AccumSpec(.smlsll, vg: 1, shape: .single, tile: .d, src: .h, tier: 4)
        case 0xC160_0410: return AccumSpec(.umlall, vg: 1, shape: .single, tile: .d, src: .h, tier: 4)
        case 0xC160_0418: return AccumSpec(.umlsll, vg: 1, shape: .single, tile: .d, src: .h, tier: 4)
        case 0xC160_0800: return AccumSpec(.smlal, vg: 2, shape: .single, tile: .s, src: .h, tier: 2)
        case 0xC160_0808: return AccumSpec(.smlsl, vg: 2, shape: .single, tile: .s, src: .h, tier: 2)
        case 0xC160_0810: return AccumSpec(.umlal, vg: 2, shape: .single, tile: .s, src: .h, tier: 2)
        case 0xC160_0818: return AccumSpec(.umlsl, vg: 2, shape: .single, tile: .s, src: .h, tier: 2)
        case 0xC170_0800: return AccumSpec(.smlal, vg: 4, shape: .single, tile: .s, src: .h, tier: 2)
        case 0xC170_0808: return AccumSpec(.smlsl, vg: 4, shape: .single, tile: .s, src: .h, tier: 2)
        case 0xC170_0810: return AccumSpec(.umlal, vg: 4, shape: .single, tile: .s, src: .h, tier: 2)
        case 0xC170_0818: return AccumSpec(.umlsl, vg: 4, shape: .single, tile: .s, src: .h, tier: 2)
        default: break
        }
        switch e & 0xFFF0_9078 {
        case 0xC110_8000: return AccumSpec(.smlall, vg: 4, shape: .idx, tile: .s, src: .b, tier: 4, index: .i4LL2)
        case 0xC110_8008: return AccumSpec(.smlsll, vg: 4, shape: .idx, tile: .s, src: .b, tier: 4, index: .i4LL2)
        case 0xC110_8010: return AccumSpec(.umlall, vg: 4, shape: .idx, tile: .s, src: .b, tier: 4, index: .i4LL2)
        case 0xC110_8018: return AccumSpec(.umlsll, vg: 4, shape: .idx, tile: .s, src: .b, tier: 4, index: .i4LL2)
        case 0xC110_8020: return AccumSpec(.usmlall, vg: 4, shape: .idx, tile: .s, src: .b, tier: 4, index: .i4LL2)
        case 0xC110_8030: return AccumSpec(.sumlall, vg: 4, shape: .idx, tile: .s, src: .b, tier: 4, index: .i4LL2)
        case 0xC110_8040: return AccumSpec(.fmlall, vg: 4, shape: .idx, tile: .s, src: .b, tier: 4, index: .i4LL2)
        case 0xC150_8000: return AccumSpec(.fmla, vg: 4, shape: .idx, tile: .s, src: .s, tier: 1, index: .i2)
        case 0xC150_8008: return AccumSpec(.fdot, vg: 4, shape: .idx, tile: .s, src: .b, tier: 1, index: .i2)
        case 0xC150_8010: return AccumSpec(.fmls, vg: 4, shape: .idx, tile: .s, src: .s, tier: 1, index: .i2)
        case 0xC150_8020: return AccumSpec(.svdot, vg: 4, shape: .idx, tile: .s, src: .b, tier: 1, index: .i2)
        case 0xC150_8028: return AccumSpec(.usvdot, vg: 4, shape: .idx, tile: .s, src: .b, tier: 1, index: .i2)
        case 0xC150_8030: return AccumSpec(.uvdot, vg: 4, shape: .idx, tile: .s, src: .b, tier: 1, index: .i2)
        case 0xC150_8038: return AccumSpec(.suvdot, vg: 4, shape: .idx, tile: .s, src: .b, tier: 1, index: .i2)
        case 0xC150_9000: return AccumSpec(.sdot, vg: 4, shape: .idx, tile: .s, src: .h, tier: 1, index: .i2)
        case 0xC150_9008: return AccumSpec(.fdot, vg: 4, shape: .idx, tile: .s, src: .h, tier: 1, index: .i2)
        case 0xC150_9010: return AccumSpec(.udot, vg: 4, shape: .idx, tile: .s, src: .h, tier: 1, index: .i2)
        case 0xC150_9018: return AccumSpec(.bfdot, vg: 4, shape: .idx, tile: .s, src: .h, tier: 1, index: .i2)
        case 0xC150_9020: return AccumSpec(.sdot, vg: 4, shape: .idx, tile: .s, src: .b, tier: 1, index: .i2)
        case 0xC150_9028: return AccumSpec(.usdot, vg: 4, shape: .idx, tile: .s, src: .b, tier: 1, index: .i2)
        case 0xC150_9030: return AccumSpec(.udot, vg: 4, shape: .idx, tile: .s, src: .b, tier: 1, index: .i2)
        case 0xC150_9038: return AccumSpec(.sudot, vg: 4, shape: .idx, tile: .s, src: .b, tier: 1, index: .i2)
        case 0xC190_9000: return AccumSpec(.fmlal, vg: 4, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L2)
        case 0xC190_9008: return AccumSpec(.fmlsl, vg: 4, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L2)
        case 0xC190_9010: return AccumSpec(.bfmlal, vg: 4, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L2)
        case 0xC190_9018: return AccumSpec(.bfmlsl, vg: 4, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L2)
        case 0xC1D0_9000: return AccumSpec(.smlal, vg: 4, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L2)
        case 0xC1D0_9008: return AccumSpec(.smlsl, vg: 4, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L2)
        case 0xC1D0_9010: return AccumSpec(.umlal, vg: 4, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L2)
        case 0xC1D0_9018: return AccumSpec(.umlsl, vg: 4, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L2)
        default: break
        }
        switch e & 0xFFF0_9838 {
        case 0xC190_0000: return AccumSpec(.smlall, vg: 2, shape: .idx, tile: .d, src: .h, tier: 4, index: .i3LLd2)
        case 0xC190_0008: return AccumSpec(.smlsll, vg: 2, shape: .idx, tile: .d, src: .h, tier: 4, index: .i3LLd2)
        case 0xC190_0010: return AccumSpec(.umlall, vg: 2, shape: .idx, tile: .d, src: .h, tier: 4, index: .i3LLd2)
        case 0xC190_0018: return AccumSpec(.umlsll, vg: 2, shape: .idx, tile: .d, src: .h, tier: 4, index: .i3LLd2)
        case 0xC1D0_0000: return AccumSpec(.fmla, vg: 2, shape: .idx, tile: .d, src: .d, tier: 1, index: .i1)
        case 0xC1D0_0008: return AccumSpec(.sdot, vg: 2, shape: .idx, tile: .d, src: .h, tier: 1, index: .i1)
        case 0xC1D0_0010: return AccumSpec(.fmls, vg: 2, shape: .idx, tile: .d, src: .d, tier: 1, index: .i1)
        case 0xC1D0_0018: return AccumSpec(.udot, vg: 2, shape: .idx, tile: .d, src: .h, tier: 1, index: .i1)
        default: break
        }
        switch e & 0xFFF0_9C18 {
        case 0xC120_0C00: return AccumSpec(.fmlal, vg: 1, shape: .single, tile: .s, src: .h, tier: 2)
        case 0xC120_0C08: return AccumSpec(.fmlsl, vg: 1, shape: .single, tile: .s, src: .h, tier: 2)
        case 0xC120_0C10: return AccumSpec(.bfmlal, vg: 1, shape: .single, tile: .s, src: .h, tier: 2)
        case 0xC120_0C18: return AccumSpec(.bfmlsl, vg: 1, shape: .single, tile: .s, src: .h, tier: 2)
        case 0xC120_1000: return AccumSpec(.fdot, vg: 2, shape: .single, tile: .s, src: .h, tier: 1)
        case 0xC120_1008: return AccumSpec(.fdot, vg: 2, shape: .single, tile: .h, src: .b, tier: 1)
        case 0xC120_1010: return AccumSpec(.bfdot, vg: 2, shape: .single, tile: .s, src: .h, tier: 1)
        case 0xC120_1018: return AccumSpec(.fdot, vg: 2, shape: .single, tile: .s, src: .b, tier: 1)
        case 0xC120_1400: return AccumSpec(.sdot, vg: 2, shape: .single, tile: .s, src: .b, tier: 1)
        case 0xC120_1408: return AccumSpec(.usdot, vg: 2, shape: .single, tile: .s, src: .b, tier: 1)
        case 0xC120_1410: return AccumSpec(.udot, vg: 2, shape: .single, tile: .s, src: .b, tier: 1)
        case 0xC120_1418: return AccumSpec(.sudot, vg: 2, shape: .single, tile: .s, src: .b, tier: 1)
        case 0xC120_1800: return AccumSpec(.fmla, vg: 2, shape: .single, tile: .s, src: .s, tier: 1)
        case 0xC120_1808: return AccumSpec(.fmls, vg: 2, shape: .single, tile: .s, src: .s, tier: 1)
        case 0xC120_1810: return AccumSpec(.add, vg: 2, shape: .single, tile: .s, src: .s, tier: 1)
        case 0xC120_1818: return AccumSpec(.sub, vg: 2, shape: .single, tile: .s, src: .s, tier: 1)
        case 0xC120_1C00: return AccumSpec(.fmla, vg: 2, shape: .single, tile: .h, src: .h, tier: 1)
        case 0xC120_1C08: return AccumSpec(.fmls, vg: 2, shape: .single, tile: .h, src: .h, tier: 1)
        case 0xC130_0C00: return AccumSpec(.fmlal, vg: 1, shape: .single, tile: .h, src: .b, tier: 2)
        case 0xC130_1000: return AccumSpec(.fdot, vg: 4, shape: .single, tile: .s, src: .h, tier: 1)
        case 0xC130_1008: return AccumSpec(.fdot, vg: 4, shape: .single, tile: .h, src: .b, tier: 1)
        case 0xC130_1010: return AccumSpec(.bfdot, vg: 4, shape: .single, tile: .s, src: .h, tier: 1)
        case 0xC130_1018: return AccumSpec(.fdot, vg: 4, shape: .single, tile: .s, src: .b, tier: 1)
        case 0xC130_1400: return AccumSpec(.sdot, vg: 4, shape: .single, tile: .s, src: .b, tier: 1)
        case 0xC130_1408: return AccumSpec(.usdot, vg: 4, shape: .single, tile: .s, src: .b, tier: 1)
        case 0xC130_1410: return AccumSpec(.udot, vg: 4, shape: .single, tile: .s, src: .b, tier: 1)
        case 0xC130_1418: return AccumSpec(.sudot, vg: 4, shape: .single, tile: .s, src: .b, tier: 1)
        case 0xC130_1800: return AccumSpec(.fmla, vg: 4, shape: .single, tile: .s, src: .s, tier: 1)
        case 0xC130_1808: return AccumSpec(.fmls, vg: 4, shape: .single, tile: .s, src: .s, tier: 1)
        case 0xC130_1810: return AccumSpec(.add, vg: 4, shape: .single, tile: .s, src: .s, tier: 1)
        case 0xC130_1818: return AccumSpec(.sub, vg: 4, shape: .single, tile: .s, src: .s, tier: 1)
        case 0xC130_1C00: return AccumSpec(.fmla, vg: 4, shape: .single, tile: .h, src: .h, tier: 1)
        case 0xC130_1C08: return AccumSpec(.fmls, vg: 4, shape: .single, tile: .h, src: .h, tier: 1)
        case 0xC160_0C00: return AccumSpec(.smlal, vg: 1, shape: .single, tile: .s, src: .h, tier: 2)
        case 0xC160_0C08: return AccumSpec(.smlsl, vg: 1, shape: .single, tile: .s, src: .h, tier: 2)
        case 0xC160_0C10: return AccumSpec(.umlal, vg: 1, shape: .single, tile: .s, src: .h, tier: 2)
        case 0xC160_0C18: return AccumSpec(.umlsl, vg: 1, shape: .single, tile: .s, src: .h, tier: 2)
        case 0xC160_1400: return AccumSpec(.sdot, vg: 2, shape: .single, tile: .d, src: .h, tier: 1)
        case 0xC160_1408: return AccumSpec(.sdot, vg: 2, shape: .single, tile: .s, src: .h, tier: 1)
        case 0xC160_1410: return AccumSpec(.udot, vg: 2, shape: .single, tile: .d, src: .h, tier: 1)
        case 0xC160_1418: return AccumSpec(.udot, vg: 2, shape: .single, tile: .s, src: .h, tier: 1)
        case 0xC160_1800: return AccumSpec(.fmla, vg: 2, shape: .single, tile: .d, src: .d, tier: 1)
        case 0xC160_1808: return AccumSpec(.fmls, vg: 2, shape: .single, tile: .d, src: .d, tier: 1)
        case 0xC160_1810: return AccumSpec(.add, vg: 2, shape: .single, tile: .d, src: .d, tier: 1)
        case 0xC160_1818: return AccumSpec(.sub, vg: 2, shape: .single, tile: .d, src: .d, tier: 1)
        case 0xC160_1C00: return AccumSpec(.bfmla, vg: 2, shape: .single, tile: .h, src: .h, tier: 1)
        case 0xC160_1C08: return AccumSpec(.bfmls, vg: 2, shape: .single, tile: .h, src: .h, tier: 1)
        case 0xC170_1400: return AccumSpec(.sdot, vg: 4, shape: .single, tile: .d, src: .h, tier: 1)
        case 0xC170_1408: return AccumSpec(.sdot, vg: 4, shape: .single, tile: .s, src: .h, tier: 1)
        case 0xC170_1410: return AccumSpec(.udot, vg: 4, shape: .single, tile: .d, src: .h, tier: 1)
        case 0xC170_1418: return AccumSpec(.udot, vg: 4, shape: .single, tile: .s, src: .h, tier: 1)
        case 0xC170_1800: return AccumSpec(.fmla, vg: 4, shape: .single, tile: .d, src: .d, tier: 1)
        case 0xC170_1808: return AccumSpec(.fmls, vg: 4, shape: .single, tile: .d, src: .d, tier: 1)
        case 0xC170_1810: return AccumSpec(.add, vg: 4, shape: .single, tile: .d, src: .d, tier: 1)
        case 0xC170_1818: return AccumSpec(.sub, vg: 4, shape: .single, tile: .d, src: .d, tier: 1)
        case 0xC170_1C00: return AccumSpec(.bfmla, vg: 4, shape: .single, tile: .h, src: .h, tier: 1)
        case 0xC170_1C08: return AccumSpec(.bfmls, vg: 4, shape: .single, tile: .h, src: .h, tier: 1)
        default: break
        }
        switch e & 0xFFF0_9038 {
        case 0xC110_0000: return AccumSpec(.smlall, vg: 2, shape: .idx, tile: .s, src: .b, tier: 4, index: .i4LL2)
        case 0xC110_0008: return AccumSpec(.smlsll, vg: 2, shape: .idx, tile: .s, src: .b, tier: 4, index: .i4LL2)
        case 0xC110_0010: return AccumSpec(.umlall, vg: 2, shape: .idx, tile: .s, src: .b, tier: 4, index: .i4LL2)
        case 0xC110_0018: return AccumSpec(.umlsll, vg: 2, shape: .idx, tile: .s, src: .b, tier: 4, index: .i4LL2)
        case 0xC110_0020: return AccumSpec(.usmlall, vg: 2, shape: .idx, tile: .s, src: .b, tier: 4, index: .i4LL2)
        case 0xC110_0030: return AccumSpec(.sumlall, vg: 2, shape: .idx, tile: .s, src: .b, tier: 4, index: .i4LL2)
        case 0xC150_0000: return AccumSpec(.fmla, vg: 2, shape: .idx, tile: .s, src: .s, tier: 1, index: .i2)
        case 0xC150_0008: return AccumSpec(.fvdot, vg: 2, shape: .idx, tile: .s, src: .h, tier: 1, index: .i2)
        case 0xC150_0010: return AccumSpec(.fmls, vg: 2, shape: .idx, tile: .s, src: .s, tier: 1, index: .i2)
        case 0xC150_0018: return AccumSpec(.bfvdot, vg: 2, shape: .idx, tile: .s, src: .h, tier: 1, index: .i2)
        case 0xC150_0020: return AccumSpec(.svdot, vg: 2, shape: .idx, tile: .s, src: .h, tier: 1, index: .i2)
        case 0xC150_0030: return AccumSpec(.uvdot, vg: 2, shape: .idx, tile: .s, src: .h, tier: 1, index: .i2)
        case 0xC150_0038: return AccumSpec(.fdot, vg: 2, shape: .idx, tile: .s, src: .b, tier: 1, index: .i2)
        case 0xC150_1000: return AccumSpec(.sdot, vg: 2, shape: .idx, tile: .s, src: .h, tier: 1, index: .i2)
        case 0xC150_1008: return AccumSpec(.fdot, vg: 2, shape: .idx, tile: .s, src: .h, tier: 1, index: .i2)
        case 0xC150_1010: return AccumSpec(.udot, vg: 2, shape: .idx, tile: .s, src: .h, tier: 1, index: .i2)
        case 0xC150_1018: return AccumSpec(.bfdot, vg: 2, shape: .idx, tile: .s, src: .h, tier: 1, index: .i2)
        case 0xC150_1020: return AccumSpec(.sdot, vg: 2, shape: .idx, tile: .s, src: .b, tier: 1, index: .i2)
        case 0xC150_1028: return AccumSpec(.usdot, vg: 2, shape: .idx, tile: .s, src: .b, tier: 1, index: .i2)
        case 0xC150_1030: return AccumSpec(.udot, vg: 2, shape: .idx, tile: .s, src: .b, tier: 1, index: .i2)
        case 0xC150_1038: return AccumSpec(.sudot, vg: 2, shape: .idx, tile: .s, src: .b, tier: 1, index: .i2)
        case 0xC190_0020: return AccumSpec(.fmlall, vg: 2, shape: .idx, tile: .s, src: .b, tier: 4, index: .i4LL2)
        case 0xC190_1000: return AccumSpec(.fmlal, vg: 2, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L2)
        case 0xC190_1008: return AccumSpec(.fmlsl, vg: 2, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L2)
        case 0xC190_1010: return AccumSpec(.bfmlal, vg: 2, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L2)
        case 0xC190_1018: return AccumSpec(.bfmlsl, vg: 2, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L2)
        case 0xC1D0_1000: return AccumSpec(.smlal, vg: 2, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L2)
        case 0xC1D0_1008: return AccumSpec(.smlsl, vg: 2, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L2)
        case 0xC1D0_1010: return AccumSpec(.umlal, vg: 2, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L2)
        case 0xC1D0_1018: return AccumSpec(.umlsl, vg: 2, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L2)
        default: break
        }
        switch e & 0xFFF0_9070 {
        case 0xC110_9000: return AccumSpec(.fmla, vg: 4, shape: .idx, tile: .h, src: .h, tier: 1, index: .i3s)
        case 0xC110_9010: return AccumSpec(.fmls, vg: 4, shape: .idx, tile: .h, src: .h, tier: 1, index: .i3s)
        case 0xC110_9020: return AccumSpec(.bfmla, vg: 4, shape: .idx, tile: .h, src: .h, tier: 1, index: .i3s)
        case 0xC110_9030: return AccumSpec(.bfmls, vg: 4, shape: .idx, tile: .h, src: .h, tier: 1, index: .i3s)
        case 0xC110_9040: return AccumSpec(.fdot, vg: 4, shape: .idx, tile: .h, src: .b, tier: 1, index: .i3s)
        case 0xC190_9020: return AccumSpec(.fmlal, vg: 4, shape: .idx, tile: .h, src: .b, tier: 2, index: .i4f8L2)
        default: break
        }
        switch e & 0xFFF0_9830 {
        case 0xC1D0_0800: return AccumSpec(.fvdotb, vg: 4, shape: .idx, tile: .s, src: .b, tier: 1, index: .i2vt)
        case 0xC1D0_0810: return AccumSpec(.fvdott, vg: 4, shape: .idx, tile: .s, src: .b, tier: 1, index: .i2vt)
        default: break
        }
        switch e & 0xFFF0_101C {
        case 0xC180_0000: return AccumSpec(.smlall, vg: 1, shape: .idx, tile: .d, src: .h, tier: 4, index: .i3L1)
        case 0xC180_0008: return AccumSpec(.smlsll, vg: 1, shape: .idx, tile: .d, src: .h, tier: 4, index: .i3L1)
        case 0xC180_0010: return AccumSpec(.umlall, vg: 1, shape: .idx, tile: .d, src: .h, tier: 4, index: .i3L1)
        case 0xC180_0018: return AccumSpec(.umlsll, vg: 1, shape: .idx, tile: .d, src: .h, tier: 4, index: .i3L1)
        default: break
        }
        switch e & 0xFFF0_9030 {
        case 0xC110_1000: return AccumSpec(.fmla, vg: 2, shape: .idx, tile: .h, src: .h, tier: 1, index: .i3s)
        case 0xC110_1010: return AccumSpec(.fmls, vg: 2, shape: .idx, tile: .h, src: .h, tier: 1, index: .i3s)
        case 0xC110_1020: return AccumSpec(.bfmla, vg: 2, shape: .idx, tile: .h, src: .h, tier: 1, index: .i3s)
        case 0xC110_1030: return AccumSpec(.bfmls, vg: 2, shape: .idx, tile: .h, src: .h, tier: 1, index: .i3s)
        case 0xC190_1030: return AccumSpec(.fmlal, vg: 2, shape: .idx, tile: .h, src: .b, tier: 2, index: .i4f8L2)
        case 0xC1D0_0020: return AccumSpec(.fdot, vg: 2, shape: .idx, tile: .h, src: .b, tier: 1, index: .i3s)
        case 0xC1D0_1020: return AccumSpec(.fvdot, vg: 2, shape: .idx, tile: .h, src: .b, tier: 1, index: .i3s)
        default: break
        }
        switch e & 0xFFF0_001C {
        case 0xC100_0000: return AccumSpec(.smlall, vg: 1, shape: .idx, tile: .s, src: .b, tier: 4, index: .i4LL1)
        case 0xC100_0004: return AccumSpec(.usmlall, vg: 1, shape: .idx, tile: .s, src: .b, tier: 4, index: .i4LL1)
        case 0xC100_0008: return AccumSpec(.smlsll, vg: 1, shape: .idx, tile: .s, src: .b, tier: 4, index: .i4LL1)
        case 0xC100_0010: return AccumSpec(.umlall, vg: 1, shape: .idx, tile: .s, src: .b, tier: 4, index: .i4LL1)
        case 0xC100_0014: return AccumSpec(.sumlall, vg: 1, shape: .idx, tile: .s, src: .b, tier: 4, index: .i4LL1)
        case 0xC100_0018: return AccumSpec(.umlsll, vg: 1, shape: .idx, tile: .s, src: .b, tier: 4, index: .i4LL1)
        case 0xC140_0000: return AccumSpec(.fmlall, vg: 1, shape: .idx, tile: .s, src: .b, tier: 4, index: .i4LL1)
        default: break
        }
        switch e & 0xFFF0_1018 {
        case 0xC180_1000: return AccumSpec(.fmlal, vg: 1, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L1)
        case 0xC180_1008: return AccumSpec(.fmlsl, vg: 1, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L1)
        case 0xC180_1010: return AccumSpec(.bfmlal, vg: 1, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L1)
        case 0xC180_1018: return AccumSpec(.bfmlsl, vg: 1, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L1)
        case 0xC1C0_1000: return AccumSpec(.smlal, vg: 1, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L1)
        case 0xC1C0_1008: return AccumSpec(.smlsl, vg: 1, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L1)
        case 0xC1C0_1010: return AccumSpec(.umlal, vg: 1, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L1)
        case 0xC1C0_1018: return AccumSpec(.umlsl, vg: 1, shape: .idx, tile: .s, src: .h, tier: 2, index: .i3L1)
        default: break
        }
        switch e & 0xFFF0_1010 {
        case 0xC1C0_0000: return AccumSpec(.fmlal, vg: 1, shape: .idx, tile: .h, src: .b, tier: 2, index: .i4f8L1)
        default: break
        }
        return nil
    }
}
