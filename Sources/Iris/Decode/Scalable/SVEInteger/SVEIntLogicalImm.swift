// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// G9 bitwise-immediate (AND/EOR/ORR and DUPM), the highest-
// risk rendering in the tier. The 13-bit N:immr:imms field decodes
// (via the reused `DecodeBitMasks`) to a 64-bit value; the element size is
// its smallest replication period, and the per-element value is what prints.
// AND/EOR/ORR always print `<mn> Zdn.<T>, Zdn.<T>, #0x<hex>`. DUPM prints
// `mov Zd.<T>, #<value>` when the per-element value is NOT expressible as an
// SVE cpy-imm8 (a "preferred logical immediate"), otherwise `dupm Zd.<T>,
// #0x<hex>`. `[23:22]` selects ORR(00)/EOR(01)/AND(10)/DUPM(11).

extension SVEIntegerDecode {
    @inline(__always)
    static func decodeLogicalImmediate(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let imm13 = (e >> 5) & 0x1FFF
        guard let value = DecodeBitMasks.decode(
            n: UInt8((imm13 >> 12) & 1), imms: UInt8(imm13 & 0x3F),
            immr: UInt8((imm13 >> 6) & 0x3F), regSize: 64,
        ) else { return undefined(e, a) }
        let (element, width) = logicalImmElement(value)
        let perElem = width == 64 ? value : value & ((UInt64(1) << width) - 1)
        let d = zd(e)
        // DUPM (`[23:22]==11`) collapses to `mov` for a preferred logical imm.
        if (e >> 22) & 0b11 == 0b11 {
            let mnemonic: Mnemonic = isSVECpyImm(perElem, width: width) ? .dupm : .mov
            return DecodedDraft(
                address: a, encoding: e, mnemonic: mnemonic,
                semanticWrites: vecMask(d), category: .sve,
                operands: [vec(d, element), .unsignedImmediate(value: perElem, width: UInt8(width))],
                scalableEffect: .readsStreamingMode,
            )
        }
        let mnemonic: Mnemonic = switch (e >> 22) & 0b11 {
        case 0b00: .orr
        case 0b01: .eor
        default: .and // 0b10
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(d), semanticWrites: vecMask(d), category: .sve,
            operands: [vec(d, element), vec(d, element), .unsignedImmediate(value: perElem, width: UInt8(width))],
            scalableEffect: .readsStreamingMode,
        )
    }

    /// The element size of a logical-immediate value: the smallest power-of-two
    /// width (8/16/32/64) whose low bits, replicated, reproduce the 64-bit value.
    @inline(__always)
    static func logicalImmElement(_ value: UInt64) -> (ScalarSize, UInt64) {
        if value & 0xFF == (value >> 8) & 0xFF, replicated(value, width: 8) { return (.b, 8) }
        if replicated(value, width: 16) { return (.h, 16) }
        if replicated(value, width: 32) { return (.s, 32) }
        return (.d, 64)
    }

    /// Whether `value` equals its low `width` bits replicated across 64 bits.
    @inline(__always)
    static func replicated(_ value: UInt64, width: UInt64) -> Bool {
        let element = value & ((UInt64(1) << width) - 1)
        var filled = element
        var w = width
        while w < 64 {
            filled |= filled << w; w *= 2
        }
        return filled == value
    }

    /// Whether the `width`-bit `perElem` is an SVE cpy immediate: a signed 8-bit
    /// value, optionally shifted left by 8. Such values render via DUP/CPY, so
    /// DUPM keeps the `dupm` form for them (they are not "preferred logical").
    @inline(__always)
    static func isSVECpyImm(_ perElem: UInt64, width: UInt64) -> Bool {
        let signed = signExtendValue(perElem, width: width)
        if signed >= -128, signed <= 127 { return true } // imm8
        if perElem & 0xFF == 0 { // imm8 << 8
            let high = signExtendValue(perElem >> 8, width: width - 8)
            if high >= -128, high <= 127 { return true }
        }
        return false
    }

    @inline(__always)
    static func signExtendValue(_ value: UInt64, width: UInt64) -> Int64 {
        if width >= 64 { return Int64(bitPattern: value) }
        let shift = UInt64(64) - width
        return Int64(bitPattern: value << shift) >> Int64(shift)
    }
}
