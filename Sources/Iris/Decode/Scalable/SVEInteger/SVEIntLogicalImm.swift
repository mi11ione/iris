// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEIntegerDecode {
    @inline(__always)
    static func decodeLogicalImmediate(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let imm13 = (e >> 5) & 0x1FFF
        guard let value = DecodeBitMasks.decode(
            n: UInt8((imm13 >> 12) & 1), imms: UInt8(imm13 & 0x3F),
            immr: UInt8((imm13 >> 6) & 0x3F), regSize: 64,
        ) else { return undefined(e, a) }
        let (element, width) = logicalImmElement(value)
        let perElem = width == 64 ? value : value & ((UInt64(1) << width) - 1)
        let d = zd(e)
        if (e >> 22) & 0b11 == 0b11 {
            let mnemonic: Mnemonic = isSVECpyImm(perElem, width: width) ? .dupm : .mov
            return DecodedDraft(
                address: a, encoding: e, mnemonic: mnemonic,
                semanticWrites: vecMask(d), category: .sve,
                operandCount: sink.emit(vec(d, element), .unsignedImmediate(value: perElem, width: UInt8(width))),
                scalableEffect: .readsStreamingMode,
            )
        }
        let mnemonic: Mnemonic = switch (e >> 22) & 0b11 {
        case 0b00: .orr
        case 0b01: .eor
        default: .and
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(d), semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, element), vec(d, element), .unsignedImmediate(value: perElem, width: UInt8(width))),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// The element size of a logical-immediate value.
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

    /// Whether the `width`-bit `perElem` is an SVE cpy immediate.
    @inline(__always)
    static func isSVECpyImm(_ perElem: UInt64, width: UInt64) -> Bool {
        let signed = signExtendValue(perElem, width: width)
        if signed >= -128, signed <= 127 { return true }
        if perElem & 0xFF == 0 {
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
