// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// The SVE / SVE2 integer decoder for SVE-integer.
enum SVEIntegerDecode {
    /// Decode an in-scope SVE integer word.
    @_optimize(speed)
    static func decode(encoding e: UInt32, address a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        switch (e >> 24) & 0xFF {
        case 0x24: decodeCompare(e, a, &sink)
        case 0x04: decodeCompute(e, a, &sink)
        case 0x05: decodeMove(e, a, &sink)
        case 0x25: decodeImmediate(e, a, &sink)
        case 0x44: decodeSVE2Low(e, a, &sink)
        default: decodeSVE2High(e, a, &sink)
        }
    }

    @inline(__always)
    static func decodeCompute(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 21) & 1 == 0 {
            switch (e >> 13) & 0b111 {
            case 0b000: return decodePredicatedArithLog(e, a, &sink)
            case 0b001: return decodeReduction(e, a, &sink)
            case 0b010, 0b011: return decodeMultiplyAddMLA(e, a, &sink)
            case 0b100: return decodePredicatedShift(e, a, &sink)
            case 0b101: return decodePredicatedUnary(e, a, &sink)
            default: return decodeMultiplyAddMAD(e, a, &sink)
            }
        }
        return decodeUnpredicated(e, a, &sink)
    }

    /// Element size from a 2-bit `sz` value (already shifted to the low 2
    /// bits).
    @inline(__always)
    static func elementSize(_ sz: UInt32) -> ScalarSize {
        switch sz & 0b11 {
        case 0: .b
        case 1: .h
        case 2: .s
        default: .d
        }
    }

    /// The element size one step below `size`.
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

    /// Append the operand(s) for a shifted imm8 (`#imm8{, lsl #8}`).
    @inline(__always)
    static func appendShiftedImmediate(
        raw: UInt32, shift: UInt32, signed: Bool, to sink: inout OperandSink,
    ) {
        if shift != 0, raw == 0 {
            sink.append(signed
                ? .immediate(value: 0, width: 8)
                : .unsignedImmediate(value: 0, width: 8))
            sink.append(.shiftAmount(kind: .lsl, amount: UInt8(shift)))
            return
        }
        let width: UInt8 = shift == 0 ? 8 : 16
        sink.append(signed
            ? .immediate(value: signExtend(raw, bits: 8) << Int64(shift), width: width)
            : .unsignedImmediate(value: UInt64(raw) << shift, width: width))
    }

    /// Decode the SVE shift-immediate `tsz` scheme.
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
    /// encoding preserved), matching llvm-mc's empty output for rejected
    /// words.
    @inline(__always)
    static func undefined(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        DecodedDraft(address: a, encoding: e, mnemonic: .undefined, category: .sve)
    }
}
