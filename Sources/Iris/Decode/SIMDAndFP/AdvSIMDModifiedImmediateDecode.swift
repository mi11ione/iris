// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum AdvSIMDModifiedImmediateDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let op = UInt8((encoding >> 29) & 0x1)
        let abc = UInt8((encoding >> 16) & 0x7)
        let cmode = UInt8((encoding >> 12) & 0xF)
        let defgh = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        if (encoding >> 11) & 1 == 1, cmode != 0b1111 {
            return .undefined(at: address, encoding: encoding)
        }

        let abcdefgh: UInt8 = (abc << 5) | defgh
        let (immValue, immKind) = decodeAdvSIMDModifiedImmediate(
            cmode: cmode, op: op, abcdefgh: abcdefgh,
        )

        if cmode == 0b1110, op == 1 {
            let dst: Operand = Q == 0
                ? simdfpScalarOperand(Rd, size: .d)
                : simdfpVectorOperand(Rd, arrangement: .d2)
            return DecodedDraft(
                address: address, encoding: encoding, mnemonic: .movi,
                semanticReads: .empty,
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operandCount: sink.emit(dst, .unsignedImmediate(value: immValue, width: 64)),
            )
        }
        let kindInfo = classifyImmediate(cmode: cmode, op: op, Q: Q, o2: UInt8((encoding >> 11) & 1))
        guard let info = kindInfo else {
            return .undefined(at: address, encoding: encoding)
        }
        let operandMark = sink.mark
        sink.append(simdfpVectorOperand(Rd, arrangement: info.arrangement))
        switch immKind {
        case .integer:
            sink.append(.unsignedImmediate(value: UInt64(abcdefgh), width: 8))
        case .floatDouble:
            sink.append(.floatImmediate(bits: immValue, kind: .double))
        default:
            sink.append(.floatImmediate(bits: immValue, kind: .single))
        }
        if let shift = info.shiftOperand {
            sink.append(shift)
        }
        let destReadsItself = info.mnemonic == .bic || info.mnemonic == .orr
        var reads: RegisterSet = .empty
        if destReadsItself {
            reads = simdfpInsertingVector(Rd, into: reads)
        }
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: info.mnemonic,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.count(since: operandMark),
        )
    }

    private struct ImmediateInfo {
        let mnemonic: Mnemonic
        let arrangement: VectorArrangement
        let shiftOperand: Operand?
    }

    @inline(__always)
    @_effects(readonly)
    private static func classifyImmediate(
        cmode: UInt8, op: UInt8, Q: UInt8, o2: UInt8,
    ) -> ImmediateInfo? {
        let arrSI: VectorArrangement = Q == 1 ? .s4 : .s2
        let arrHI: VectorArrangement = Q == 1 ? .h8 : .h4
        let arrBI: VectorArrangement = Q == 1 ? .b16 : .b8
        let cmodeHi3 = (cmode >> 1) & 0x7
        let cmodeLow = cmode & 1
        let shiftAmount = UInt8(cmodeHi3) * 8

        if (cmode & 0b1001) == 0b0000 {
            let mnemonic: Mnemonic = op == 0 ? .movi : .mvni
            let shiftOp: Operand? = shiftAmount == 0
                ? nil
                : .shiftAmount(kind: .lsl, amount: shiftAmount)
            return ImmediateInfo(mnemonic: mnemonic, arrangement: arrSI, shiftOperand: shiftOp)
        }
        if (cmode & 0b1001) == 0b0001 {
            let mnemonic: Mnemonic = op == 0 ? .orr : .bic
            let shiftOp: Operand? = shiftAmount == 0
                ? nil
                : .shiftAmount(kind: .lsl, amount: shiftAmount)
            return ImmediateInfo(mnemonic: mnemonic, arrangement: arrSI, shiftOperand: shiftOp)
        }
        if (cmode & 0b1101) == 0b1000 {
            let mnemonic: Mnemonic = op == 0 ? .movi : .mvni
            let shamt = UInt8((cmode >> 1) & 1) * 8
            let shiftOp: Operand? = shamt == 0
                ? nil
                : .shiftAmount(kind: .lsl, amount: shamt)
            return ImmediateInfo(mnemonic: mnemonic, arrangement: arrHI, shiftOperand: shiftOp)
        }
        if (cmode & 0b1101) == 0b1001 {
            let mnemonic: Mnemonic = op == 0 ? .orr : .bic
            let shamt = UInt8((cmode >> 1) & 1) * 8
            let shiftOp: Operand? = shamt == 0
                ? nil
                : .shiftAmount(kind: .lsl, amount: shamt)
            return ImmediateInfo(mnemonic: mnemonic, arrangement: arrHI, shiftOperand: shiftOp)
        }
        if (cmode & 0b1110) == 0b1100 {
            let mnemonic: Mnemonic = op == 0 ? .movi : .mvni
            let mslAmt = UInt8(cmodeLow) * 8 + 8
            let shiftOp: Operand = .shiftAmount(kind: .msl, amount: mslAmt)
            return ImmediateInfo(mnemonic: mnemonic, arrangement: arrSI, shiftOperand: shiftOp)
        }
        if cmode == 0b1110 {
            return ImmediateInfo(mnemonic: .movi, arrangement: arrBI, shiftOperand: nil)
        }
        if op == 0 {
            return ImmediateInfo(mnemonic: .fmov, arrangement: o2 == 1 ? arrHI : arrSI, shiftOperand: nil)
        }
        if o2 == 1 { return nil }
        if Q == 0 { return nil }
        return ImmediateInfo(mnemonic: .fmov, arrangement: .d2, shiftOperand: nil)
    }
}

/// Output kind from `decodeAdvSIMDModifiedImmediate` — consumers can
/// pattern-match to pick the
/// right `Operand` variant.
@frozen
public enum AdvSIMDImmediateKind: Sendable, Hashable {
    case integer
    case floatHalf
    case floatSingle
    case floatDouble
}

/// ARM ARM `AdvSIMDExpandImm`: from (cmode, op, abcdefgh), the 64-bit
/// replicated value for MOVI/MVNI/ORR-imm/BIC-imm/FMOV-imm plus the kind
/// distinguishing integer-replicated from FP-immediate forms.
@_effects(readonly)
public func decodeAdvSIMDModifiedImmediate(
    cmode: UInt8, op: UInt8, abcdefgh: UInt8,
) -> (value: UInt64, kind: AdvSIMDImmediateKind) {
    let byte = UInt64(abcdefgh)
    let cmodeHi3 = (cmode >> 1) & 0x7
    let cmodeLow = cmode & 1

    if (cmode & 0b1001) == 0b0000 {
        let shift = UInt64(cmodeHi3) * 8
        let lane32 = byte << shift
        return (lane32 | (lane32 << 32), .integer)
    }
    if (cmode & 0b1001) == 0b0001 {
        let shift = UInt64(cmodeHi3) * 8
        let lane32 = byte << shift
        return (lane32 | (lane32 << 32), .integer)
    }
    if (cmode & 0b1101) == 0b1000 {
        let shift = UInt64((cmode >> 1) & 1) * 8
        let lane16 = byte << shift
        let lane32 = lane16 | (lane16 << 16)
        return (lane32 | (lane32 << 32), .integer)
    }
    if (cmode & 0b1101) == 0b1001 {
        let shift = UInt64((cmode >> 1) & 1) * 8
        let lane16 = byte << shift
        let lane32 = lane16 | (lane16 << 16)
        return (lane32 | (lane32 << 32), .integer)
    }
    if (cmode & 0b1110) == 0b1100 {
        let onesBits: UInt64 = cmodeLow == 0 ? 0xFF : 0xFFFF
        let mslShift = (UInt64(cmodeLow) * 8) + 8
        let lane32 = (byte << mslShift) | onesBits
        return (lane32 | (lane32 << 32), .integer)
    }
    if cmode == 0b1110 {
        if op == 0 {
            var lane: UInt64 = byte
            lane |= lane << 8
            lane |= lane << 16
            lane |= lane << 32
            return (lane, .integer)
        }
        var lane: UInt64 = 0
        for i: UInt64 in 0 ..< 8 {
            if (byte >> i) & 1 == 1 {
                lane |= 0xFF << (i * 8)
            }
        }
        return (lane, .integer)
    }
    if op == 0 {
        let bits = vfpExpandImm(imm8: abcdefgh, kind: .single)
        return (bits | (bits << 32), .floatSingle)
    }
    let bits = vfpExpandImm(imm8: abcdefgh, kind: .double)
    return (bits, .floatDouble)
}
