// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// AdvSIMD modified immediate per ARM ARM § C4.1.96.30.
// Encoding: `0 Q op 0 1111 00000 abc cmode 01 defgh Rd`.
// `cmode` (bits[15:12]) + `op` (bit[29]) select between MOVI/MVNI/
// ORR-imm/BIC-imm/FMOV-imm forms; `abcdefgh` (bits 18-16:9-5) is the
// 8-bit immediate seed expanded into a 64-bit pattern per ARM ARM
// `AdvSIMDExpandImm`.

enum AdvSIMDModifiedImmediateDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let op = UInt8((encoding >> 29) & 0x1)
        let abc = UInt8((encoding >> 16) & 0x7)
        let cmode = UInt8((encoding >> 12) & 0xF)
        let defgh = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        // For the integer modimm forms (cmode != 1111), bit11 (o2) is a
        // fixed 0; o2 = 1 there is reserved (UNDEFINED).
        if (encoding >> 11) & 1 == 1, cmode != 0b1111 {
            return .undefined(at: address, encoding: encoding)
        }

        let abcdefgh: UInt8 = (abc << 5) | defgh
        let (immValue, immKind) = decodeAdvSIMDModifiedImmediate(
            cmode: cmode, op: op, abcdefgh: abcdefgh,
        )

        // MOVI 64-bit replicated-byte (cmode=1110, op=1) has two forms:
        //   Q=0 → scalar `MOVI Dd, #imm`; Q=1 → vector `MOVI Vd.2D, #imm`.
        // Both render the full 64-bit expanded value. (classifyImmediate
        // below handles only the vector arrangement, so cover both here.)
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
                operands: [dst, .unsignedImmediate(value: immValue, width: 64)],
            )
        }
        // Mnemonic + destination arrangement + optional shift operand
        // depend on cmode+op per ARM ARM Table C4-1.
        let kindInfo = classifyImmediate(cmode: cmode, op: op, Q: Q, o2: UInt8((encoding >> 11) & 1))
        guard let info = kindInfo else {
            return .undefined(at: address, encoding: encoding)
        }
        var operands: [Operand] = []
        operands.reserveCapacity(3)
        operands.append(simdfpVectorOperand(Rd, arrangement: info.arrangement))
        switch immKind {
        case .integer:
            // Integer forms render the raw 8-bit seed (`#abcdefgh`), with
            // the LSL/MSL shift as a separate operand — matching llvm-mc.
            // (The 64-bit replicated-byte MOVI, cmode=1110/op=1, renders
            // its full expanded value via the early return above.)
            operands.append(.unsignedImmediate(value: UInt64(abcdefgh), width: 8))
        case .floatDouble:
            operands.append(.floatImmediate(bits: immValue, kind: .double))
        default:
            // .floatSingle — .floatHalf is structurally unreachable here
            // (decodeAdvSIMDModifiedImmediate never emits half today; FP16
            // vector immediates land in this branch if a future caller
            // changes that, with kind .single as a non-trapping fallback).
            operands.append(.floatImmediate(bits: immValue, kind: .single))
        }
        if let shift = info.shiftOperand {
            operands.append(shift)
        }
        // BIC/ORR vector immediate are destructive on Rd (preserve other
        // bits per imm; semantically Vd is both read and written).
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
            operands: operands,
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
        // cmode encoding (ARM ARM Table C4-1):
        //   0xx0 op=0: MOVI 32-bit (shift = cmode[3:1] * 8). Arrangement
        //     .2S/.4S.
        //   0xx0 op=1: MVNI 32-bit (shift = cmode[3:1] * 8). .2S/.4S.
        //   0xx1 op=0: ORR (immediate) 32-bit. .2S/.4S.
        //   0xx1 op=1: BIC (immediate) 32-bit. .2S/.4S.
        //   10x0 op=0: MOVI 16-bit (shift = cmode[1] * 8). .4H/.8H.
        //   10x0 op=1: MVNI 16-bit. .4H/.8H.
        //   10x1 op=0: ORR 16-bit. .4H/.8H.
        //   10x1 op=1: BIC 16-bit. .4H/.8H.
        //   110x op=0: MOVI 32-bit MSL (shift-with-1s-fill = cmode[0]*8).
        //   110x op=1: MVNI 32-bit MSL.
        //   1110 op=0: MOVI 8-bit. .8B/.16B.
        //   1110 op=1: MOVI 64-bit replicated byte. .2D.
        //   1111 op=0: FMOV 32-bit immediate (single-precision). .2S/.4S.
        //   1111 op=1 Q=1: FMOV 64-bit immediate (double-precision). .2D.
        //   1111 op=1 Q=0: reserved (or FMOV half-precision under FEAT_FP16).
        let arrSI: VectorArrangement = Q == 1 ? .s4 : .s2
        let arrHI: VectorArrangement = Q == 1 ? .h8 : .h4
        let arrBI: VectorArrangement = Q == 1 ? .b16 : .b8
        let cmodeHi3 = (cmode >> 1) & 0x7
        let cmodeLow = cmode & 1
        let shiftAmount = UInt8(cmodeHi3) * 8

        if (cmode & 0b1001) == 0b0000 {
            // 0xx0 — 32-bit MOVI/MVNI with LSL shift cmode[3:1] * 8.
            let mnemonic: Mnemonic = op == 0 ? .movi : .mvni
            let shiftOp: Operand? = shiftAmount == 0
                ? nil
                : .shiftAmount(kind: .lsl, amount: shiftAmount)
            return ImmediateInfo(mnemonic: mnemonic, arrangement: arrSI, shiftOperand: shiftOp)
        }
        if (cmode & 0b1001) == 0b0001 {
            // 0xx1 — 32-bit ORR/BIC immediate.
            let mnemonic: Mnemonic = op == 0 ? .orr : .bic
            let shiftOp: Operand? = shiftAmount == 0
                ? nil
                : .shiftAmount(kind: .lsl, amount: shiftAmount)
            return ImmediateInfo(mnemonic: mnemonic, arrangement: arrSI, shiftOperand: shiftOp)
        }
        if (cmode & 0b1101) == 0b1000 {
            // 10x0 — 16-bit MOVI/MVNI with cmode[1] * 8 shift.
            let mnemonic: Mnemonic = op == 0 ? .movi : .mvni
            let shamt = UInt8((cmode >> 1) & 1) * 8
            let shiftOp: Operand? = shamt == 0
                ? nil
                : .shiftAmount(kind: .lsl, amount: shamt)
            return ImmediateInfo(mnemonic: mnemonic, arrangement: arrHI, shiftOperand: shiftOp)
        }
        if (cmode & 0b1101) == 0b1001 {
            // 10x1 — 16-bit ORR/BIC.
            let mnemonic: Mnemonic = op == 0 ? .orr : .bic
            let shamt = UInt8((cmode >> 1) & 1) * 8
            let shiftOp: Operand? = shamt == 0
                ? nil
                : .shiftAmount(kind: .lsl, amount: shamt)
            return ImmediateInfo(mnemonic: mnemonic, arrangement: arrHI, shiftOperand: shiftOp)
        }
        if (cmode & 0b1110) == 0b1100 {
            // 110x — 32-bit MOVI/MVNI with MSL shift cmode[0] * 8 + 8.
            let mnemonic: Mnemonic = op == 0 ? .movi : .mvni
            let mslAmt = UInt8(cmodeLow) * 8 + 8
            let shiftOp: Operand = .shiftAmount(kind: .msl, amount: mslAmt)
            return ImmediateInfo(mnemonic: mnemonic, arrangement: arrSI, shiftOperand: shiftOp)
        }
        if cmode == 0b1110 {
            // op is 0 here: the op=1 64-bit replicated-byte MOVI returns
            // from `decode` before classification.
            return ImmediateInfo(mnemonic: .movi, arrangement: arrBI, shiftOperand: nil)
        }
        // cmode == 0b1111 — FMOV vector immediate. o2 (bit11) selects half:
        // op=0,o2=0 → single (.2s/.4s); op=0,o2=1 → half (.4h/.8h, FEAT_FP16);
        // op=1,o2=0 → double (.2d, Q=1); op=1,o2=1 reserved.
        if op == 0 {
            return ImmediateInfo(mnemonic: .fmov, arrangement: o2 == 1 ? arrHI : arrSI, shiftOperand: nil)
        }
        if o2 == 1 { return nil }
        // op=1: FMOV.2D (double); Q must be 1.
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

/// ARM ARM `AdvSIMDExpandImm` pseudo-code. Given (cmode, op, abcdefgh),
/// returns the 64-bit replicated value used by MOVI/MVNI/ORR-imm/
/// BIC-imm/FMOV-imm, plus the `AdvSIMDImmediateKind` distinguishing
/// integer-replicated forms from FP-imm forms.
@_effects(readonly)
public func decodeAdvSIMDModifiedImmediate(
    cmode: UInt8, op: UInt8, abcdefgh: UInt8,
) -> (value: UInt64, kind: AdvSIMDImmediateKind) {
    let byte = UInt64(abcdefgh)
    let cmodeHi3 = (cmode >> 1) & 0x7
    let cmodeLow = cmode & 1

    // 0xx0: 32-bit MOVI shifted byte: byte << (cmode[3:1] * 8), zero-extended
    //       and replicated to 64-bit.
    if (cmode & 0b1001) == 0b0000 {
        let shift = UInt64(cmodeHi3) * 8
        let lane32 = byte << shift
        return (lane32 | (lane32 << 32), .integer)
    }
    // 0xx1: same value, integer kind (ORR/BIC mask).
    if (cmode & 0b1001) == 0b0001 {
        let shift = UInt64(cmodeHi3) * 8
        let lane32 = byte << shift
        return (lane32 | (lane32 << 32), .integer)
    }
    // 10x0: 16-bit MOVI shifted byte.
    if (cmode & 0b1101) == 0b1000 {
        let shift = UInt64((cmode >> 1) & 1) * 8
        let lane16 = byte << shift
        let lane32 = lane16 | (lane16 << 16)
        return (lane32 | (lane32 << 32), .integer)
    }
    // 10x1: 16-bit ORR/BIC.
    if (cmode & 0b1101) == 0b1001 {
        let shift = UInt64((cmode >> 1) & 1) * 8
        let lane16 = byte << shift
        let lane32 = lane16 | (lane16 << 16)
        return (lane32 | (lane32 << 32), .integer)
    }
    // 110x: 32-bit MOVI MSL — byte << (8 + cmode[0]*8) with low bits
    // filled with ones (cmode[0]=0: low 8 = 1s; cmode[0]=1: low 16 = 1s).
    if (cmode & 0b1110) == 0b1100 {
        let onesBits: UInt64 = cmodeLow == 0 ? 0xFF : 0xFFFF
        let mslShift = (UInt64(cmodeLow) * 8) + 8
        let lane32 = (byte << mslShift) | onesBits
        return (lane32 | (lane32 << 32), .integer)
    }
    if cmode == 0b1110 {
        if op == 0 {
            // 8-bit MOVI replicated byte.
            var lane: UInt64 = byte
            lane |= lane << 8
            lane |= lane << 16
            lane |= lane << 32
            return (lane, .integer)
        }
        // 64-bit MOVI: each bit of abcdefgh expands to a byte of all-1s
        // or all-0s.
        var lane: UInt64 = 0
        for i: UInt64 in 0 ..< 8 {
            if (byte >> i) & 1 == 1 {
                lane |= 0xFF << (i * 8)
            }
        }
        return (lane, .integer)
    }
    // cmode == 0b1111 — only remaining 4-bit value after the patterns
    // above exhaust 0000..1110. FMOV vector immediate.
    if op == 0 {
        // FMOV vector single-precision immediate.
        let bits = vfpExpandImm(imm8: abcdefgh, kind: .single)
        return (bits | (bits << 32), .floatSingle)
    }
    // FMOV vector double-precision immediate.
    let bits = vfpExpandImm(imm8: abcdefgh, kind: .double)
    return (bits, .floatDouble)
}
