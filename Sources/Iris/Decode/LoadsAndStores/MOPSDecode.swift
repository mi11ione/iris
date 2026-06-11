// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// FEAT_MOPS memory-copy / memory-set acceleration. Detected by the
// dispatcher's `(encoding & 0x3B200C00) == 0x19000400` discriminant
// (bits 28,27,24 set, bit 10 set; bits 29,25,21 clear; bits 23:22,
// 15:12, and o0 free) BEFORE the V check, since CPY/SETG carry bit26
// (o0) = 1 which would otherwise route them to SIMD.
//
//   bits[31:30] must be 00 (else UNDEFINED).
//   bit[26] = o0: 0 = CPYF / SET, 1 = CPY / SETG.
//   bits[23:22]: 00/01/10 = CPY-family stage (P/M/E); 11 = SET-family.
//
// CPY/CPYF `[Xd]!, [Xs]!, Xn!`:
//   Xd = bits[4:0] (≠ 31), Xs = bits[20:16] (≠ 31), Xn = bits[9:5] (ZR ok).
//   options bits[15:12]: bits13:12 = {-, wt, rt, t}, bits15:14 = {-, wn, rn, n}.
//
// SET/SETG `[Xd]!, Xn!, Xs`:
//   Xd = bits[4:0] (≠ 31), Xn = bits[9:5] (ZR ok), Xs = bits[20:16] (ZR ok).
//   stage bits[15:14]: 00/01/10 = P/M/E (11 UNDEFINED).
//   options bits[13:12]: bit12 = t, bit13 = n.
//
// All three register fields (bits[4:0], bits[9:5], bits[20:16]) must be
// pairwise distinct (compared by raw 5-bit value) — else UNDEFINED.
// MOPS is a read-modify-write of all three working registers.

enum MOPSDecode {
    /// CPY/CPYF mnemonic cube, indexed `[family*3 + stage][options]` with
    /// family 0=cpyf, 1=cpy; stage 0=P,1=M,2=E; options = bits[15:12].
    private static let cpyMnemonics: [[Mnemonic]] = [
        // cpyf P
        [.cpyfp, .cpyfpwt, .cpyfprt, .cpyfpt, .cpyfpwn, .cpyfpwtwn, .cpyfprtwn, .cpyfptwn,
         .cpyfprn, .cpyfpwtrn, .cpyfprtrn, .cpyfptrn, .cpyfpn, .cpyfpwtn, .cpyfprtn, .cpyfptn],
        // cpyf M
        [.cpyfm, .cpyfmwt, .cpyfmrt, .cpyfmt, .cpyfmwn, .cpyfmwtwn, .cpyfmrtwn, .cpyfmtwn,
         .cpyfmrn, .cpyfmwtrn, .cpyfmrtrn, .cpyfmtrn, .cpyfmn, .cpyfmwtn, .cpyfmrtn, .cpyfmtn],
        // cpyf E
        [.cpyfe, .cpyfewt, .cpyfert, .cpyfet, .cpyfewn, .cpyfewtwn, .cpyfertwn, .cpyfetwn,
         .cpyfern, .cpyfewtrn, .cpyfertrn, .cpyfetrn, .cpyfen, .cpyfewtn, .cpyfertn, .cpyfetn],
        // cpy P
        [.cpyp, .cpypwt, .cpyprt, .cpypt, .cpypwn, .cpypwtwn, .cpyprtwn, .cpyptwn,
         .cpyprn, .cpypwtrn, .cpyprtrn, .cpyptrn, .cpypn, .cpypwtn, .cpyprtn, .cpyptn],
        // cpy M
        [.cpym, .cpymwt, .cpymrt, .cpymt, .cpymwn, .cpymwtwn, .cpymrtwn, .cpymtwn,
         .cpymrn, .cpymwtrn, .cpymrtrn, .cpymtrn, .cpymn, .cpymwtn, .cpymrtn, .cpymtn],
        // cpy E
        [.cpye, .cpyewt, .cpyert, .cpyet, .cpyewn, .cpyewtwn, .cpyertwn, .cpyetwn,
         .cpyern, .cpyewtrn, .cpyertrn, .cpyetrn, .cpyen, .cpyewtn, .cpyertn, .cpyetn],
    ]

    /// SET/SETG mnemonic cube, indexed `[family*3 + stage][options]` with
    /// family 0=set, 1=setg; stage 0=P,1=M,2=E; options = bits[13:12].
    private static let setMnemonics: [[Mnemonic]] = [
        [.setp, .setpt, .setpn, .setptn],
        [.setm, .setmt, .setmn, .setmtn],
        [.sete, .setet, .seten, .setetn],
        [.setgp, .setgpt, .setgpn, .setgptn],
        [.setgm, .setgmt, .setgmn, .setgmtn],
        [.setge, .setget, .setgen, .setgetn],
    ]

    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        // bits[31:30] are SBZ; nonzero is not a MOPS encoding.
        if (encoding >> 30) != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let o0 = UInt8((encoding >> 26) & 1)
        let szStage = UInt8((encoding >> 22) & 0x3)
        let rD = UInt8(encoding & 0x1F)
        let rField9_5 = UInt8((encoding >> 5) & 0x1F)
        let rField20_16 = UInt8((encoding >> 16) & 0x1F)

        // All three register fields must be pairwise distinct.
        if rD == rField9_5 || rD == rField20_16 || rField9_5 == rField20_16 {
            return .undefined(at: address, encoding: encoding)
        }
        // Destination is never the ZR encoding.
        if rD == 31 {
            return .undefined(at: address, encoding: encoding)
        }

        if szStage == 0b11 {
            return decodeSet(
                encoding: encoding, address: address, o0: o0,
                rD: rD, rN: rField9_5, rS: rField20_16,
            )
        }
        return decodeCopy(
            encoding: encoding, address: address, o0: o0, stage: szStage,
            rD: rD, rN: rField9_5, rS: rField20_16,
        )
    }

    /// CPY/CPYF: `[Xd]!, [Xs]!, Xn!`. Xs (the source-address register) is
    /// also restricted from the ZR encoding.
    @_optimize(speed)
    private static func decodeCopy(
        encoding: UInt32, address: UInt64, o0: UInt8, stage: UInt8,
        rD: UInt8, rN: UInt8, rS: UInt8,
    ) -> DecodedDraft {
        if rS == 31 {
            return .undefined(at: address, encoding: encoding)
        }
        let options = Int((encoding >> 12) & 0xF)
        let row = Int(o0) * 3 + Int(stage)
        let mnemonic = cpyMnemonics[row][options]

        let xd = RegisterRef.x(rD)
        let xs = RegisterRef.x(rS)
        let xn = lsGprOperand(encoding: rN, width: .x64, form: .zrOrGeneral)

        // Read-modify-write of all three: each holds a pointer/count updated
        // by the instruction. Operand order is [Xd], [Xs], Xn.
        var regs = lsInsertingNonZero(reg: xd, into: .empty)
        regs = lsInsertingNonZero(reg: xs, into: regs)
        regs = lsInsertingNonZero(reg: xn, into: regs)

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: regs,
            semanticWrites: regs,
            branchClass: .none,
            memoryAccess: .atomic,
            memoryOrdering: [],
            flagEffect: .none,
            category: .loadsAndStores,
            operands: [.register(xd), .register(xs), .register(xn)],
        )
    }

    /// SET/SETG: `[Xd]!, Xn!, Xs`.
    @_optimize(speed)
    private static func decodeSet(
        encoding: UInt32, address: UInt64, o0: UInt8,
        rD: UInt8, rN: UInt8, rS: UInt8,
    ) -> DecodedDraft {
        let stage = UInt8((encoding >> 14) & 0x3)
        // stage 11 is UNDEFINED.
        if stage == 0b11 {
            return .undefined(at: address, encoding: encoding)
        }
        let options = Int((encoding >> 12) & 0x3)
        let row = Int(o0) * 3 + Int(stage)
        let mnemonic = setMnemonics[row][options]

        let xd = RegisterRef.x(rD)
        let xn = lsGprOperand(encoding: rN, width: .x64, form: .zrOrGeneral)
        let xs = lsGprOperand(encoding: rS, width: .x64, form: .zrOrGeneral)

        // Read-modify-write of the dest pointer + count; the data register Xs
        // is read.
        var regs = lsInsertingNonZero(reg: xd, into: .empty)
        regs = lsInsertingNonZero(reg: xn, into: regs)
        regs = lsInsertingNonZero(reg: xs, into: regs)
        var writes = lsInsertingNonZero(reg: xd, into: .empty)
        writes = lsInsertingNonZero(reg: xn, into: writes)

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: regs,
            semanticWrites: writes,
            branchClass: .none,
            memoryAccess: .atomic,
            memoryOrdering: [],
            flagEffect: .none,
            category: .loadsAndStores,
            operands: [.register(xd), .register(xn), .register(xs)],
        )
    }
}
