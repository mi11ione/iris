// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum MOPSDecode {
    /// CPY/CPYF mnemonic cube, indexed `[family*3 + stage][options]` with
    /// family 0=cpyf, 1=cpy; stage 0=P,1=M,2=E; options = bits[15:12].
    private static let cpyMnemonics: [[Mnemonic]] = [
        [.cpyfp, .cpyfpwt, .cpyfprt, .cpyfpt, .cpyfpwn, .cpyfpwtwn, .cpyfprtwn, .cpyfptwn,
         .cpyfprn, .cpyfpwtrn, .cpyfprtrn, .cpyfptrn, .cpyfpn, .cpyfpwtn, .cpyfprtn, .cpyfptn],
        [.cpyfm, .cpyfmwt, .cpyfmrt, .cpyfmt, .cpyfmwn, .cpyfmwtwn, .cpyfmrtwn, .cpyfmtwn,
         .cpyfmrn, .cpyfmwtrn, .cpyfmrtrn, .cpyfmtrn, .cpyfmn, .cpyfmwtn, .cpyfmrtn, .cpyfmtn],
        [.cpyfe, .cpyfewt, .cpyfert, .cpyfet, .cpyfewn, .cpyfewtwn, .cpyfertwn, .cpyfetwn,
         .cpyfern, .cpyfewtrn, .cpyfertrn, .cpyfetrn, .cpyfen, .cpyfewtn, .cpyfertn, .cpyfetn],
        [.cpyp, .cpypwt, .cpyprt, .cpypt, .cpypwn, .cpypwtwn, .cpyprtwn, .cpyptwn,
         .cpyprn, .cpypwtrn, .cpyprtrn, .cpyptrn, .cpypn, .cpypwtn, .cpyprtn, .cpyptn],
        [.cpym, .cpymwt, .cpymrt, .cpymt, .cpymwn, .cpymwtwn, .cpymrtwn, .cpymtwn,
         .cpymrn, .cpymwtrn, .cpymrtrn, .cpymtrn, .cpymn, .cpymwtn, .cpymrtn, .cpymtn],
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

    /// SETGO mnemonic cube, indexed `[stage][options]` with stage 0=P, 1=M,
    /// 2=E from bits[15:14] and options = bits[13:12].
    private static let setgoMnemonics: [[Mnemonic]] = [
        [.setgop, .setgopt, .setgopn, .setgoptn],
        [.setgom, .setgomt, .setgomn, .setgomtn],
        [.setgoe, .setgoet, .setgoen, .setgoetn],
    ]

    /// SETGO: `[Xd]!, Xn!` — the memory-set-with-tags option form, whose
    /// source register field is fixed to 11111 and carries no operand.
    @_optimize(speed)
    static func decodeSetGO(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let stage = Int((encoding >> 14) & 0x3)
        if stage == 0b11 {
            return .undefined(at: address, encoding: encoding)
        }
        let rD = UInt8(encoding & 0x1F)
        let rN = UInt8((encoding >> 5) & 0x1F)
        if rD == 31 || rD == rN {
            return .undefined(at: address, encoding: encoding)
        }
        let mnemonic = setgoMnemonics[stage][Int((encoding >> 12) & 0x3)]
        let xd = RegisterRef.x(rD)
        let xn = lsGprOperand(encoding: rN, width: .x64, form: .zrOrGeneral)
        var regs = lsInsertingNonZero(reg: xd, into: .empty)
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
            operandCount: sink.emit(.register(xd), .register(xn)),
        )
    }

    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (encoding >> 30) != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let o0 = UInt8((encoding >> 26) & 1)
        let szStage = UInt8((encoding >> 22) & 0x3)
        let rD = UInt8(encoding & 0x1F)
        let rField9_5 = UInt8((encoding >> 5) & 0x1F)
        let rField20_16 = UInt8((encoding >> 16) & 0x1F)

        if rD == rField9_5 || rD == rField20_16 || rField9_5 == rField20_16 {
            return .undefined(at: address, encoding: encoding)
        }
        if rD == 31 {
            return .undefined(at: address, encoding: encoding)
        }

        if szStage == 0b11 {
            return decodeSet(
                encoding: encoding, address: address, o0: o0,
                rD: rD, rN: rField9_5, rS: rField20_16, &sink,
            )
        }
        return decodeCopy(
            encoding: encoding, address: address, o0: o0, stage: szStage,
            rD: rD, rN: rField9_5, rS: rField20_16, &sink,
        )
    }

    /// CPY/CPYF: `[Xd]!, [Xs]!, Xn!`. Xs (the source-address register) is also
    /// restricted from the ZR encoding.
    @_optimize(speed)
    private static func decodeCopy(
        encoding: UInt32, address: UInt64, o0: UInt8, stage: UInt8,
        rD: UInt8, rN: UInt8, rS: UInt8, _ sink: inout OperandSink,
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
            operandCount: sink.emit(.register(xd), .register(xs), .register(xn)),
        )
    }

    /// SET/SETG: `[Xd]!, Xn!, Xs`.
    @_optimize(speed)
    private static func decodeSet(
        encoding: UInt32, address: UInt64, o0: UInt8,
        rD: UInt8, rN: UInt8, rS: UInt8, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let stage = UInt8((encoding >> 14) & 0x3)
        if stage == 0b11 {
            return .undefined(at: address, encoding: encoding)
        }
        let options = Int((encoding >> 12) & 0x3)
        let row = Int(o0) * 3 + Int(stage)
        let mnemonic = setMnemonics[row][options]

        let xd = RegisterRef.x(rD)
        let xn = lsGprOperand(encoding: rN, width: .x64, form: .zrOrGeneral)
        let xs = lsGprOperand(encoding: rS, width: .x64, form: .zrOrGeneral)

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
            operandCount: sink.emit(.register(xd), .register(xn), .register(xs)),
        )
    }
}
