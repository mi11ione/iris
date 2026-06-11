// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Load register (literal) decode. PC-relative loads.
// Encoding shell bits[29:24] = 011000, V=0. opc[31:30] selects the
// instruction: 00 = LDR (32-bit Wt), 01 = LDR (64-bit Xt),
// 10 = LDRSW (sign-extend 32→64 into Xt), 11 = PRFM literal.
//
// Operand shape: register Rt (or .prefetchOperation for PRFM) followed by
// .memory(.pc, displacement: signExtend19(imm19) << 2) — the typed PC-base
// MemoryOperand carries the PC-relative target so consumers can compute
// the absolute literal address from the record's source address.

enum LoadLiteralDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let opc = UInt8((encoding >> 30) & 0x3)
        let imm19 = (encoding >> 5) & 0x7FFFF
        let Rt = UInt8(encoding & 0x1F)

        let displacement = lsSignExtendImm19(imm19) << 2

        let mnemonic: Mnemonic
        let rtOperand: Operand
        let memoryAccess: MemoryAccess
        var writes: RegisterSet = .empty

        switch opc {
        case 0b00:
            // LDR Wt, label
            mnemonic = .ldr
            let rt = lsGprOperand(encoding: Rt, width: .w32, form: .zrOrGeneral)
            rtOperand = .register(rt)
            writes = lsInsertingNonZero(reg: rt, into: .empty)
            memoryAccess = .load
        case 0b01:
            // LDR Xt, label
            mnemonic = .ldr
            let rt = lsGprOperand(encoding: Rt, width: .x64, form: .zrOrGeneral)
            rtOperand = .register(rt)
            writes = lsInsertingNonZero(reg: rt, into: .empty)
            memoryAccess = .load
        case 0b10:
            // LDRSW Xt, label
            mnemonic = .ldrsw
            let rt = lsGprOperand(encoding: Rt, width: .x64, form: .zrOrGeneral)
            rtOperand = .register(rt)
            writes = lsInsertingNonZero(reg: rt, into: .empty)
            memoryAccess = .load
        // opc ∈ {00,01,10,11} all enumerated; 0b11 (PRFM literal) is `default`.
        default:
            // PRFM <prfop>, label — Rt slot carries the prefetch operation.
            mnemonic = .prfm
            rtOperand = .prefetchOperation(PrefetchOperation(rawValue: Rt))
            memoryAccess = .prefetch
        }

        let memOperand: Operand = .memory(MemoryOperand(
            base: .pc,
            index: nil,
            displacement: displacement,
            extend: .none,
            shift: 0,
            writeback: .none,
        ))

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: .empty,
            semanticWrites: writes,
            branchClass: .none,
            memoryAccess: memoryAccess,
            memoryOrdering: [],
            flagEffect: .none,
            category: .loadsAndStores,
            operands: [rtOperand, memOperand],
        )
    }
}
