// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum AdvSIMDLoadStoreMultipleStructuresDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let postIndexed = ((encoding >> 23) & 1) == 1
        let L = UInt8((encoding >> 22) & 0x1)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let opcode = UInt8((encoding >> 12) & 0xF)
        let size = UInt8((encoding >> 10) & 0x3)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        if (encoding >> 31) & 1 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        if (encoding >> 21) & 1 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        if !postIndexed, Rm != 0 {
            return .undefined(at: address, encoding: encoding)
        }

        let arrangement = arrangementFromSizeQ(size: size, Q: Q)
        guard let layout = layoutFor(opcode: opcode, L: L) else {
            return .undefined(at: address, encoding: encoding)
        }
        if layout.selem > 1, arrangement == .d1 {
            return .undefined(at: address, encoding: encoding)
        }
        let totalRegs = layout.selem * layout.rpt
        let totalBytes = UInt64(totalRegs) * 8 * (1 + UInt64(Q))

        let operandMark = sink.mark
        var listReads: RegisterSet = .empty
        var listWrites: RegisterSet = .empty
        for i in 0 ..< Int(totalRegs) {
            let r = (Rt &+ UInt8(i)) & 0x1F
            sink.append(simdfpVectorOperand(r, arrangement: arrangement))
            if L == 1 {
                listWrites = simdfpInsertingVector(r, into: listWrites)
            } else {
                listReads = simdfpInsertingVector(r, into: listReads)
            }
        }

        let rnRef = simdfpGprOperand(encoding: Rn, width: .x64, spOrGeneral: true)
        var memOperand: MemoryOperand
        if postIndexed {
            if Rm == 0b11111 {
                memOperand = MemoryOperand(
                    base: .register(rnRef), index: nil,
                    displacement: Int64(totalBytes),
                    extend: .none, shift: 0, writeback: .postIndex,
                )
            } else {
                let rmRef = simdfpGprOperand(encoding: Rm, width: .x64, spOrGeneral: false)
                memOperand = MemoryOperand(
                    base: .register(rnRef), index: rmRef,
                    displacement: 0,
                    extend: .none, shift: 0, writeback: .postIndex,
                )
            }
        } else {
            memOperand = MemoryOperand(
                base: .register(rnRef), index: nil, displacement: 0,
                extend: .none, shift: 0, writeback: .none,
            )
        }
        sink.append(.memory(memOperand))

        var reads = listReads
        reads = simdfpInsertingNonZeroGPR(reg: rnRef, into: reads)
        var writes = listWrites
        if postIndexed {
            writes = simdfpInsertingNonZeroGPR(reg: rnRef, into: writes)
        }
        if postIndexed, Rm != 0b11111 {
            let rmRef = simdfpGprOperand(encoding: Rm, width: .x64, spOrGeneral: false)
            reads = simdfpInsertingNonZeroGPR(reg: rmRef, into: reads)
        }

        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: layout.mnemonic,
            semanticReads: reads,
            semanticWrites: writes,
            branchClass: .none,
            memoryAccess: L == 1 ? .load : .store,
            memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.count(since: operandMark),
        )
    }

    private struct LoadStoreLayout {
        let mnemonic: Mnemonic
        let selem: UInt8
        let rpt: UInt8
    }

    @inline(__always)
    @_effects(readonly)
    private static func layoutFor(opcode: UInt8, L: UInt8) -> LoadStoreLayout? {
        let isLoad = L == 1
        switch opcode {
        case 0b0000: return .init(mnemonic: isLoad ? .ld4 : .st4, selem: 4, rpt: 1)
        case 0b0010: return .init(mnemonic: isLoad ? .ld1 : .st1, selem: 1, rpt: 4)
        case 0b0100: return .init(mnemonic: isLoad ? .ld3 : .st3, selem: 3, rpt: 1)
        case 0b0110: return .init(mnemonic: isLoad ? .ld1 : .st1, selem: 1, rpt: 3)
        case 0b0111: return .init(mnemonic: isLoad ? .ld1 : .st1, selem: 1, rpt: 1)
        case 0b1000: return .init(mnemonic: isLoad ? .ld2 : .st2, selem: 2, rpt: 1)
        case 0b1010: return .init(mnemonic: isLoad ? .ld1 : .st1, selem: 1, rpt: 2)
        default: return nil
        }
    }
}
