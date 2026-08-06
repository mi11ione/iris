// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum AdvSIMDLoadStoreSingleStructureDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let postIndexed = ((encoding >> 23) & 1) == 1
        let L = UInt8((encoding >> 22) & 0x1)
        let R = UInt8((encoding >> 21) & 0x1)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let opcode = UInt8((encoding >> 13) & 0x7)
        let S = UInt8((encoding >> 12) & 0x1)
        let size = UInt8((encoding >> 10) & 0x3)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        if (encoding >> 31) & 1 != 0 {
            return .undefined(at: address, encoding: encoding)
        }

        if (encoding >> 23) & 1 == 0,
           (encoding >> 16) & 0x1F == 0b00001,
           (encoding >> 21) & 1 == 0,
           (encoding >> 13) & 0x7 == 0b100,
           (encoding >> 12) & 1 == 0,
           (encoding >> 10) & 0x3 == 0b01
        {
            let isLoad = (encoding >> 22) & 1 == 1
            let elementIndex = UInt8((encoding >> 30) & 1)
            let rtNum = UInt8(encoding & 0x1F)
            let rnNum = UInt8((encoding >> 5) & 0x1F)
            let rnRef = simdfpGprOperand(encoding: rnNum, width: .x64, spOrGeneral: true)
            let element = simdfpElementOperand(rtNum, elementSize: .d, index: elementIndex)
            let mem = MemoryOperand(
                base: .register(rnRef), index: nil, displacement: 0,
                extend: .none, shift: 0, writeback: .none,
            )
            var reads = simdfpInsertingNonZeroGPR(reg: rnRef, into: .empty)
            var writes: RegisterSet = .empty
            if isLoad {
                reads = simdfpInsertingVector(rtNum, into: reads)
                writes = simdfpInsertingVector(rtNum, into: writes)
            } else {
                reads = simdfpInsertingVector(rtNum, into: reads)
            }
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: isLoad ? .ldap1 : .stl1,
                semanticReads: reads, semanticWrites: writes,
                branchClass: .none,
                memoryAccess: isLoad ? .load : .store,
                memoryOrdering: isLoad ? [.acquire] : [.release],
                flagEffect: .none, category: .simdAndFP,
                operandCount: sink.emit(element, .memory(mem)),
            )
        }

        if !postIndexed, Rm != 0 {
            return .undefined(at: address, encoding: encoding)
        }

        guard let info = singleStructLayout(opcode: opcode, L: L, R: R) else {
            return .undefined(at: address, encoding: encoding)
        }
        let isReplicate = info.isReplicate
        if isReplicate, S != 0 {
            return .undefined(at: address, encoding: encoding)
        }

        let elementSize: ScalarSize
        let index: UInt8
        if isReplicate {
            elementSize = scalarElementFromSize(size)
            index = 0
        } else {
            switch (opcode >> 1) & 0x3 {
            case 0b00:
                elementSize = .b
                index = (Q << 3) | (S << 2) | size
            case 0b01:
                if (size & 1) != 0 {
                    return .undefined(at: address, encoding: encoding)
                }
                elementSize = .h
                index = (Q << 2) | (S << 1) | (size >> 1)
            default:
                if (size & 0b10) != 0 {
                    return .undefined(at: address, encoding: encoding)
                }
                if (size & 1) == 0 {
                    elementSize = .s
                    index = (Q << 1) | S
                } else {
                    if S != 0 {
                        return .undefined(at: address, encoding: encoding)
                    }
                    elementSize = .d
                    index = Q
                }
            }
        }

        let operandMark = sink.mark
        var listReads: RegisterSet = .empty
        var listWrites: RegisterSet = .empty
        for i in 0 ..< Int(info.selem) {
            let r = (Rt &+ UInt8(i)) & 0x1F
            if isReplicate {
                let arrangement = arrangementFromSizeQ(size: size, Q: Q)
                sink.append(simdfpVectorOperand(r, arrangement: arrangement))
            } else {
                sink.append(simdfpElementOperand(r, elementSize: elementSize, index: index))
            }
            if L == 1 {
                listWrites = simdfpInsertingVector(r, into: listWrites)
                if !isReplicate {
                    listReads = simdfpInsertingVector(r, into: listReads)
                }
            } else {
                listReads = simdfpInsertingVector(r, into: listReads)
            }
        }

        let rnRef = simdfpGprOperand(encoding: Rn, width: .x64, spOrGeneral: true)
        let elementBytes = UInt64(elementSize.byteWidth)
        let increment = isReplicate
            ? elementBytes * UInt64(info.selem)
            : elementBytes * UInt64(info.selem)
        var memOperand: MemoryOperand
        if postIndexed {
            if Rm == 0b11111 {
                memOperand = MemoryOperand(
                    base: .register(rnRef), index: nil,
                    displacement: Int64(increment),
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
            mnemonic: info.mnemonic,
            semanticReads: reads,
            semanticWrites: writes,
            branchClass: .none,
            memoryAccess: L == 1 ? .load : .store,
            memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.count(since: operandMark),
        )
    }

    private struct SingleStructInfo {
        let mnemonic: Mnemonic
        let selem: UInt8
        let isReplicate: Bool
    }

    @inline(__always)
    @_effects(readonly)
    private static func singleStructLayout(
        opcode: UInt8, L: UInt8, R: UInt8,
    ) -> SingleStructInfo? {
        let isLoad = L == 1
        switch opcode {
        case 0b000:
            let selem: UInt8 = R == 0 ? 1 : 2
            return .init(
                mnemonic: isLoad ? loadMnemonic(selem: selem) : storeMnemonic(selem: selem),
                selem: selem, isReplicate: false,
            )
        case 0b001:
            let selem: UInt8 = R == 0 ? 3 : 4
            return .init(
                mnemonic: isLoad ? loadMnemonic(selem: selem) : storeMnemonic(selem: selem),
                selem: selem, isReplicate: false,
            )
        case 0b010, 0b100:
            let selem: UInt8 = R == 0 ? 1 : 2
            return .init(
                mnemonic: isLoad ? loadMnemonic(selem: selem) : storeMnemonic(selem: selem),
                selem: selem, isReplicate: false,
            )
        case 0b011, 0b101:
            let selem: UInt8 = R == 0 ? 3 : 4
            return .init(
                mnemonic: isLoad ? loadMnemonic(selem: selem) : storeMnemonic(selem: selem),
                selem: selem, isReplicate: false,
            )
        case 0b110:
            if !isLoad { return nil }
            let selem: UInt8 = R == 0 ? 1 : 2
            return .init(mnemonic: replicateMnemonic(selem: selem), selem: selem, isReplicate: true)
        default:
            if !isLoad { return nil }
            let selem: UInt8 = R == 0 ? 3 : 4
            return .init(mnemonic: replicateMnemonic(selem: selem), selem: selem, isReplicate: true)
        }
    }

    @inline(__always)
    @_effects(readonly)
    private static func loadMnemonic(selem: UInt8) -> Mnemonic {
        switch selem {
        case 1: .ld1
        case 2: .ld2
        case 3: .ld3
        default: .ld4
        }
    }

    @inline(__always)
    @_effects(readonly)
    private static func storeMnemonic(selem: UInt8) -> Mnemonic {
        switch selem {
        case 1: .st1
        case 2: .st2
        case 3: .st3
        default: .st4
        }
    }

    @inline(__always)
    @_effects(readonly)
    private static func replicateMnemonic(selem: UInt8) -> Mnemonic {
        switch selem {
        case 1: .ld1r
        case 2: .ld2r
        case 3: .ld3r
        default: .ld4r
        }
    }
}
