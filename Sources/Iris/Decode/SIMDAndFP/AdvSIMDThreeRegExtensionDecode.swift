// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum AdvSIMDThreeRegExtensionDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let U = UInt8((encoding >> 29) & 0x1)
        let size = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let op4 = UInt8((encoding >> 11) & 0xF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        guard let r = mnemonicAndShape(U: U, size: size, op4: op4, Q: Q) else {
            return .undefined(at: address, encoding: encoding)
        }
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(Rm, into: reads)
        if r.accumulates {
            reads = simdfpInsertingVector(Rd, into: reads)
        }
        let operandMark = sink.mark
        _ = sink.emit(simdfpVectorOperand(Rd, arrangement: r.dstArrangement), simdfpVectorOperand(Rn, arrangement: r.srcArrangement), simdfpVectorOperand(Rm, arrangement: r.srcArrangement))
        if let rot = r.rotation {
            sink.append(.immediate(value: rot, width: 16))
        }
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: r.mnemonic,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.count(since: operandMark),
        )
    }

    private struct ResolvedShape {
        let mnemonic: Mnemonic
        let dstArrangement: VectorArrangement
        let srcArrangement: VectorArrangement
        let rotation: Int64?
        let accumulates: Bool
    }

    @inline(__always)
    @_effects(readonly)
    private static func mnemonicAndShape(U: UInt8, size: UInt8, op4: UInt8, Q: UInt8) -> ResolvedShape? {
        if U == 1 {
            let arr: VectorArrangement? = switch (size, Q) {
            case (1, 0): .h4
            case (1, 1): .h8
            case (2, 0): .s2
            case (2, 1): .s4
            case (3, 1): .d2
            default: nil
            }
            if let a = arr {
                switch op4 {
                case 8, 9, 10, 11:
                    return ResolvedShape(mnemonic: .fcmla, dstArrangement: a, srcArrangement: a,
                                         rotation: Int64(op4 & 0b11) * 90, accumulates: true)
                case 12:
                    return ResolvedShape(mnemonic: .fcadd, dstArrangement: a, srcArrangement: a,
                                         rotation: 90, accumulates: false)
                case 14:
                    return ResolvedShape(mnemonic: .fcadd, dstArrangement: a, srcArrangement: a,
                                         rotation: 270, accumulates: false)
                case 0 where size == 1 || size == 2:
                    return ResolvedShape(mnemonic: .sqrdmlah, dstArrangement: a, srcArrangement: a,
                                         rotation: nil, accumulates: true)
                case 1 where size == 1 || size == 2:
                    return ResolvedShape(mnemonic: .sqrdmlsh, dstArrangement: a, srcArrangement: a,
                                         rotation: nil, accumulates: true)
                default: break
                }
            }
        }

        let dotDst: VectorArrangement = Q == 1 ? .s4 : .s2
        let byteSrc: VectorArrangement = Q == 1 ? .b16 : .b8
        let halfSrc: VectorArrangement = Q == 1 ? .h8 : .h4
        switch (U, size, op4) {
        case (0, 2, 2): return ResolvedShape(mnemonic: .sdot, dstArrangement: dotDst, srcArrangement: byteSrc, rotation: nil, accumulates: true)
        case (1, 2, 2): return ResolvedShape(mnemonic: .udot, dstArrangement: dotDst, srcArrangement: byteSrc, rotation: nil, accumulates: true)
        case (0, 2, 3): return ResolvedShape(mnemonic: .usdot, dstArrangement: dotDst, srcArrangement: byteSrc, rotation: nil, accumulates: true)
        case (1, 1, 15): return ResolvedShape(mnemonic: .bfdot, dstArrangement: dotDst, srcArrangement: halfSrc, rotation: nil, accumulates: true)
        case (0, 0, 15): return ResolvedShape(mnemonic: .fdot, dstArrangement: dotDst, srcArrangement: byteSrc, rotation: nil, accumulates: true)
        case (0, 1, 15): return ResolvedShape(mnemonic: .fdot, dstArrangement: Q == 1 ? .h8 : .h4, srcArrangement: byteSrc, rotation: nil, accumulates: true)
        case (0, 2, 4) where Q == 1: return ResolvedShape(mnemonic: .smmla, dstArrangement: .s4, srcArrangement: .b16, rotation: nil, accumulates: true)
        case (1, 2, 4) where Q == 1: return ResolvedShape(mnemonic: .ummla, dstArrangement: .s4, srcArrangement: .b16, rotation: nil, accumulates: true)
        case (0, 2, 5) where Q == 1: return ResolvedShape(mnemonic: .usmmla, dstArrangement: .s4, srcArrangement: .b16, rotation: nil, accumulates: true)
        case (1, 1, 13) where Q == 1: return ResolvedShape(mnemonic: .bfmmla, dstArrangement: .s4, srcArrangement: .h8, rotation: nil, accumulates: true)
        case (0, 1, 13) where Q == 1: return ResolvedShape(mnemonic: .fmmla, dstArrangement: .s4, srcArrangement: .h8, rotation: nil, accumulates: true)
        case (0, 3, 13) where Q == 1: return ResolvedShape(mnemonic: .fmmla, dstArrangement: .h8, srcArrangement: .h8, rotation: nil, accumulates: true)
        case (1, 0, 13) where Q == 1: return ResolvedShape(mnemonic: .fmmla, dstArrangement: .h8, srcArrangement: .b16, rotation: nil, accumulates: true)
        case (1, 2, 13) where Q == 1: return ResolvedShape(mnemonic: .fmmla, dstArrangement: .s4, srcArrangement: .b16, rotation: nil, accumulates: true)
        case (0, 2, 15): return ResolvedShape(mnemonic: .fdot, dstArrangement: dotDst, srcArrangement: halfSrc, rotation: nil, accumulates: true)
        case (1, 3, 15): return ResolvedShape(mnemonic: Q == 1 ? .bfmlalt : .bfmlalb, dstArrangement: .s4, srcArrangement: .h8, rotation: nil, accumulates: true)
        case (0, 3, 15): return ResolvedShape(mnemonic: Q == 1 ? .fmlalt : .fmlalb, dstArrangement: .h8, srcArrangement: .b16, rotation: nil, accumulates: true)
        case (0, 0, 8): return ResolvedShape(mnemonic: Q == 1 ? .fmlalltb : .fmlallbb, dstArrangement: .s4, srcArrangement: .b16, rotation: nil, accumulates: true)
        case (0, 1, 8): return ResolvedShape(mnemonic: Q == 1 ? .fmlalltt : .fmlallbt, dstArrangement: .s4, srcArrangement: .b16, rotation: nil, accumulates: true)
        case (0, 0, 14): return ResolvedShape(mnemonic: Q == 1 ? .fcvtn2 : .fcvtn, dstArrangement: Q == 1 ? .b16 : .b8, srcArrangement: .s4, rotation: nil, accumulates: false)
        case (0, 1, 14): return ResolvedShape(mnemonic: .fcvtn, dstArrangement: Q == 1 ? .b16 : .b8, srcArrangement: Q == 1 ? .h8 : .h4, rotation: nil, accumulates: false)
        default: return nil
        }
    }
}
