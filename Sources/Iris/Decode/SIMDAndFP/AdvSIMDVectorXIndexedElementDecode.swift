// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum AdvSIMDVectorXIndexedElementDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let U = UInt8((encoding >> 29) & 0x1)
        let size = UInt8((encoding >> 22) & 0x3)
        let L = UInt8((encoding >> 21) & 0x1)
        let M = UInt8((encoding >> 20) & 0x1)
        let Rm = UInt8((encoding >> 16) & 0xF)
        let opcode = UInt8((encoding >> 12) & 0xF)
        let H = UInt8((encoding >> 11) & 0x1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        if let dot = decodeDot(encoding: encoding, address: address, &sink) {
            return dot
        }
        if let fmlal = decodeFmlal(encoding: encoding, address: address, &sink) {
            return fmlal
        }
        if let fcmla = decodeFcmla(encoding: encoding, address: address, &sink) {
            return fcmla
        }

        let elementReg = (M << 4) | Rm
        let isFPFamily = switch opcode {
        case 0b0001, 0b0101, 0b1001:
            true
        default:
            false
        }

        if isFPFamily {
            return decodeFPFamily(
                encoding: encoding, address: address,
                Q: Q, U: U, size: size, L: L, H: H,
                Rm: elementReg, opcode: opcode, Rn: Rn, Rd: Rd, &sink,
            )
        }
        return decodeIntFamily(
            encoding: encoding, address: address,
            Q: Q, U: U, size: size, L: L, H: H,
            Rm: elementReg, opcode: opcode, Rn: Rn, Rd: Rd, &sink,
        )
    }

    /// Dot-product by-element forms (SDOT/UDOT/USDOT/SUDOT/BFDOT).
    @inline(__always)
    @_optimize(speed)
    private static func decodeDot(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft? {
        let Q = UInt8((encoding >> 30) & 1)
        let U = UInt8((encoding >> 29) & 1)
        let size = UInt8((encoding >> 22) & 3)
        let L = UInt8((encoding >> 21) & 1)
        let M = UInt8((encoding >> 20) & 1)
        let Rm = UInt8((encoding >> 16) & 0xF)
        let opcode = UInt8((encoding >> 12) & 0xF)
        let H = UInt8((encoding >> 11) & 1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        let m: Mnemonic
        let srcElement: ScalarSize
        let groupCount: UInt8
        var dstHalf = false
        switch (U, opcode, size) {
        case (0, 0b1110, 0b10): m = .sdot; srcElement = .b; groupCount = 4
        case (1, 0b1110, 0b10): m = .udot; srcElement = .b; groupCount = 4
        case (0, 0b1111, 0b10): m = .usdot; srcElement = .b; groupCount = 4
        case (0, 0b1111, 0b00): m = .sudot; srcElement = .b; groupCount = 4
        case (0, 0b1111, 0b01): m = .bfdot; srcElement = .h; groupCount = 2
        case (0, 0b1001, 0b01): m = .fdot; srcElement = .h; groupCount = 2
        case (0, 0b0000, 0b00): m = .fdot; srcElement = .b; groupCount = 4
        case (0, 0b0000, 0b01): m = .fdot; srcElement = .b; groupCount = 2; dstHalf = true
        default: return nil
        }
        let dstArrangement: VectorArrangement = dstHalf
            ? (Q == 1 ? .h8 : .h4)
            : (Q == 1 ? .s4 : .s2)
        let srcArrangement: VectorArrangement = srcElement == .b
            ? (Q == 1 ? .b16 : .b8)
            : (Q == 1 ? .h8 : .h4)
        let rmReg: UInt8
        let index: UInt8
        if groupCount == 2, srcElement == .b {
            rmReg = Rm
            index = (H << 2) | (L << 1) | M
        } else {
            rmReg = (M << 4) | Rm
            index = (H << 1) | L
        }
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(rmReg, into: reads)
        reads = simdfpInsertingVector(Rd, into: reads)
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: m,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.emit(simdfpVectorOperand(Rd, arrangement: dstArrangement), simdfpVectorOperand(Rn, arrangement: srcArrangement), simdfpElementGroupOperand(rmReg, elementSize: srcElement, count: groupCount, index: index)),
        )
    }

    /// FP8/BF16 FMLAL/FMLALL by-element.
    @inline(__always)
    @_optimize(speed)
    private static func decodeFmlal(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft? {
        let Q = UInt8((encoding >> 30) & 1)
        let U = UInt8((encoding >> 29) & 1)
        let size = UInt8((encoding >> 22) & 3)
        let L = UInt8((encoding >> 21) & 1)
        let M = UInt8((encoding >> 20) & 1)
        let Rm = UInt8((encoding >> 16) & 0xF)
        let opcode = UInt8((encoding >> 12) & 0xF)
        let H = UInt8((encoding >> 11) & 1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)
        let hlm = (H << 2) | (L << 1) | M

        let m: Mnemonic
        let dstArr: VectorArrangement
        let srcArr: VectorArrangement
        let elemSize: ScalarSize
        switch (U, opcode, size) {
        case (0, 0b0000, 0b11):
            m = Q == 1 ? .fmlalt : .fmlalb
            dstArr = .h8; srcArr = .b16; elemSize = .b
        case (0, 0b1111, 0b11):
            m = Q == 1 ? .bfmlalt : .bfmlalb
            dstArr = .s4; srcArr = .h8; elemSize = .h
        case (1, 0b1000, 0b00):
            m = Q == 1 ? .fmlalltb : .fmlallbb
            dstArr = .s4; srcArr = .b16; elemSize = .b
        case (1, 0b1000, 0b01):
            m = Q == 1 ? .fmlalltt : .fmlallbt
            dstArr = .s4; srcArr = .b16; elemSize = .b
        case (0, 0b0000, 0b10):
            m = .fmlal
            dstArr = Q == 1 ? .s4 : .s2; srcArr = Q == 1 ? .h4 : .h2; elemSize = .h
        case (0, 0b0100, 0b10):
            m = .fmlsl
            dstArr = Q == 1 ? .s4 : .s2; srcArr = Q == 1 ? .h4 : .h2; elemSize = .h
        case (1, 0b1000, 0b10):
            m = .fmlal2
            dstArr = Q == 1 ? .s4 : .s2; srcArr = Q == 1 ? .h4 : .h2; elemSize = .h
        case (1, 0b1100, 0b10):
            m = .fmlsl2
            dstArr = Q == 1 ? .s4 : .s2; srcArr = Q == 1 ? .h4 : .h2; elemSize = .h
        default:
            return nil
        }
        let elemReg: UInt8
        let index: UInt8
        if elemSize == .b {
            elemReg = Rm & 0x7
            index = (hlm << 1) | ((Rm >> 3) & 1)
        } else {
            elemReg = Rm
            index = hlm
        }
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(elemReg, into: reads)
        reads = simdfpInsertingVector(Rd, into: reads)
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: m,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.emit(simdfpVectorOperand(Rd, arrangement: dstArr), simdfpVectorOperand(Rn, arrangement: srcArr), simdfpElementOperand(elemReg, elementSize: elemSize, index: index)),
        )
    }

    @inline(__always)
    @_optimize(speed)
    private static func decodeFPFamily(
        encoding: UInt32, address: UInt64,
        Q: UInt8, U: UInt8, size: UInt8, L: UInt8, H: UInt8,
        Rm: UInt8, opcode: UInt8, Rn: UInt8, Rd: UInt8, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let m: Mnemonic
        switch (U, opcode) {
        case (0, 0b0001): m = .fmla
        case (0, 0b0101): m = .fmls
        case (0, 0b1001): m = .fmul
        case (1, 0b1001): m = .fmulx
        default: return .undefined(at: address, encoding: encoding)
        }
        let mBit = (Rm >> 4) & 1
        let arrangement: VectorArrangement
        let elementSize: ScalarSize
        let index: UInt8
        let rmReg: UInt8
        switch (size, Q) {
        case (0b00, 0): arrangement = .h4; elementSize = .h; index = (H << 2) | (L << 1) | mBit; rmReg = Rm & 0xF
        case (0b00, 1): arrangement = .h8; elementSize = .h; index = (H << 2) | (L << 1) | mBit; rmReg = Rm & 0xF
        case (0b10, 0): arrangement = .s2; elementSize = .s; index = (H << 1) | L; rmReg = Rm
        case (0b10, 1): arrangement = .s4; elementSize = .s; index = (H << 1) | L; rmReg = Rm
        case (0b11, 1) where L == 0: arrangement = .d2; elementSize = .d; index = H; rmReg = Rm
        default: return .undefined(at: address, encoding: encoding)
        }
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(rmReg, into: reads)
        if simdFPDestinationReadsItself(m) {
            reads = simdfpInsertingVector(Rd, into: reads)
        }
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: m,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.emit(simdfpVectorOperand(Rd, arrangement: arrangement), simdfpVectorOperand(Rn, arrangement: arrangement), simdfpElementOperand(rmReg, elementSize: elementSize, index: index)),
        )
    }

    @inline(__always)
    @_optimize(speed)
    private static func decodeIntFamily(
        encoding: UInt32, address: UInt64,
        Q: UInt8, U: UInt8, size: UInt8, L: UInt8, H: UInt8,
        Rm: UInt8, opcode: UInt8, Rn: UInt8, Rd: UInt8, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let elementSize: ScalarSize
        let srcArrangement: VectorArrangement
        switch (size, Q) {
        case (0b01, 0): elementSize = .h; srcArrangement = .h4
        case (0b01, 1): elementSize = .h; srcArrangement = .h8
        case (0b10, 0): elementSize = .s; srcArrangement = .s2
        case (0b10, 1): elementSize = .s; srcArrangement = .s4
        default: return .undefined(at: address, encoding: encoding)
        }
        let M_bit = (Rm >> 4) & 1
        let index: UInt8
            = switch elementSize
        {
        case .h: (H << 2) | (L << 1) | M_bit
        default: (H << 1) | L
        }
        let rmReg = elementSize == .h ? Rm & 0xF : Rm

        let m: Mnemonic
        let isLengthening: Bool
        switch (U, opcode) {
        case (0, 0b0010): m = .smlal; isLengthening = true
        case (0, 0b0110): m = .smlsl; isLengthening = true
        case (0, 0b1010): m = .smull; isLengthening = true
        case (0, 0b1011): m = .sqdmull; isLengthening = true
        case (0, 0b0011): m = .sqdmlal; isLengthening = true
        case (0, 0b0111): m = .sqdmlsl; isLengthening = true
        case (0, 0b1000): m = .mul; isLengthening = false
        case (0, 0b1100): m = .sqdmulh; isLengthening = false
        case (0, 0b1101): m = .sqrdmulh; isLengthening = false
        case (1, 0b0000): m = .mla; isLengthening = false
        case (1, 0b0100): m = .mls; isLengthening = false
        case (1, 0b0010): m = .umlal; isLengthening = true
        case (1, 0b0110): m = .umlsl; isLengthening = true
        case (1, 0b1010): m = .umull; isLengthening = true
        case (1, 0b1101): m = .sqrdmlah; isLengthening = false
        case (1, 0b1111): m = .sqrdmlsh; isLengthening = false
        default: return .undefined(at: address, encoding: encoding)
        }

        let dstArrangement: VectorArrangement = if isLengthening {
            switch elementSize {
            case .h: .s4
            default: .d2
            }
        } else {
            srcArrangement
        }

        let finalMnemonic: Mnemonic = isLengthening && Q == 1 ? lengtheningUpperHalf(m) : m
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(rmReg, into: reads)
        if simdFPDestinationReadsItself(finalMnemonic) {
            reads = simdfpInsertingVector(Rd, into: reads)
        }
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: finalMnemonic,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.emit(simdfpVectorOperand(Rd, arrangement: dstArrangement), simdfpVectorOperand(Rn, arrangement: srcArrangement), simdfpElementOperand(rmReg, elementSize: elementSize, index: index)),
        )
    }

    /// FCMLA by-element (U=1, opcode = 0:rot:0:1, so 0001/0011/0101/0111).
    @inline(__always)
    @_optimize(speed)
    private static func decodeFcmla(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft? {
        guard (encoding >> 29) & 1 == 1 else { return nil }
        let opcode = UInt8((encoding >> 12) & 0xF)
        switch opcode {
        case 0b0001, 0b0011, 0b0101, 0b0111: break
        default: return nil
        }
        let Q = UInt8((encoding >> 30) & 1)
        let size = UInt8((encoding >> 22) & 3)
        let L = UInt8((encoding >> 21) & 1)
        let M = UInt8((encoding >> 20) & 1)
        let Rm = UInt8((encoding >> 16) & 0xF)
        let H = UInt8((encoding >> 11) & 1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)
        let rot = Int64((opcode >> 1) & 0b11) * 90

        let elementSize: ScalarSize
        let arrangement: VectorArrangement
        let index: UInt8
        switch (size, Q) {
        case (0b01, 0):
            if H != 0 { return nil }
            elementSize = .h; arrangement = .h4; index = L
        case (0b01, 1): elementSize = .h; arrangement = .h8; index = (H << 1) | L
        case (0b10, 1):
            if L != 0 { return nil }
            elementSize = .s; arrangement = .s4; index = H
        default: return nil
        }
        let rmReg = (M << 4) | Rm
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(rmReg, into: reads)
        reads = simdfpInsertingVector(Rd, into: reads)
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: .fcmla,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.emit(simdfpVectorOperand(Rd, arrangement: arrangement), simdfpVectorOperand(Rn, arrangement: arrangement), simdfpElementOperand(rmReg, elementSize: elementSize, index: index), .immediate(value: rot, width: 16)),
        )
    }

    /// Maps a lengthening by-element base mnemonic to its upper-half ("2")
    /// form.
    @inline(__always)
    @_effects(readonly)
    private static func lengtheningUpperHalf(_ m: Mnemonic) -> Mnemonic {
        switch m {
        case .smlal: .smlal2
        case .smlsl: .smlsl2
        case .smull: .smull2
        case .sqdmlal: .sqdmlal2
        case .sqdmlsl: .sqdmlsl2
        case .sqdmull: .sqdmull2
        case .umlal: .umlal2
        case .umlsl: .umlsl2
        default: .umull2
        }
    }
}
