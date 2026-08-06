// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum AdvSIMDTwoRegMiscDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let U = UInt8((encoding >> 29) & 0x1)
        let size = UInt8((encoding >> 22) & 0x3)
        let opcode = UInt8((encoding >> 12) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        let bit23 = (size >> 1) & 1
        if opcode >= 0b11000 || (opcode >= 0b01100 && opcode <= 0b01111 && bit23 == 1) {
            return decodeFPFamily(
                encoding: encoding, address: address,
                Q: Q, U: U, size: size, opcode: opcode, Rn: Rn, Rd: Rd, &sink,
            )
        }

        if opcode == 0b10110 || opcode == 0b10111 {
            return decodeFPConvertNarrowLong(
                encoding: encoding, address: address,
                Q: Q, U: U, size: size, opcode: opcode, Rn: Rn, Rd: Rd, &sink,
            )
        }

        let mnemonicAndShape = intMnemonicAndDstShape(
            U: U, opcode: opcode, size: size, Q: Q,
        )
        guard let (m, dstArrangement, srcArrangement) = mnemonicAndShape else {
            return .undefined(at: address, encoding: encoding)
        }
        let destReadsItself = simdFPDestinationReadsItself(m)
        var reads = simdfpInsertingVector(Rn, into: .empty)
        if destReadsItself {
            reads = simdfpInsertingVector(Rd, into: reads)
        }

        let zeroForm = isZeroCompareForm(U: U, opcode: opcode)
        let operandMark = sink.mark
        sink.append(simdfpVectorOperand(Rd, arrangement: dstArrangement))
        sink.append(simdfpVectorOperand(Rn, arrangement: srcArrangement))
        if zeroForm {
            sink.append(.unsignedImmediate(value: 0, width: 1))
        }
        if m == .shll || m == .shll2 {
            sink.append(.unsignedImmediate(value: UInt64(8) << UInt64(size), width: 8))
        }

        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: m,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.count(since: operandMark),
        )
    }

    @inline(__always)
    @_effects(readonly)
    private static func isZeroCompareForm(U: UInt8, opcode: UInt8) -> Bool {
        switch (U, opcode) {
        case (0, 0b01000),
             (0, 0b01001),
             (0, 0b01010),
             (1, 0b01000),
             (1, 0b01001),
             (0, 0b01101),
             (0, 0b01110),
             (0, 0b01111),
             (1, 0b01100),
             (1, 0b01101):
            true
        default:
            false
        }
    }

    /// Map (U, opcode, size, Q) → (mnemonic, destinationArrangement).
    @inline(__always)
    @_effects(readonly)
    private static func intMnemonicAndDstShape(
        U: UInt8, opcode: UInt8, size: UInt8, Q: UInt8,
    ) -> (Mnemonic, VectorArrangement, VectorArrangement)? {
        let same = arrangementFromSizeQ(size: size, Q: Q)
        let longDst = arrangementFromSizeQ(size: (size &+ 1) & 0x3, Q: Q)
        let narrowDst = narrowArrangement(size: size, Q: Q)
        let wideSrc = arrangementFromSizeQ(size: (size &+ 1) & 0x3, Q: 1)
        let m: Mnemonic
        var dstArrangement = same
        var srcArrangement = same
        switch (U, opcode) {
        case (0, 0b00000): m = .rev64
        case (0, 0b00001): m = .rev16
        case (0, 0b00010): m = .saddlp; dstArrangement = longDst
        case (0, 0b00011): m = .suqadd
        case (0, 0b00100): m = .cls
        case (0, 0b00101): m = .cnt
        case (0, 0b00110): m = .sadalp; dstArrangement = longDst
        case (0, 0b00111): m = .sqabs
        case (0, 0b01000): m = .cmgt
        case (0, 0b01001): m = .cmeq
        case (0, 0b01010): m = .cmlt
        case (0, 0b01011): m = .abs
        case (0, 0b10010):
            m = Q == 1 ? .xtn2 : .xtn; dstArrangement = narrowDst; srcArrangement = wideSrc
        case (0, 0b10100):
            m = Q == 1 ? .sqxtn2 : .sqxtn; dstArrangement = narrowDst; srcArrangement = wideSrc
        case (1, 0b10011):
            m = Q == 1 ? .shll2 : .shll
            dstArrangement = widenArrangement(size: size)
        case (1, 0b00000): m = .rev32
        case (1, 0b00010): m = .uaddlp; dstArrangement = longDst
        case (1, 0b00011): m = .usqadd
        case (1, 0b00100): m = .clz
        case (1, 0b00110): m = .uadalp; dstArrangement = longDst
        case (1, 0b00111): m = .sqneg
        case (1, 0b01000): m = .cmge
        case (1, 0b01001): m = .cmle
        case (1, 0b01011): m = .neg
        case (1, 0b10010):
            m = Q == 1 ? .sqxtun2 : .sqxtun; dstArrangement = narrowDst; srcArrangement = wideSrc
        case (1, 0b10100):
            m = Q == 1 ? .uqxtn2 : .uqxtn; dstArrangement = narrowDst; srcArrangement = wideSrc
        case (1, 0b00101):
            switch size {
            case 0b00: m = .mvn
            case 0b01: m = .rbit
            default: return nil
            }
            dstArrangement = Q == 1 ? .b16 : .b8
            srcArrangement = Q == 1 ? .b16 : .b8
        default:
            return nil
        }
        let sizeOK: Bool = switch (U, opcode) {
        case (0, 0b00000): size != 0b11
        case (1, 0b00000): size <= 0b01
        case (0, 0b00001): size == 0b00
        case (0, 0b00101): size == 0b00
        case (0, 0b00010), (1, 0b00010),
             (0, 0b00110), (1, 0b00110),
             (0, 0b00100), (1, 0b00100),
             (0, 0b10010), (1, 0b10010),
             (0, 0b10100), (1, 0b10100),
             (1, 0b10011):
            size != 0b11
        default: !(size == 0b11 && Q == 0)
        }
        guard sizeOK else { return nil }
        return (m, dstArrangement, srcArrangement)
    }

    @inline(__always)
    @_effects(readonly)
    private static func narrowArrangement(size: UInt8, Q: UInt8) -> VectorArrangement {
        let idx = Int(((size & 0x3) << 1) | (Q & 0x1))
        return narrowArrangementTable[idx]
    }

    @inline(__always)
    @_effects(readonly)
    private static func widenArrangement(size: UInt8) -> VectorArrangement {
        switch size & 0x3 {
        case 0b00: .h8
        case 0b01: .s4
        default: .d2
        }
    }

    private static let narrowArrangementTable: [VectorArrangement] = [
        .b8, .b16, .h4, .h8, .s2, .s4,
        .b8, .b8,
    ]

    /// FP16 two-register miscellaneous (.4h/.8h) at bits[21:17]=11100,
    /// bit22=1, bit23 the altBit.
    static func decodeFP16TwoRegMisc(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 1)
        let U = UInt8((encoding >> 29) & 1)
        let altBit = UInt8((encoding >> 23) & 1)
        let opcode = UInt8((encoding >> 12) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)
        if (encoding >> 22) & 1 == 0 { return .undefined(at: address, encoding: encoding) }
        let m: Mnemonic
        switch (U, opcode, altBit) {
        case (0, 0b11000, 0): m = .frintn
        case (0, 0b11001, 0): m = .frintm
        case (0, 0b11010, 0): m = .fcvtns
        case (0, 0b11011, 0): m = .fcvtms
        case (0, 0b11100, 0): m = .fcvtas
        case (0, 0b11101, 0): m = .scvtf
        case (0, 0b01100, 1): m = .fcmgt
        case (0, 0b01101, 1): m = .fcmeq
        case (0, 0b01110, 1): m = .fcmlt
        case (0, 0b01111, 1): m = .fabs
        case (0, 0b11000, 1): m = .frintp
        case (0, 0b11001, 1): m = .frintz
        case (0, 0b11010, 1): m = .fcvtps
        case (0, 0b11011, 1): m = .fcvtzs
        case (0, 0b11101, 1): m = .frecpe
        case (1, 0b11000, 0): m = .frinta
        case (1, 0b11001, 0): m = .frintx
        case (1, 0b11010, 0): m = .fcvtnu
        case (1, 0b11011, 0): m = .fcvtmu
        case (1, 0b11100, 0): m = .fcvtau
        case (1, 0b11101, 0): m = .ucvtf
        case (1, 0b01100, 1): m = .fcmge
        case (1, 0b01101, 1): m = .fcmle
        case (1, 0b01111, 1): m = .fneg
        case (1, 0b11001, 1): m = .frinti
        case (1, 0b11010, 1): m = .fcvtpu
        case (1, 0b11011, 1): m = .fcvtzu
        case (1, 0b11101, 1): m = .frsqrte
        case (1, 0b11111, 1): m = .fsqrt
        default: return .undefined(at: address, encoding: encoding)
        }
        let arrangement: VectorArrangement = Q == 1 ? .h8 : .h4
        let zeroForm = switch m {
        case .fcmgt, .fcmeq, .fcmlt, .fcmge, .fcmle: true
        default: false
        }
        let operandMark = sink.mark
        _ = sink.emit(simdfpVectorOperand(Rd, arrangement: arrangement), simdfpVectorOperand(Rn, arrangement: arrangement))
        if zeroForm {
            sink.append(.floatImmediate(bits: 0, kind: .half))
        }
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: m,
            semanticReads: simdfpInsertingVector(Rn, into: .empty),
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.count(since: operandMark),
        )
    }

    /// FCVTN/FCVTL/FCVTXN — FP convert with size-changing operand shapes. sz =
    /// bit[22]: 0 ⇒ half↔single, 1 ⇒ single↔double. bit[23] is SBZ. Q selects
    /// the "2" (upper-half) form for the narrow operand.
    @inline(__always)
    @_effects(readonly)
    private static func decodeFPConvertNarrowLong(
        encoding: UInt32, address: UInt64,
        Q: UInt8, U: UInt8, size: UInt8, opcode: UInt8, Rn: UInt8, Rd: UInt8, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let bit23 = (size >> 1) & 1
        let sz = size & 1
        let m: Mnemonic
        let dstArr: VectorArrangement
        let srcArr: VectorArrangement
        if U == 1, opcode == 0b10111 {
            let fp8: Mnemonic = switch size {
            case 0b00: Q == 1 ? .f1cvtl2 : .f1cvtl
            case 0b01: Q == 1 ? .f2cvtl2 : .f2cvtl
            case 0b10: Q == 1 ? .bf1cvtl2 : .bf1cvtl
            default: Q == 1 ? .bf2cvtl2 : .bf2cvtl
            }
            return DecodedDraft(
                address: address, encoding: encoding, mnemonic: fp8,
                semanticReads: simdfpInsertingVector(Rn, into: .empty),
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operandCount: sink.emit(simdfpVectorOperand(Rd, arrangement: .h8), simdfpVectorOperand(Rn, arrangement: Q == 1 ? .b16 : .b8)),
            )
        }
        switch (U, opcode, bit23) {
        case (0, 0b10110, 0):
            m = Q == 1 ? .fcvtn2 : .fcvtn
            dstArr = sz == 0 ? (Q == 1 ? .h8 : .h4) : (Q == 1 ? .s4 : .s2)
            srcArr = sz == 0 ? .s4 : .d2
        case (0, 0b10111, 0):
            m = Q == 1 ? .fcvtl2 : .fcvtl
            dstArr = sz == 0 ? .s4 : .d2
            srcArr = sz == 0 ? (Q == 1 ? .h8 : .h4) : (Q == 1 ? .s4 : .s2)
        case (1, 0b10110, 0):
            if sz != 1 { return .undefined(at: address, encoding: encoding) }
            m = Q == 1 ? .fcvtxn2 : .fcvtxn
            dstArr = Q == 1 ? .s4 : .s2
            srcArr = .d2
        case (0, 0b10110, 1):
            if sz != 0 { return .undefined(at: address, encoding: encoding) }
            m = Q == 1 ? .bfcvtn2 : .bfcvtn
            dstArr = Q == 1 ? .h8 : .h4
            srcArr = .s4
        default:
            return .undefined(at: address, encoding: encoding)
        }
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: m,
            semanticReads: simdfpInsertingVector(Rn, into: .empty),
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.emit(simdfpVectorOperand(Rd, arrangement: dstArr), simdfpVectorOperand(Rn, arrangement: srcArr)),
        )
    }

    @inline(__always)
    @_optimize(speed)
    private static func decodeFPFamily(
        encoding: UInt32, address: UInt64,
        Q: UInt8, U: UInt8, size: UInt8, opcode: UInt8,
        Rn: UInt8, Rd: UInt8, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let sz = size & 1
        let altBit = (size >> 1) & 1
        let arrangement: VectorArrangement
        switch (sz, Q) {
        case (0, 0): arrangement = .s2
        case (0, 1): arrangement = .s4
        case (1, 1): arrangement = .d2
        default: return .undefined(at: address, encoding: encoding)
        }
        if opcode == 0b11110 || opcode == 0b11111, altBit == 0 {
            let is64 = opcode == 0b11111
            let fm: Mnemonic = switch (U, is64) {
            case (0, false): .frint32z
            case (1, false): .frint32x
            case (0, true): .frint64z
            default: .frint64x
            }
            return DecodedDraft(
                address: address, encoding: encoding, mnemonic: fm,
                semanticReads: simdfpInsertingVector(Rn, into: .empty),
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operandCount: sink.emit(simdfpVectorOperand(Rd, arrangement: arrangement), simdfpVectorOperand(Rn, arrangement: arrangement)),
            )
        }
        let m: Mnemonic
        switch (U, opcode, altBit) {
        case (0, 0b11000, 0): m = .frintn
        case (0, 0b11000, 1): m = .frintp
        case (0, 0b11001, 0): m = .frintm
        case (0, 0b11001, 1): m = .frintz
        case (0, 0b11010, 0): m = .fcvtns
        case (0, 0b11010, 1): m = .fcvtps
        case (0, 0b11011, 0): m = .fcvtms
        case (0, 0b11011, 1): m = .fcvtzs
        case (0, 0b11100, 0): m = .fcvtas
        case (0, 0b11101, 0): m = .scvtf
        case (0, 0b11101, 1): m = .frecpe
        case (0, 0b11100, 1): m = .urecpe
        case (0, 0b01100, 1): m = .fcmgt
        case (0, 0b01101, 1): m = .fcmeq
        case (0, 0b01110, 1): m = .fcmlt
        case (0, 0b01111, 1): m = .fabs
        case (1, 0b11000, 0): m = .frinta
        case (1, 0b11001, 0): m = .frintx
        case (1, 0b11001, 1): m = .frinti
        case (1, 0b11010, 0): m = .fcvtnu
        case (1, 0b11010, 1): m = .fcvtpu
        case (1, 0b11011, 0): m = .fcvtmu
        case (1, 0b11011, 1): m = .fcvtzu
        case (1, 0b11100, 0): m = .fcvtau
        case (1, 0b11101, 0): m = .ucvtf
        case (1, 0b11101, 1): m = .frsqrte
        case (1, 0b11100, 1): m = .ursqrte
        case (1, 0b11111, 1): m = .fsqrt
        case (1, 0b01100, 1): m = .fcmge
        case (1, 0b01101, 1): m = .fcmle
        case (1, 0b01111, 1): m = .fneg
        default:
            return .undefined(at: address, encoding: encoding)
        }
        if m == .urecpe || m == .ursqrte, sz != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let zeroForm = switch m {
        case .fcmgt, .fcmeq, .fcmlt, .fcmge, .fcmle:
            true
        default:
            false
        }
        let operandMark = sink.mark
        sink.append(simdfpVectorOperand(Rd, arrangement: arrangement))
        sink.append(simdfpVectorOperand(Rn, arrangement: arrangement))
        if zeroForm {
            let fpKind: FloatImmediateKind = sz == 0 ? .single : .double
            sink.append(.floatImmediate(bits: 0, kind: fpKind))
        }
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: m,
            semanticReads: simdfpInsertingVector(Rn, into: .empty),
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.count(since: operandMark),
        )
    }
}
