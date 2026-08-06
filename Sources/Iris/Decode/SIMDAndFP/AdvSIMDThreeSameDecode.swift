// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum AdvSIMDThreeSameDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let U = UInt8((encoding >> 29) & 0x1)
        let size = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let opcode = UInt8((encoding >> 11) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        if opcode >= 0b11000 {
            return decodeFPFamily(
                encoding: encoding, address: address,
                Q: Q, U: U, size: size, opcode: opcode, Rm: Rm, Rn: Rn, Rd: Rd, &sink,
            )
        }
        return decodeIntFamily(
            encoding: encoding, address: address,
            Q: Q, U: U, size: size, opcode: opcode, Rm: Rm, Rn: Rn, Rd: Rd, &sink,
        )
    }

    @inline(__always)
    @_optimize(speed)
    private static func decodeIntFamily(
        encoding: UInt32, address: UInt64,
        Q: UInt8, U: UInt8, size: UInt8, opcode: UInt8,
        Rm: UInt8, Rn: UInt8, Rd: UInt8, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let arrangement = arrangementFromSizeQ(size: size, Q: Q)
        if opcode == 0b00011 {
            let actualArrangement: VectorArrangement = Q == 1 ? .b16 : .b8
            let m = logicalMnemonicByteVec(U: U, size: size)
            let isOrr = (U == 0 && size == 0b10)
            if isOrr, Rm == Rn {
                return makeTwoOperandRecord(
                    address: address, encoding: encoding,
                    mnemonic: .mov, Rd: Rd, Rn: Rn,
                    arrangement: actualArrangement, &sink,
                )
            }
            return makeThreeOperandRecord(
                address: address, encoding: encoding,
                mnemonic: m, Rd: Rd, Rn: Rn, Rm: Rm,
                arrangement: actualArrangement,
                destReadsItself: U == 1 && (size == 0b01 || size == 0b10 || size == 0b11), &sink,
            )
        }
        let mnemonic = intMnemonic(U: U, opcode: opcode)
        guard let m = mnemonic else {
            return .undefined(at: address, encoding: encoding)
        }
        if !arrangementValidForIntOpcode(U: U, opcode: opcode, arrangement: arrangement) {
            return .undefined(at: address, encoding: encoding)
        }
        let destReadsItself = simdFPDestinationReadsItself(m)
        return makeThreeOperandRecord(
            address: address, encoding: encoding,
            mnemonic: m, Rd: Rd, Rn: Rn, Rm: Rm,
            arrangement: arrangement,
            destReadsItself: destReadsItself, &sink,
        )
    }

    @inline(__always)
    @_effects(readonly)
    private static func logicalMnemonicByteVec(U: UInt8, size: UInt8) -> Mnemonic {
        switch (U, size) {
        case (0, 0b00): .and
        case (0, 0b01): .bic
        case (0, 0b10): .orr
        case (0, 0b11): .orn
        case (1, 0b00): .eor
        case (1, 0b01): .bsl
        case (1, 0b10): .bit
        default: .bif
        }
    }

    @inline(__always)
    @_effects(readonly)
    private static func intMnemonic(U: UInt8, opcode: UInt8) -> Mnemonic? {
        switch (U, opcode) {
        case (0, 0b00000): .shadd
        case (0, 0b00001): .sqadd
        case (0, 0b00010): .srhadd
        case (0, 0b00100): .shsub
        case (0, 0b00101): .sqsub
        case (0, 0b00110): .cmgt
        case (0, 0b00111): .cmge
        case (0, 0b01000): .sshl
        case (0, 0b01001): .sqshl
        case (0, 0b01010): .srshl
        case (0, 0b01011): .sqrshl
        case (0, 0b01100): .smax
        case (0, 0b01101): .smin
        case (0, 0b01110): .sabd
        case (0, 0b01111): .saba
        case (0, 0b10000): .add
        case (0, 0b10001): .cmtst
        case (0, 0b10010): .mla
        case (0, 0b10011): .mul
        case (0, 0b10100): .smaxp
        case (0, 0b10101): .sminp
        case (0, 0b10110): .sqdmulh
        case (0, 0b10111): .addp
        case (1, 0b00000): .uhadd
        case (1, 0b00001): .uqadd
        case (1, 0b00010): .urhadd
        case (1, 0b00100): .uhsub
        case (1, 0b00101): .uqsub
        case (1, 0b00110): .cmhi
        case (1, 0b00111): .cmhs
        case (1, 0b01000): .ushl
        case (1, 0b01001): .uqshl
        case (1, 0b01010): .urshl
        case (1, 0b01011): .uqrshl
        case (1, 0b01100): .umax
        case (1, 0b01101): .umin
        case (1, 0b01110): .uabd
        case (1, 0b01111): .uaba
        case (1, 0b10000): .sub
        case (1, 0b10001): .cmeq
        case (1, 0b10010): .mls
        case (1, 0b10011): .pmul
        case (1, 0b10100): .umaxp
        case (1, 0b10101): .uminp
        case (1, 0b10110): .sqrdmulh
        default: nil
        }
    }

    /// Per-opcode arrangement-validity check.
    @inline(__always)
    @_effects(readonly)
    private static func arrangementValidForIntOpcode(
        U: UInt8, opcode: UInt8, arrangement: VectorArrangement,
    ) -> Bool {
        if arrangement == .d1 { return false }
        if opcode == 0b10110 {
            return arrangement == .h4 || arrangement == .h8
                || arrangement == .s2 || arrangement == .s4
        }
        if opcode == 0b10011 {
            if U == 1 {
                return arrangement == .b8 || arrangement == .b16
            }
            return arrangement != .d2
        }
        switch opcode {
        case 0b10010, 0b00000, 0b00010, 0b00100,
             0b10101, 0b10100, 0b01100, 0b01101,
             0b01110, 0b01111:
            return arrangement != .d2
        default:
            return true
        }
    }

    @inline(__always)
    @_optimize(speed)
    private static func decodeFPFamily(
        encoding: UInt32, address: UInt64,
        Q: UInt8, U: UInt8, size: UInt8, opcode: UInt8,
        Rm: UInt8, Rn: UInt8, Rd: UInt8, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        if let widening = wideningHalfProductMnemonic(U: U, size: size, opcode: opcode) {
            return makeWideningRecord(
                address: address, encoding: encoding, mnemonic: widening,
                Rd: Rd, Rn: Rn, Rm: Rm,
                dstArrangement: Q == 1 ? .s4 : .s2,
                srcArrangement: Q == 1 ? .h4 : .h2, &sink,
            )
        }
        let sz = (size & 0b01)
        let altBit = (size >> 1) & 1
        let arrangement: VectorArrangement
        switch (sz, Q) {
        case (0, 0): arrangement = .s2
        case (0, 1): arrangement = .s4
        case (1, 1): arrangement = .d2
        default: return .undefined(at: address, encoding: encoding)
        }
        let m: Mnemonic
        switch (U, opcode, altBit) {
        case (0, 0b11000, 0): m = .fmaxnm
        case (0, 0b11000, 1): m = .fminnm
        case (0, 0b11001, 0): m = .fmla
        case (0, 0b11001, 1): m = .fmls
        case (0, 0b11010, 0): m = .fadd
        case (0, 0b11010, 1): m = .fsub
        case (0, 0b11011, 0): m = .fmulx
        case (0, 0b11100, 0): m = .fcmeq
        case (0, 0b11110, 0): m = .fmax
        case (0, 0b11110, 1): m = .fmin
        case (0, 0b11111, 0): m = .frecps
        case (0, 0b11111, 1): m = .frsqrts
        case (1, 0b11000, 0): m = .fmaxnmp
        case (1, 0b11000, 1): m = .fminnmp
        case (1, 0b11010, 0): m = .faddp
        case (1, 0b11011, 0): m = .fmul
        case (1, 0b11100, 0): m = .fcmge
        case (1, 0b11100, 1): m = .fcmgt
        case (1, 0b11101, 0): m = .facge
        case (1, 0b11101, 1): m = .facgt
        case (1, 0b11110, 0): m = .fmaxp
        case (1, 0b11110, 1): m = .fminp
        case (1, 0b11111, 0): m = .fdiv
        case (1, 0b11010, 1): m = .fabd
        case (0, 0b11011, 1): m = .famax
        case (1, 0b11011, 1): m = .famin
        case (1, 0b11111, 1): m = .fscale
        default: return .undefined(at: address, encoding: encoding)
        }
        let destReadsItself = simdFPDestinationReadsItself(m)
        return makeThreeOperandRecord(
            address: address, encoding: encoding,
            mnemonic: m, Rd: Rd, Rn: Rn, Rm: Rm,
            arrangement: arrangement,
            destReadsItself: destReadsItself, &sink,
        )
    }

    /// FEAT_FHM widening half-precision products, whose destination is twice
    /// the element width of both sources.
    @inline(__always)
    @_effects(readonly)
    private static func wideningHalfProductMnemonic(
        U: UInt8, size: UInt8, opcode: UInt8,
    ) -> Mnemonic? {
        if size & 0b01 != 0 { return nil }
        let subtracting = (size >> 1) & 1 == 1
        if U == 0, opcode == 0b11101 { return subtracting ? .fmlsl : .fmlal }
        if U == 1, opcode == 0b11001 { return subtracting ? .fmlsl2 : .fmlal2 }
        return nil
    }

    @inline(__always)
    @_effects(readonly)
    private static func makeWideningRecord(
        address: UInt64, encoding: UInt32, mnemonic: Mnemonic,
        Rd: UInt8, Rn: UInt8, Rm: UInt8,
        dstArrangement: VectorArrangement, srcArrangement: VectorArrangement,
        _ sink: inout OperandSink,
    ) -> DecodedDraft {
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(Rm, into: reads)
        reads = simdfpInsertingVector(Rd, into: reads)
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.emit(simdfpVectorOperand(Rd, arrangement: dstArrangement), simdfpVectorOperand(Rn, arrangement: srcArrangement), simdfpVectorOperand(Rm, arrangement: srcArrangement)),
        )
    }

    @inline(__always)
    @_effects(readonly)
    private static func makeThreeOperandRecord(
        address: UInt64, encoding: UInt32, mnemonic: Mnemonic,
        Rd: UInt8, Rn: UInt8, Rm: UInt8,
        arrangement: VectorArrangement,
        destReadsItself: Bool, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(Rm, into: reads)
        if destReadsItself {
            reads = simdfpInsertingVector(Rd, into: reads)
        }
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.emit(simdfpVectorOperand(Rd, arrangement: arrangement), simdfpVectorOperand(Rn, arrangement: arrangement), simdfpVectorOperand(Rm, arrangement: arrangement)),
        )
    }

    @inline(__always)
    @_effects(readonly)
    private static func makeTwoOperandRecord(
        address: UInt64, encoding: UInt32, mnemonic: Mnemonic,
        Rd: UInt8, Rn: UInt8, arrangement: VectorArrangement, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: simdfpInsertingVector(Rn, into: .empty),
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.emit(simdfpVectorOperand(Rd, arrangement: arrangement), simdfpVectorOperand(Rn, arrangement: arrangement)),
        )
    }
}
