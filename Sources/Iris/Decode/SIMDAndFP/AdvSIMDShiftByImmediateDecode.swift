// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum AdvSIMDShiftByImmediateDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let U = UInt8((encoding >> 29) & 0x1)
        let immh = UInt8((encoding >> 19) & 0xF)
        let immb = UInt8((encoding >> 16) & 0x7)
        let opcode = UInt8((encoding >> 11) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        if (encoding >> 23) & 1 == 1 { return .undefined(at: address, encoding: encoding) }
        let (elementSize, arrSrcQ0, arrSrcQ1): (ScalarSize, VectorArrangement, VectorArrangement)
        if (immh & 0b1000) != 0 {
            elementSize = .d
            arrSrcQ0 = .d1; arrSrcQ1 = .d2
        } else if (immh & 0b0100) != 0 {
            elementSize = .s; arrSrcQ0 = .s2; arrSrcQ1 = .s4
        } else if (immh & 0b0010) != 0 {
            elementSize = .h; arrSrcQ0 = .h4; arrSrcQ1 = .h8
        } else {
            elementSize = .b; arrSrcQ0 = .b8; arrSrcQ1 = .b16
        }
        let elementBits = UInt32(elementSize.byteWidth) * 8
        let immhb = (UInt32(immh) << 3) | UInt32(immb)
        let srcArrangement: VectorArrangement = Q == 1 ? arrSrcQ1 : arrSrcQ0

        let info = mnemonicAndShift(U: U, opcode: opcode)
        guard let resolved = info else {
            return .undefined(at: address, encoding: encoding)
        }
        switch resolved.kind {
        case .narrowing, .lengthening:
            if elementSize == .d { return .undefined(at: address, encoding: encoding) }
        case .sameShape:
            if elementSize == .d, Q == 0 { return .undefined(at: address, encoding: encoding) }
            if elementSize == .b,
               resolved.mnemonic == .scvtf || resolved.mnemonic == .ucvtf
               || resolved.mnemonic == .fcvtzs || resolved.mnemonic == .fcvtzu
            {
                return .undefined(at: address, encoding: encoding)
            }
        }
        let shift = switch resolved.direction {
        case .left: UInt8(immhb &- elementBits)
        case .right: UInt8((elementBits &* 2) &- immhb)
        }

        let dstArrangement: VectorArrangement
        let sourceArrangement: VectorArrangement
        switch resolved.kind {
        case .narrowing:
            dstArrangement = srcArrangement
            sourceArrangement = lengthenedArrangement(for: elementSize)
        case .lengthening:
            dstArrangement = lengthenedArrangement(for: elementSize)
            sourceArrangement = srcArrangement
        case .sameShape:
            dstArrangement = srcArrangement
            sourceArrangement = srcArrangement
        }

        let mnemonic = q1SuffixedMnemonic(resolved.mnemonic, Q: Q)
        let destReadsItself = simdFPDestinationReadsItself(mnemonic)
        var reads = simdfpInsertingVector(Rn, into: .empty)
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
            operandCount: sink.emit(simdfpVectorOperand(Rd, arrangement: dstArrangement), simdfpVectorOperand(Rn, arrangement: sourceArrangement), .unsignedImmediate(value: UInt64(shift), width: 8)),
        )
    }

    /// Map narrowing/lengthening mnemonics to their "2" suffix form when Q=1.
    @inline(__always)
    @_effects(readonly)
    private static func q1SuffixedMnemonic(_ m: Mnemonic, Q: UInt8) -> Mnemonic {
        guard Q == 1 else { return m }
        switch m {
        case .shrn: return .shrn2
        case .rshrn: return .rshrn2
        case .sqshrn: return .sqshrn2
        case .sqrshrn: return .sqrshrn2
        case .uqshrn: return .uqshrn2
        case .uqrshrn: return .uqrshrn2
        case .sqshrun: return .sqshrun2
        case .sqrshrun: return .sqrshrun2
        case .sshll: return .sshll2
        case .ushll: return .ushll2
        default: return m
        }
    }

    private struct ResolvedMnemonic {
        let mnemonic: Mnemonic
        let direction: ShiftDirection
        let kind: ShapeKind
    }

    private enum ShiftDirection { case left, right }
    private enum ShapeKind { case sameShape, narrowing, lengthening }

    @inline(__always)
    @_effects(readonly)
    private static func mnemonicAndShift(U: UInt8, opcode: UInt8) -> ResolvedMnemonic? {
        switch (U, opcode) {
        case (0, 0b00000): .init(mnemonic: .sshr, direction: .right, kind: .sameShape)
        case (0, 0b00010): .init(mnemonic: .ssra, direction: .right, kind: .sameShape)
        case (0, 0b00100): .init(mnemonic: .srshr, direction: .right, kind: .sameShape)
        case (0, 0b00110): .init(mnemonic: .srsra, direction: .right, kind: .sameShape)
        case (0, 0b01010): .init(mnemonic: .shl, direction: .left, kind: .sameShape)
        case (0, 0b01110): .init(mnemonic: .sqshl, direction: .left, kind: .sameShape)
        case (0, 0b10000): .init(mnemonic: .shrn, direction: .right, kind: .narrowing)
        case (0, 0b10001): .init(mnemonic: .rshrn, direction: .right, kind: .narrowing)
        case (0, 0b10010): .init(mnemonic: .sqshrn, direction: .right, kind: .narrowing)
        case (0, 0b10011): .init(mnemonic: .sqrshrn, direction: .right, kind: .narrowing)
        case (0, 0b10100): .init(mnemonic: .sshll, direction: .left, kind: .lengthening)
        case (0, 0b11100): .init(mnemonic: .scvtf, direction: .right, kind: .sameShape)
        case (0, 0b11111): .init(mnemonic: .fcvtzs, direction: .right, kind: .sameShape)
        case (1, 0b00000): .init(mnemonic: .ushr, direction: .right, kind: .sameShape)
        case (1, 0b00010): .init(mnemonic: .usra, direction: .right, kind: .sameShape)
        case (1, 0b00100): .init(mnemonic: .urshr, direction: .right, kind: .sameShape)
        case (1, 0b00110): .init(mnemonic: .ursra, direction: .right, kind: .sameShape)
        case (1, 0b01000): .init(mnemonic: .sri, direction: .right, kind: .sameShape)
        case (1, 0b01010): .init(mnemonic: .sli, direction: .left, kind: .sameShape)
        case (1, 0b01100): .init(mnemonic: .sqshlu, direction: .left, kind: .sameShape)
        case (1, 0b01110): .init(mnemonic: .uqshl, direction: .left, kind: .sameShape)
        case (1, 0b10000): .init(mnemonic: .sqshrun, direction: .right, kind: .narrowing)
        case (1, 0b10001): .init(mnemonic: .sqrshrun, direction: .right, kind: .narrowing)
        case (1, 0b10010): .init(mnemonic: .uqshrn, direction: .right, kind: .narrowing)
        case (1, 0b10011): .init(mnemonic: .uqrshrn, direction: .right, kind: .narrowing)
        case (1, 0b10100): .init(mnemonic: .ushll, direction: .left, kind: .lengthening)
        case (1, 0b11100): .init(mnemonic: .ucvtf, direction: .right, kind: .sameShape)
        case (1, 0b11111): .init(mnemonic: .fcvtzu, direction: .right, kind: .sameShape)
        default: nil
        }
    }

    @inline(__always)
    @_effects(readonly)
    private static func lengthenedArrangement(
        for elementSize: ScalarSize,
    ) -> VectorArrangement {
        switch elementSize {
        case .b: .h8
        case .h: .s4
        default: .d2
        }
    }
}
