// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum AdvSIMDCopyDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let op = UInt8((encoding >> 29) & 0x1)
        let imm5 = UInt8((encoding >> 16) & 0x1F)
        let imm4 = UInt8((encoding >> 11) & 0xF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        guard let (elementSize, indexDst) = decodeElementSizeAndIndex(imm5: imm5)
        else { return .undefined(at: address, encoding: encoding) }

        if op == 1 {
            let indexSrc = decodeSourceElementIndex(elementSize: elementSize, imm4: imm4)
            if Q == 0 { return .undefined(at: address, encoding: encoding) }
            let dstOperand = simdfpElementOperand(Rd, elementSize: elementSize, index: indexDst)
            let srcOperand = simdfpElementOperand(Rn, elementSize: elementSize, index: indexSrc)
            var reads = simdfpInsertingVector(Rn, into: .empty)
            reads = simdfpInsertingVector(Rd, into: reads)
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: .mov,
                semanticReads: reads,
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operandCount: sink.emit(dstOperand, srcOperand),
            )
        }

        switch imm4 {
        case 0b0000:
            guard let dstArrangement = arrangementFor(elementSize: elementSize, Q: Q) else {
                return .undefined(at: address, encoding: encoding)
            }
            let dst = simdfpVectorOperand(Rd, arrangement: dstArrangement)
            let src = simdfpElementOperand(Rn, elementSize: elementSize, index: indexDst)
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: .dup,
                semanticReads: simdfpInsertingVector(Rn, into: .empty),
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operandCount: sink.emit(dst, src),
            )
        case 0b0001:
            guard let dstArrangement = arrangementFor(elementSize: elementSize, Q: Q) else {
                return .undefined(at: address, encoding: encoding)
            }
            let gprWidth: RegisterWidth = elementSize == .d ? .x64 : .w32
            let gpr = simdfpGprOperand(encoding: Rn, width: gprWidth, spOrGeneral: false)
            let dst = simdfpVectorOperand(Rd, arrangement: dstArrangement)
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: .dup,
                semanticReads: simdfpInsertingNonZeroGPR(reg: gpr, into: .empty),
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operandCount: sink.emit(dst, .register(gpr)),
            )
        case 0b0011:
            if Q == 0 { return .undefined(at: address, encoding: encoding) }
            let gprWidth: RegisterWidth = elementSize == .d ? .x64 : .w32
            let gpr = simdfpGprOperand(encoding: Rn, width: gprWidth, spOrGeneral: false)
            let dst = simdfpElementOperand(Rd, elementSize: elementSize, index: indexDst)
            var reads = simdfpInsertingNonZeroGPR(reg: gpr, into: .empty)
            reads = simdfpInsertingVector(Rd, into: reads)
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: .mov,
                semanticReads: reads,
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operandCount: sink.emit(dst, .register(gpr)),
            )
        case 0b0101:
            if elementSize == .d { return .undefined(at: address, encoding: encoding) }
            if elementSize == .s, Q == 0 { return .undefined(at: address, encoding: encoding) }
            let gprWidth: RegisterWidth = Q == 1 ? .x64 : .w32
            let gpr = simdfpGprOperand(encoding: Rd, width: gprWidth, spOrGeneral: false)
            let src = simdfpElementOperand(Rn, elementSize: elementSize, index: indexDst)
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: .smov,
                semanticReads: simdfpInsertingVector(Rn, into: .empty),
                semanticWrites: simdfpInsertingNonZeroGPR(reg: gpr, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operandCount: sink.emit(.register(gpr), src),
            )
        case 0b0111:
            let (validQ, gprWidth, useMovAlias): (UInt8, RegisterWidth, Bool) = switch elementSize {
            case .s: (0, .w32, true)
            case .d: (1, .x64, true)
            default: (0, .w32, false)
            }
            if Q != validQ { return .undefined(at: address, encoding: encoding) }
            let gpr = simdfpGprOperand(encoding: Rd, width: gprWidth, spOrGeneral: false)
            let src = simdfpElementOperand(Rn, elementSize: elementSize, index: indexDst)
            let mnemonic: Mnemonic = useMovAlias ? .mov : .umov
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: simdfpInsertingVector(Rn, into: .empty),
                semanticWrites: simdfpInsertingNonZeroGPR(reg: gpr, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operandCount: sink.emit(.register(gpr), src),
            )
        default:
            return .undefined(at: address, encoding: encoding)
        }
    }

    /// Decode (elementSize, destinationIndex) from imm5 by first-set-bit.
    @inline(__always)
    @_effects(readonly)
    private static func decodeElementSizeAndIndex(imm5: UInt8) -> (ScalarSize, UInt8)? {
        if imm5 == 0 { return nil }
        if (imm5 & 0x01) != 0 {
            return (.b, (imm5 >> 1) & 0xF)
        }
        if (imm5 & 0x02) != 0 {
            return (.h, (imm5 >> 2) & 0x7)
        }
        if (imm5 & 0x04) != 0 {
            return (.s, (imm5 >> 3) & 0x3)
        }
        if (imm5 & 0x08) != 0 {
            return (.d, (imm5 >> 4) & 0x1)
        }
        return nil
    }

    /// Decode the source element index for INS element-to-element from imm4,
    /// given the element size from imm5.
    @inline(__always)
    @_effects(readonly)
    private static func decodeSourceElementIndex(
        elementSize: ScalarSize, imm4: UInt8,
    ) -> UInt8 {
        switch elementSize {
        case .b: imm4 & 0xF
        case .h: (imm4 >> 1) & 0x7
        case .s: (imm4 >> 2) & 0x3
        default: (imm4 >> 3) & 0x1
        }
    }

    /// Vector arrangement for (elementSize, Q).
    @inline(__always)
    @_effects(readonly)
    private static func arrangementFor(elementSize: ScalarSize, Q: UInt8) -> VectorArrangement? {
        switch (elementSize, Q) {
        case (.b, 0): .b8
        case (.b, 1): .b16
        case (.h, 0): .h4
        case (.h, 1): .h8
        case (.s, 0): .s2
        case (.s, 1): .s4
        case (.d, 1): .d2
        default: nil
        }
    }
}
