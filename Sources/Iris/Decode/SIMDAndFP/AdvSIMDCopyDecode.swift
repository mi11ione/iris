// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// AdvSIMD vector copy per ARM ARM § C4.1.96.22.
// Encoding: `0 Q op 0 1110 000 imm5 0 imm4 1 Rn Rd`. The `imm5` field
// encodes element size via first-set-bit position:
//   imm5 = xxxx1 → byte (B); index = imm5[4:1]
//   imm5 = xxx10 → halfword (H); index = imm5[4:2]
//   imm5 = xx100 → word (S); index = imm5[4:3]
//   imm5 = x1000 → doubleword (D); index = imm5[4]
//   imm5 = 00000 → reserved
//
// imm4 + op selects the sub-instruction:
//   op=0 imm4=0000 → DUP element
//   op=0 imm4=0001 → DUP general (Wn/Xn → all lanes)
//   op=0 imm4=0011 → INS general (Wn/Xn → element) — aliased to MOV
//   op=0 imm4=0101 → SMOV  (element → Wd/Xd, sign-extending)
//   op=0 imm4=0111 → UMOV  (element → Wd/Xd) — aliased to MOV for S/D
//   op=1 imm4=any  → INS element-to-element — aliased to MOV

enum AdvSIMDCopyDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let op = UInt8((encoding >> 29) & 0x1)
        let imm5 = UInt8((encoding >> 16) & 0x1F)
        let imm4 = UInt8((encoding >> 11) & 0xF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        // Decode element size + index from imm5.
        guard let (elementSize, indexDst) = decodeElementSizeAndIndex(imm5: imm5)
        else { return .undefined(at: address, encoding: encoding) }

        if op == 1 {
            // INS element-to-element. imm4 encodes the source index.
            // Both src and dst are element-views; alias to MOV.
            let indexSrc = decodeSourceElementIndex(elementSize: elementSize, imm4: imm4)
            // Q must be 1 (INS-element only valid on 128-bit register; the
            // architectural constraint).
            if Q == 0 { return .undefined(at: address, encoding: encoding) }
            let dstOperand = simdfpElementOperand(Rd, elementSize: elementSize, index: indexDst)
            let srcOperand = simdfpElementOperand(Rn, elementSize: elementSize, index: indexSrc)
            // INS reads its destination (it preserves the other lanes).
            var reads = simdfpInsertingVector(Rn, into: .empty)
            reads = simdfpInsertingVector(Rd, into: reads)
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: .mov,
                semanticReads: reads,
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operands: [dstOperand, srcOperand],
            )
        }

        // op == 0 — DUP / INS-general / SMOV / UMOV.
        switch imm4 {
        case 0b0000:
            // DUP element: Vd.<arrangement> = Vn.<Ts>[index], replicated.
            // Arrangement = lane count given by (elementSize, Q).
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
                operands: [dst, src],
            )
        case 0b0001:
            // DUP general: Vd.<arrangement> = <Wn|Xn> (replicated).
            // For element size <= 4 bytes, source is W; for D, source is X.
            // arrangementFor already filters reserved combos including
            // (.d, Q=0) — no separate D/Q=0 check needed.
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
                operands: [dst, .register(gpr)],
            )
        case 0b0011:
            // INS general (alias MOV): Vd.<Ts>[idx] = <Wn|Xn>.
            // Q must be 1 (only valid on 128-bit dest).
            if Q == 0 { return .undefined(at: address, encoding: encoding) }
            // D-element source = X; others = W.
            let gprWidth: RegisterWidth = elementSize == .d ? .x64 : .w32
            let gpr = simdfpGprOperand(encoding: Rn, width: gprWidth, spOrGeneral: false)
            let dst = simdfpElementOperand(Rd, elementSize: elementSize, index: indexDst)
            // INS reads its destination (it preserves the other lanes).
            var reads = simdfpInsertingNonZeroGPR(reg: gpr, into: .empty)
            reads = simdfpInsertingVector(Rd, into: reads)
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: .mov,
                semanticReads: reads,
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operands: [dst, .register(gpr)],
            )
        case 0b0101:
            // SMOV: Wd or Xd = sign-extend(Vn.<Ts>[idx]). Q selects Wd vs Xd.
            // Valid only for B/H (Q=0/1) and S (Q=1).
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
                operands: [.register(gpr), src],
            )
        case 0b0111:
            // UMOV: Wd or Xd = Vn.<Ts>[idx]. Q selects Wd vs Xd; B/H only
            // valid for Q=0, S only valid for Q=0, D only valid for Q=1.
            // elementSize ∈ {.b, .h, .s, .d} from decodeElementSizeAndIndex
            // (never .q). Default absorbs (.b, .h) — both same tuple — and
            // any sentinel.
            let (validQ, gprWidth, useMovAlias): (UInt8, RegisterWidth, Bool) = switch elementSize {
            case .s: (0, .w32, true) // MOV alias for S
            case .d: (1, .x64, true) // MOV alias for D
            default: (0, .w32, false) // .b or .h — UMOV; .q unreachable.
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
                operands: [.register(gpr), src],
            )
        default:
            return .undefined(at: address, encoding: encoding)
        }
    }

    /// Decode (elementSize, destinationIndex) from imm5 by first-set-bit.
    /// Returns nil for imm5 = 00000 (reserved). When imm5 has only bit[4]
    /// set (imm5 == 0b10000), no element type is selected and the result
    /// is nil.
    @inline(__always)
    @_effects(readonly)
    private static func decodeElementSizeAndIndex(imm5: UInt8) -> (ScalarSize, UInt8)? {
        if imm5 == 0 { return nil }
        if (imm5 & 0x01) != 0 {
            // B: index = imm5[4:1].
            return (.b, (imm5 >> 1) & 0xF)
        }
        if (imm5 & 0x02) != 0 {
            // H: index = imm5[4:2].
            return (.h, (imm5 >> 2) & 0x7)
        }
        if (imm5 & 0x04) != 0 {
            // S: index = imm5[4:3].
            return (.s, (imm5 >> 3) & 0x3)
        }
        if (imm5 & 0x08) != 0 {
            // D: index = imm5[4].
            return (.d, (imm5 >> 4) & 0x1)
        }
        // imm5 == 0b10000 (only bit 4 set) — no element type selected.
        return nil
    }

    /// Decode the SOURCE element index for INS element-to-element from
    /// imm4 (4 bits) given the element size already determined from imm5.
    /// The number of meaningful bits in imm4 depends on the element size:
    /// B uses all 4 bits, H uses 3, S uses 2, D uses 1. (`.q` never
    /// arrives here — element decode produces B/H/S/D only.)
    @inline(__always)
    @_effects(readonly)
    private static func decodeSourceElementIndex(
        elementSize: ScalarSize, imm4: UInt8,
    ) -> UInt8 {
        switch elementSize {
        case .b: imm4 & 0xF
        case .h: (imm4 >> 1) & 0x7
        case .s: (imm4 >> 2) & 0x3
        default: (imm4 >> 3) & 0x1 // elementSize == .d (.q is unreachable).
        }
    }

    /// Vector arrangement for (elementSize, Q): the destination shape of
    /// DUP and DUP-general at this class.
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
