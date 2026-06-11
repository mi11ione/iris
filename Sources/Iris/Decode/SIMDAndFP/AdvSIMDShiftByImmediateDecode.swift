// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// AdvSIMD vector shift-by-immediate per
// ARM ARM § C4.1.96.31. Encoding: `0 Q U 0 1111 0 immh immb opcode 1
// Rn Rd` with immh != 0000. The immh field encodes the element size by
// first-set-bit position (immh[3]=1 ⇒ D, [2]=1 ⇒ S, [1]=1 ⇒ H,
// [0]=1 ⇒ B). The shift amount depends on opcode kind (left-shift or
// right-shift):
//   left:  shift = concat(immh, immb) - elementBits
//   right: shift = (2 * elementBits) - concat(immh, immb)
//
// SXTL/UXTL aliases of SSHLL/USHLL emit when shift == 0 (i.e. immb=000
// and immh has exactly one bit set).

enum AdvSIMDShiftByImmediateDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let U = UInt8((encoding >> 29) & 0x1)
        let immh = UInt8((encoding >> 19) & 0xF)
        let immb = UInt8((encoding >> 16) & 0x7)
        let opcode = UInt8((encoding >> 11) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        // bit23 is a fixed 0 for shift-by-immediate (immh is bits[22:19]);
        // bit23=1 is reserved. immh == 0 with bit23 == 0 never arrives —
        // the dispatcher routes bits[23:19] == 0 to modified-immediate.
        if (encoding >> 23) & 1 == 1 { return .undefined(at: address, encoding: encoding) }
        // Element size from first-set-bit of immh.
        let (elementSize, arrSrcQ0, arrSrcQ1): (ScalarSize, VectorArrangement, VectorArrangement)
        if (immh & 0b1000) != 0 {
            // D-element — Q must be 1 for SSHLL/USHLL family; for SSHL/SHL/etc. Q must be 1.
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

        // (U, opcode) determines mnemonic + shift-direction (left vs right).
        let info = mnemonicAndShift(U: U, opcode: opcode)
        guard let resolved = info else {
            return .undefined(at: address, encoding: encoding)
        }
        // Per-kind element-size (immh) validity.
        switch resolved.kind {
        case .narrowing, .lengthening:
            // immh[3]=1 (D element) is reserved for narrow / lengthen forms.
            if elementSize == .d { return .undefined(at: address, encoding: encoding) }
        case .sameShape:
            // .1D (D element, Q=0) is reserved for every same-shape shift.
            if elementSize == .d, Q == 0 { return .undefined(at: address, encoding: encoding) }
            // SCVTF/UCVTF/FCVTZS/FCVTZU need an H/S/D element; B is reserved.
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

        // SSHLL/USHLL with shift=0 are NOT rendered as the SXTL/UXTL alias:
        // llvm-mc disassembles them as `sshll/ushll …, #0`, so they flow
        // through the standard lengthening 3-operand form below.

        // Build the standard 3-operand form: [Vd, Vn, #shift]. For narrowing
        // shifts immh encodes the DESTINATION element (Q selects the low/high
        // half) and the source is the 128-bit 2x-widened arrangement;
        // lengthening is the inverse.
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

        // Promote narrowing/lengthening mnemonics to their "2" suffix
        // form when Q=1 (e.g. SHRN → SHRN2). The .sameShape mnemonics
        // (SSHR/SSRA/etc.) don't have *2 variants — only shape-changing
        // ones do.
        let mnemonic = q1SuffixedMnemonic(resolved.mnemonic, Q: Q)
        let destReadsItself = SIMDFPSemanticAttributes.destinationReadsItself(for: mnemonic)
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
            operands: [
                simdfpVectorOperand(Rd, arrangement: dstArrangement),
                simdfpVectorOperand(Rn, arrangement: sourceArrangement),
                .unsignedImmediate(value: UInt64(shift), width: 8),
            ],
        )
    }

    /// Map narrowing/lengthening mnemonics to their "2" suffix form
    /// when Q=1. Non-shape-changing mnemonics pass through unchanged.
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
        // SSHLL/USHLL source is B/H/S; .d/.q never reach here in real
        // encodings. Default catches .s (reachable) + sentinels for .d/.q.
        switch elementSize {
        case .b: .h8
        case .h: .s4
        default: .d2 // .s lengthens to .d2; .d/.q sentinel fall-through.
        }
    }
}
