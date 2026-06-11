// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// AdvSIMD scalar shift-by-immediate per
// ARM ARM § C4.1.96.17. Encoding: `0 1 U 1 1111 0 immh immb opcode 1
// Rn Rd` with immh != 0000. Scalar form of the vector shift-by-imm
// class — operands are scalar registers at the element size encoded by
// immh's first-set-bit. Only D-element forms are valid for most opcodes;
// narrowing/widening variants accept smaller element sizes.

enum AdvSIMDScalarShiftByImmediateDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let U = UInt8((encoding >> 29) & 0x1)
        let immh = UInt8((encoding >> 19) & 0xF)
        let immb = UInt8((encoding >> 16) & 0x7)
        let opcode = UInt8((encoding >> 11) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        if immh == 0 { return .undefined(at: address, encoding: encoding) }
        // bit23 is a fixed 0 for shift-by-immediate; bit23=1 is reserved.
        if (encoding >> 23) & 1 == 1 { return .undefined(at: address, encoding: encoding) }
        // Determine element size from first-set-bit of immh.
        let elementSize: ScalarSize = if (immh & 0b1000) != 0 { .d }
        else if (immh & 0b0100) != 0 { .s }
        else if (immh & 0b0010) != 0 { .h }
        else { .b }
        let elementBits = UInt32(elementSize.byteWidth) * 8
        let immhb = (UInt32(immh) << 3) | UInt32(immb)

        // Determine mnemonic + shift direction. Most scalar shift ops are
        // D-element only (so elementSize must be .d); the narrowing /
        // saturating-narrow ops accept smaller element sizes.
        let info = mnemonicAndShift(U: U, opcode: opcode)
        guard let resolved = info else {
            return .undefined(at: address, encoding: encoding)
        }
        // SCVTF / FCVTZS / FCVTZU shift family is scalar FP form: source
        // & dest are FP scalars at the determined size (not B). For
        // most other scalar shifts, D-element is required.
        if resolved.requiresDOnly, elementSize != .d {
            return .undefined(at: address, encoding: encoding)
        }
        // SCVTF/UCVTF/FCVTZS/FCVTZU scalar shift-by-imm accept H/S/D
        // element sizes (fullfp16 for H); .b (immh=0001) is reserved.
        if elementSize == .b,
           resolved.mnemonic == .scvtf || resolved.mnemonic == .ucvtf
           || resolved.mnemonic == .fcvtzs || resolved.mnemonic == .fcvtzu
        {
            return .undefined(at: address, encoding: encoding)
        }
        let shift = switch resolved.direction {
        case .left: UInt8(immhb &- elementBits)
        case .right: UInt8((elementBits &* 2) &- immhb)
        }

        // Narrowing scalar shifts (SQSHRN/UQSHRN/SQSHRUN and rounding forms)
        // read a source element twice the dest width; `elementSize` is the
        // dest. A .d dest (immh=1xxx) would need a .q source and is reserved.
        let isNarrowing = switch resolved.mnemonic {
        case .sqshrn, .sqrshrn, .uqshrn, .uqrshrn, .sqshrun, .sqrshrun: true
        default: false
        }
        let srcSize: ScalarSize
        if isNarrowing {
            switch elementSize {
            case .b: srcSize = .h
            case .h: srcSize = .s
            case .s: srcSize = .d
            default: return .undefined(at: address, encoding: encoding)
            }
        } else {
            srcSize = elementSize
        }

        let destReadsItself = SIMDFPSemanticAttributes.destinationReadsItself(for: resolved.mnemonic)
        var reads = simdfpInsertingVector(Rn, into: .empty)
        if destReadsItself {
            reads = simdfpInsertingVector(Rd, into: reads)
        }
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: resolved.mnemonic,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operands: [
                simdfpScalarOperand(Rd, size: elementSize),
                simdfpScalarOperand(Rn, size: srcSize),
                .unsignedImmediate(value: UInt64(shift), width: 8),
            ],
        )
    }

    private struct ResolvedMnemonic {
        let mnemonic: Mnemonic
        let direction: ShiftDirection
        let requiresDOnly: Bool
    }

    private enum ShiftDirection { case left, right }

    @inline(__always)
    @_effects(readonly)
    private static func mnemonicAndShift(U: UInt8, opcode: UInt8) -> ResolvedMnemonic? {
        switch (U, opcode) {
        case (0, 0b00000): .init(mnemonic: .sshr, direction: .right, requiresDOnly: true)
        case (0, 0b00010): .init(mnemonic: .ssra, direction: .right, requiresDOnly: true)
        case (0, 0b00100): .init(mnemonic: .srshr, direction: .right, requiresDOnly: true)
        case (0, 0b00110): .init(mnemonic: .srsra, direction: .right, requiresDOnly: true)
        case (0, 0b01010): .init(mnemonic: .shl, direction: .left, requiresDOnly: true)
        case (0, 0b01110): .init(mnemonic: .sqshl, direction: .left, requiresDOnly: false)
        case (0, 0b10010): .init(mnemonic: .sqshrn, direction: .right, requiresDOnly: false)
        case (0, 0b10011): .init(mnemonic: .sqrshrn, direction: .right, requiresDOnly: false)
        case (0, 0b11100): .init(mnemonic: .scvtf, direction: .right, requiresDOnly: false)
        case (0, 0b11111): .init(mnemonic: .fcvtzs, direction: .right, requiresDOnly: false)
        case (1, 0b00000): .init(mnemonic: .ushr, direction: .right, requiresDOnly: true)
        case (1, 0b00010): .init(mnemonic: .usra, direction: .right, requiresDOnly: true)
        case (1, 0b00100): .init(mnemonic: .urshr, direction: .right, requiresDOnly: true)
        case (1, 0b00110): .init(mnemonic: .ursra, direction: .right, requiresDOnly: true)
        case (1, 0b01000): .init(mnemonic: .sri, direction: .right, requiresDOnly: true)
        case (1, 0b01010): .init(mnemonic: .sli, direction: .left, requiresDOnly: true)
        case (1, 0b01100): .init(mnemonic: .sqshlu, direction: .left, requiresDOnly: false)
        case (1, 0b01110): .init(mnemonic: .uqshl, direction: .left, requiresDOnly: false)
        case (1, 0b10000): .init(mnemonic: .sqshrun, direction: .right, requiresDOnly: false)
        case (1, 0b10001): .init(mnemonic: .sqrshrun, direction: .right, requiresDOnly: false)
        case (1, 0b10010): .init(mnemonic: .uqshrn, direction: .right, requiresDOnly: false)
        case (1, 0b10011): .init(mnemonic: .uqrshrn, direction: .right, requiresDOnly: false)
        case (1, 0b11100): .init(mnemonic: .ucvtf, direction: .right, requiresDOnly: false)
        case (1, 0b11111): .init(mnemonic: .fcvtzu, direction: .right, requiresDOnly: false)
        default: nil
        }
    }
}
