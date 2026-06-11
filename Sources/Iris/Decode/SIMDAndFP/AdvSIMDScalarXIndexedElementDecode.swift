// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// AdvSIMD scalar x-indexed-element per
// ARM ARM § C4.1.96.18. Encoding:
// `0 1 U 1 1111 size L M Rm opcode H 0 Rn Rd`. Scalar element-indexed
// multiply/multiply-accumulate variants: SQDMLAL/SQDMLSL/SQDMULL/
// SQDMULH/SQRDMULH/FMLA/FMLS/FMUL/FMULX/SQRDMLAH/SQRDMLSH.

enum AdvSIMDScalarXIndexedElementDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let U = UInt8((encoding >> 29) & 0x1)
        let size = UInt8((encoding >> 22) & 0x3)
        let L = UInt8((encoding >> 21) & 0x1)
        let M = UInt8((encoding >> 20) & 0x1)
        let Rm = UInt8((encoding >> 16) & 0xF)
        let opcode = UInt8((encoding >> 12) & 0xF)
        let H = UInt8((encoding >> 11) & 0x1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        let isFPFamily = switch opcode {
        case 0b0001, 0b0101, 0b1001:
            true
        default:
            false
        }
        if isFPFamily {
            // size selects precision: 00 = H (FP16, index H:L:M, Rm in
            // v0..v15), 10 = S (index H:L), 11 = D (index H, L reserved 0).
            // 01 is reserved.
            let elementSize: ScalarSize
            let index: UInt8
            let elementReg: UInt8
            switch size {
            case 0b00: elementSize = .h; index = (H << 2) | (L << 1) | M; elementReg = Rm & 0xF
            case 0b10: elementSize = .s; index = (H << 1) | L; elementReg = (M << 4) | Rm
            case 0b11 where L == 0: elementSize = .d; index = H; elementReg = (M << 4) | Rm
            default: return .undefined(at: address, encoding: encoding)
            }
            let m: Mnemonic
            switch (U, opcode) {
            case (0, 0b0001): m = .fmla
            case (0, 0b0101): m = .fmls
            case (0, 0b1001): m = .fmul
            case (1, 0b1001): m = .fmulx
            default: return .undefined(at: address, encoding: encoding)
            }
            var reads = simdfpInsertingVector(Rn, into: .empty)
            reads = simdfpInsertingVector(elementReg, into: reads)
            if SIMDFPSemanticAttributes.destinationReadsItself(for: m) {
                reads = simdfpInsertingVector(Rd, into: reads)
            }
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: m,
                semanticReads: reads,
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operands: [
                    simdfpScalarOperand(Rd, size: elementSize),
                    simdfpScalarOperand(Rn, size: elementSize),
                    simdfpElementOperand(elementReg, elementSize: elementSize, index: index),
                ],
            )
        }
        // Integer family (SQDMLAL/SQDMLSL/SQDMULL/SQDMULH/SQRDMULH/...).
        let (srcSize, dstSize): (ScalarSize, ScalarSize)
        switch size {
        case 0b01: srcSize = .h; dstSize = .s
        case 0b10: srcSize = .s; dstSize = .d
        default: return .undefined(at: address, encoding: encoding)
        }
        let elementReg = (M << 4) | Rm
        let rmReg = srcSize == .h ? Rm & 0xF : elementReg
        // ARM ARM x-indexed-element H-element index = H:L:M (H is the most-
        // significant bit of the 3-bit index). srcSize is constrained to
        // .h or .s by the size-switch above.
        let index: UInt8 = switch srcSize {
        case .h: (H << 2) | (L << 1) | M
        default: (H << 1) | L // srcSize == .s
        }
        let m: Mnemonic
        var isLengthening = true
        switch (U, opcode) {
        case (0, 0b0011): m = .sqdmlal
        case (0, 0b0111): m = .sqdmlsl
        case (0, 0b1011): m = .sqdmull
        case (0, 0b1100): m = .sqdmulh; isLengthening = false
        case (0, 0b1101): m = .sqrdmulh; isLengthening = false
        case (1, 0b1101): m = .sqrdmlah; isLengthening = false
        case (1, 0b1111): m = .sqrdmlsh; isLengthening = false
        default: return .undefined(at: address, encoding: encoding)
        }
        let resultSize = isLengthening ? dstSize : srcSize
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(rmReg, into: reads)
        if SIMDFPSemanticAttributes.destinationReadsItself(for: m) {
            reads = simdfpInsertingVector(Rd, into: reads)
        }
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: m,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operands: [
                simdfpScalarOperand(Rd, size: resultSize),
                simdfpScalarOperand(Rn, size: srcSize),
                simdfpElementOperand(rmReg, elementSize: srcSize, index: index),
            ],
        )
    }
}
