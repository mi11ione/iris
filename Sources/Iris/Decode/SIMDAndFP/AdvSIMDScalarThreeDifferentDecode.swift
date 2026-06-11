// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// AdvSIMD scalar three-different per
// ARM ARM § C4.1.96.15. Encoding:
// `0 1 U 1 1110 size 1 Rm opcode 00 Rn Rd`. Only opcodes 1001 (SQDMLAL),
// 1011 (SQDMLSL), 1101 (SQDMULL) are defined; all others reserved.

enum AdvSIMDScalarThreeDifferentDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let U = UInt8((encoding >> 29) & 0x1)
        let size = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let opcode = UInt8((encoding >> 12) & 0xF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        if U != 0 { return .undefined(at: address, encoding: encoding) }
        // Source size 01 = H → dst S; 10 = S → dst D.
        let (srcSize, dstSize): (ScalarSize, ScalarSize)
        switch size {
        case 0b01: srcSize = .h; dstSize = .s
        case 0b10: srcSize = .s; dstSize = .d
        default: return .undefined(at: address, encoding: encoding)
        }
        let m: Mnemonic
        switch opcode {
        case 0b1001: m = .sqdmlal
        case 0b1011: m = .sqdmlsl
        case 0b1101: m = .sqdmull
        default: return .undefined(at: address, encoding: encoding)
        }
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(Rm, into: reads)
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
                simdfpScalarOperand(Rd, size: dstSize),
                simdfpScalarOperand(Rn, size: srcSize),
                simdfpScalarOperand(Rm, size: srcSize),
            ],
        )
    }
}
