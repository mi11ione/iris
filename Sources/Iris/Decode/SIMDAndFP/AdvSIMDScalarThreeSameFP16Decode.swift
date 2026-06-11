/// Copyright (c) 2026 Roman Zhuzhgov
/// Licensed under the Apache License, Version 2.0
///
/// AdvSIMD scalar three-same FP16 and scalar three-same-extra (RDM). Both
/// live in the scalar 0x5E/0x7E tier at bit21=0. Scalar three-same FP16:
/// `01 U 11110 a 10 Rm 00 op3 1 Rn Rd` (bit22=1, bits[15:14]=00, bit10=1),
/// half-precision scalar (.h). Scalar three-same-extra: `01 1 11110 size 0
/// Rm 1000 x 1 Rn Rd` (bit15=1, bit10=1) — SQRDMLAH/SQRDMLSH, scalar .h
/// (size=01) or .s (size=10).
enum AdvSIMDScalarThreeSameFP16Decode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let U = UInt8((encoding >> 29) & 1)
        let a = UInt8((encoding >> 23) & 1)
        let op3 = UInt8((encoding >> 11) & 0x7)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        let m: Mnemonic
        switch (U, a, op3) {
        case (0, 0, 3): m = .fmulx
        case (0, 0, 4): m = .fcmeq
        case (0, 0, 7): m = .frecps
        case (0, 1, 7): m = .frsqrts
        case (1, 0, 4): m = .fcmge
        case (1, 0, 5): m = .facge
        case (1, 1, 2): m = .fabd
        case (1, 1, 4): m = .fcmgt
        case (1, 1, 5): m = .facgt
        default: return .undefined(at: address, encoding: encoding)
        }
        return make(m: m, size: .h, accumulates: false, Rm: Rm, Rn: Rn, Rd: Rd, encoding: encoding, address: address)
    }

    @_optimize(speed)
    static func decodeRDM(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let U = UInt8((encoding >> 29) & 1)
        let size = UInt8((encoding >> 22) & 0x3)
        let op5 = UInt8((encoding >> 11) & 0x1F)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        guard U == 1 else { return .undefined(at: address, encoding: encoding) }
        let m: Mnemonic
        switch op5 {
        case 0b10000: m = .sqrdmlah
        case 0b10001: m = .sqrdmlsh
        default: return .undefined(at: address, encoding: encoding)
        }
        let elementSize: ScalarSize
        switch size {
        case 0b01: elementSize = .h
        case 0b10: elementSize = .s
        default: return .undefined(at: address, encoding: encoding)
        }
        return make(m: m, size: elementSize, accumulates: true, Rm: Rm, Rn: Rn, Rd: Rd, encoding: encoding, address: address)
    }

    @inline(__always)
    private static func make(
        m: Mnemonic, size: ScalarSize, accumulates: Bool,
        Rm: UInt8, Rn: UInt8, Rd: UInt8, encoding: UInt32, address: UInt64,
    ) -> DecodedDraft {
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(Rm, into: reads)
        if accumulates {
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
                simdfpScalarOperand(Rd, size: size),
                simdfpScalarOperand(Rn, size: size),
                simdfpScalarOperand(Rm, size: size),
            ],
        )
    }
}
