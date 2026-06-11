// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// AdvSIMD vector two-reg-misc per ARM ARM § C4.1.96.26 + .24
// (FP16 merged on opcode-range).
// Encoding: `0 Q U 0 1110 size 10000 opcode 10 Rn Rd`. opcode at
// bits[16:12] (5 bits). The class includes REV*/CLS/CNT/CMxx-zero/
// ABS/NEG/XTN/SQXTN/FCVT*/FRINT*/FCM*-zero/FABS/FNEG/FSQRT/etc., plus
// .NOT (aliased to MVN). The MVN-vs-NOT direction matches llvm-mc,
// which emits MVN.

enum AdvSIMDTwoRegMiscDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let U = UInt8((encoding >> 29) & 0x1)
        let size = UInt8((encoding >> 22) & 0x3)
        let opcode = UInt8((encoding >> 12) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        // FP-family opcodes for two-reg-misc are:
        //   - 11000..11111 (FRINT*, FCVT*, SCVTF, UCVTF, FRECPE, FRSQRTE,
        //     FSQRT) — always FP family regardless of bit[23]
        //   - 01100..01111 (FCMxx-zero, FABS, FNEG) — FP family ONLY when
        //     bit[23] = 1 (the FP-family marker within size). With
        //     bit[23] = 0 those opcodes belong to the integer family but
        //     are unmapped there → reserved.
        let bit23 = (size >> 1) & 1
        if opcode >= 0b11000 || (opcode >= 0b01100 && opcode <= 0b01111 && bit23 == 1) {
            return decodeFPFamily(
                encoding: encoding, address: address,
                Q: Q, U: U, size: size, opcode: opcode, Rn: Rn, Rd: Rd,
            )
        }

        // FP convert narrow/long (FCVTN/FCVTL/FCVTXN) — opcode 10110/10111
        // carry FP-specific narrowing/lengthening shapes (dst/src differ in
        // both element size and width), so they bypass the integer table.
        if opcode == 0b10110 || opcode == 0b10111 {
            return decodeFPConvertNarrowLong(
                encoding: encoding, address: address,
                Q: Q, U: U, size: size, opcode: opcode, Rn: Rn, Rd: Rd,
            )
        }

        let mnemonicAndShape = intMnemonicAndDstShape(
            U: U, opcode: opcode, size: size, Q: Q,
        )
        guard let (m, dstArrangement, srcArrangement) = mnemonicAndShape else {
            return .undefined(at: address, encoding: encoding)
        }
        let destReadsItself = SIMDFPSemanticAttributes.destinationReadsItself(for: m)
        var reads = simdfpInsertingVector(Rn, into: .empty)
        if destReadsItself {
            reads = simdfpInsertingVector(Rd, into: reads)
        }

        // CM*-zero forms render with a #0 second operand.
        let zeroForm = isZeroCompareForm(U: U, opcode: opcode)
        var operands: [Operand] = []
        operands.reserveCapacity(zeroForm ? 3 : 2)
        operands.append(simdfpVectorOperand(Rd, arrangement: dstArrangement))
        operands.append(simdfpVectorOperand(Rn, arrangement: srcArrangement))
        if zeroForm {
            operands.append(.unsignedImmediate(value: 0, width: 1))
        }
        // SHLL shifts by the source element width (8/16/32 for .8b/.4h/.2s).
        if m == .shll || m == .shll2 {
            operands.append(.unsignedImmediate(value: UInt64(8) << UInt64(size), width: 8))
        }

        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: m,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operands: operands,
        )
    }

    @inline(__always)
    @_effects(readonly)
    private static func isZeroCompareForm(U: UInt8, opcode: UInt8) -> Bool {
        switch (U, opcode) {
        case (0, 0b01000), // CMGT zero
             (0, 0b01001), // CMEQ zero
             (0, 0b01010), // CMLT zero
             (1, 0b01000), // CMGE zero
             (1, 0b01001), // CMLE zero
             (0, 0b01101), // FCMGT zero (FP)
             (0, 0b01110), // FCMEQ zero (FP)
             (0, 0b01111), // FCMLT zero (FP)
             (1, 0b01100), // FCMGE zero (FP)
             (1, 0b01101): // FCMLE zero (FP)
            true
        default:
            false
        }
    }

    /// Map (U, opcode, size, Q) → (mnemonic, destinationArrangement).
    /// Some mnemonics widen (XTN/SQXTN) or narrow (SHLL) the destination;
    /// the rest preserve the source arrangement.
    @inline(__always)
    @_effects(readonly)
    private static func intMnemonicAndDstShape(
        U: UInt8, opcode: UInt8, size: UInt8, Q: UInt8,
    ) -> (Mnemonic, VectorArrangement, VectorArrangement)? {
        let same = arrangementFromSizeQ(size: size, Q: Q)
        // Pairwise-long: dst element doubles (.8b→.4h, .4h→.2s, .2s→.1d).
        let longDst = arrangementFromSizeQ(size: (size &+ 1) & 0x3, Q: Q)
        // Narrowing: src is the 2×-wide 128-bit form; dst is narrowArrangement
        // (Q selects 64-bit low half vs the "2" 128-bit upper half).
        let narrowDst = narrowArrangement(size: size, Q: Q)
        let wideSrc = arrangementFromSizeQ(size: (size &+ 1) & 0x3, Q: 1)
        let m: Mnemonic
        var dstArrangement = same
        var srcArrangement = same
        switch (U, opcode) {
        case (0, 0b00000): m = .rev64
        case (0, 0b00001): m = .rev16 // reused from DPR
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
        case (0, 0b10010): // XTN / XTN2 — narrowing.
            m = Q == 1 ? .xtn2 : .xtn; dstArrangement = narrowDst; srcArrangement = wideSrc
        case (0, 0b10100): // SQXTN / SQXTN2 — narrowing.
            m = Q == 1 ? .sqxtn2 : .sqxtn; dstArrangement = narrowDst; srcArrangement = wideSrc
        case (1, 0b10011): // SHLL / SHLL2 — widening (U=1; size=11 reserved).
            m = Q == 1 ? .shll2 : .shll
            dstArrangement = widenArrangement(size: size)
        case (1, 0b00000): m = .rev32 // reused from DPR
        case (1, 0b00010): m = .uaddlp; dstArrangement = longDst
        case (1, 0b00011): m = .usqadd
        case (1, 0b00100): m = .clz
        case (1, 0b00110): m = .uadalp; dstArrangement = longDst
        case (1, 0b00111): m = .sqneg
        case (1, 0b01000): m = .cmge
        case (1, 0b01001): m = .cmle
        case (1, 0b01011): m = .neg
        case (1, 0b10010): // SQXTUN / SQXTUN2 — narrowing (U=1, opcode 10010).
            m = Q == 1 ? .sqxtun2 : .sqxtun; dstArrangement = narrowDst; srcArrangement = wideSrc
        case (1, 0b10100): // UQXTN / UQXTN2 — narrowing (U=1, opcode 10100).
            m = Q == 1 ? .uqxtn2 : .uqxtn; dstArrangement = narrowDst; srcArrangement = wideSrc
        case (1, 0b00101): // MVN (size=00) / RBIT (size=01) — both .8B/.16B.
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
        // Per-opcode size validity. Narrowing / pairwise-long / CLS-CLZ have
        // no size=11; REV16/CNT are byte-only; REV32 is 8/16-bit.
        let sizeOK: Bool = switch (U, opcode) {
        case (0, 0b00000): size != 0b11 // rev64
        case (1, 0b00000): size <= 0b01 // rev32 (.8b/.4h)
        case (0, 0b00001): size == 0b00 // rev16 (.8b)
        case (0, 0b00101): size == 0b00 // cnt (.8b)
        case (0, 0b00010), (1, 0b00010), // saddlp / uaddlp
             (0, 0b00110), (1, 0b00110), // sadalp / uadalp
             (0, 0b00100), (1, 0b00100), // cls / clz
             (0, 0b10010), (1, 0b10010), // xtn / uqxtn
             (0, 0b10100), (1, 0b10100), // sqxtn / sqxtun
             (1, 0b10011): // shll
            size != 0b11
        // Same-shape ops (suqadd/sqabs/cmgt/cmeq/cmlt/abs/cmge/cmle/neg/
        // usqadd/sqneg) allow .2D (size=11, Q=1) but never .1D (size=11, Q=0).
        default: !(size == 0b11 && Q == 0)
        }
        guard sizeOK else { return nil }
        return (m, dstArrangement, srcArrangement)
    }

    @inline(__always)
    @_effects(readonly)
    private static func narrowArrangement(size: UInt8, Q: UInt8) -> VectorArrangement {
        // Narrowing destination is half-element-width at the same lane
        // count (.4H → .4H from .4S, but the destination is at the same
        // total byte width: .8B from .8H, etc., with the "2" form using
        // Q=1). size=11 isn't a valid narrowing source (no narrower
        // arrangement exists below B-element); callers route it via the
        // size-11 reserved predicate upstream. The fallback returns .b8
        // as a sentinel — the caller's upstream check prevents emit.
        let idx = Int(((size & 0x3) << 1) | (Q & 0x1))
        return narrowArrangementTable[idx]
    }

    @inline(__always)
    @_effects(readonly)
    private static func widenArrangement(size: UInt8) -> VectorArrangement {
        // SHLL produces 2× source byte-width destination. size=11 (D
        // source) doesn't exist architecturally; the default absorbs
        // size=10 (S→D) and the unreachable size=11 sentinel.
        switch size & 0x3 {
        case 0b00: .h8
        case 0b01: .s4
        default: .d2 // size=10 (S→D); size=11 unreachable.
        }
    }

    private static let narrowArrangementTable: [VectorArrangement] = [
        .b8, .b16, .h4, .h8, .s2, .s4,
        .b8, .b8, // size=11 sentinels (upstream filters via reserved check)
    ]

    /// FP16 two-register miscellaneous (.4h/.8h). A distinct encoding from
    /// the FP32/64 two-reg-misc: bits[21:17]=11100, bit22=1; bit23 is the
    /// altBit. The (U, opcode, altBit) table mirrors the FP32/64 family
    /// minus URECPE/URSQRTE (op 11100, alt=1 — .2s/.4s integer-recip only)
    /// and FRINT32/64. Routed by the dispatcher at bits[20:17]=1100.
    static func decodeFP16TwoRegMisc(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 1)
        let U = UInt8((encoding >> 29) & 1)
        let altBit = UInt8((encoding >> 23) & 1)
        let opcode = UInt8((encoding >> 12) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)
        // bit22 is the FP16 marker (always 1); bit22=0 is reserved here.
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
        var operands: [Operand] = [
            simdfpVectorOperand(Rd, arrangement: arrangement),
            simdfpVectorOperand(Rn, arrangement: arrangement),
        ]
        if zeroForm {
            operands.append(.floatImmediate(bits: 0, kind: .half))
        }
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: m,
            semanticReads: simdfpInsertingVector(Rn, into: .empty),
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operands: operands,
        )
    }

    /// FCVTN/FCVTL/FCVTXN — FP convert with size-changing operand shapes.
    /// sz = bit[22]: 0 ⇒ half↔single, 1 ⇒ single↔double. bit[23] is SBZ.
    /// Q selects the "2" (upper-half) form for the narrow operand.
    @inline(__always)
    @_effects(readonly)
    private static func decodeFPConvertNarrowLong(
        encoding: UInt32, address: UInt64,
        Q: UInt8, U: UInt8, size: UInt8, opcode: UInt8, Rn: UInt8, Rd: UInt8,
    ) -> DecodedDraft {
        let bit23 = (size >> 1) & 1
        let sz = size & 1
        let m: Mnemonic
        let dstArr: VectorArrangement
        let srcArr: VectorArrangement
        // FP8 → FP16/BF16 long convert (FEAT_FP8): U=1, opcode=10111; the
        // full size field selects the format. dst .8h, src .8b/.16b (Q→"2").
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
                operands: [
                    simdfpVectorOperand(Rd, arrangement: .h8),
                    simdfpVectorOperand(Rn, arrangement: Q == 1 ? .b16 : .b8),
                ],
            )
        }
        switch (U, opcode, bit23) {
        case (0, 0b10110, 0): // FCVTN/FCVTN2 — narrow (.4s→.4h / .2d→.2s).
            m = Q == 1 ? .fcvtn2 : .fcvtn
            dstArr = sz == 0 ? (Q == 1 ? .h8 : .h4) : (Q == 1 ? .s4 : .s2)
            srcArr = sz == 0 ? .s4 : .d2
        case (0, 0b10111, 0): // FCVTL/FCVTL2 — lengthen (.4h→.4s / .2s→.2d).
            m = Q == 1 ? .fcvtl2 : .fcvtl
            dstArr = sz == 0 ? .s4 : .d2
            srcArr = sz == 0 ? (Q == 1 ? .h8 : .h4) : (Q == 1 ? .s4 : .s2)
        case (1, 0b10110, 0): // FCVTXN/FCVTXN2 — narrow round-to-odd (.2d→.2s only).
            if sz != 1 { return .undefined(at: address, encoding: encoding) }
            m = Q == 1 ? .fcvtxn2 : .fcvtxn
            dstArr = Q == 1 ? .s4 : .s2
            srcArr = .d2
        case (0, 0b10110, 1): // BFCVTN/BFCVTN2 — BF16 narrow (.4s→.4h, size=10).
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
            operands: [
                simdfpVectorOperand(Rd, arrangement: dstArr),
                simdfpVectorOperand(Rn, arrangement: srcArr),
            ],
        )
    }

    @inline(__always)
    @_optimize(speed)
    private static func decodeFPFamily(
        encoding: UInt32, address: UInt64,
        Q: UInt8, U: UInt8, size: UInt8, opcode: UInt8,
        Rn: UInt8, Rd: UInt8,
    ) -> DecodedDraft {
        // FP family two-reg-misc — sz = size[0] (bit[22]).
        let sz = size & 1
        let altBit = (size >> 1) & 1
        let arrangement: VectorArrangement
        switch (sz, Q) {
        case (0, 0): arrangement = .s2
        case (0, 1): arrangement = .s4
        case (1, 1): arrangement = .d2
        default: return .undefined(at: address, encoding: encoding)
        }
        // FP opcodes (per ARM ARM § C7.2):
        //   00000 FRINTN  00001 FRINTM  00010 FCVTNS  00011 FCVTMS
        //   00100 FCVTAS  00101 SCVTF  ...  01100 FCMGT0  01101 FCMEQ0
        //   01110 FCMLT0  01111 FABS   10000 FRINTP   10001 FRINTZ
        //   10010 FCVTPS  10011 FCVTZS 10100 URECPE  10101 FRECPE
        //   ... 11000 ... etc. Truncated — handle most common opcodes;
        // others fall through to UNDEFINED.
        // FEAT_FRINTTS frint32/64 (opcode 11110, bit23=0): sz selects 32-bit
        // (.2s/.4s) vs 64-bit (.2d); U selects Z (toward zero) vs X (current).
        if opcode == 0b11110 || opcode == 0b11111, altBit == 0 {
            // FEAT_FRINTTS: opcode 11110 = frint32, 11111 = frint64; U picks
            // z (toward zero) vs x (current mode). sz/Q give .2s/.4s/.2d.
            let is64 = opcode == 0b11111
            let fm: Mnemonic = switch (U, is64) {
            case (0, false): .frint32z
            case (1, false): .frint32x
            case (0, true): .frint64z
            default: .frint64x // (1, true) — U is a single bit.
            }
            return DecodedDraft(
                address: address, encoding: encoding, mnemonic: fm,
                semanticReads: simdfpInsertingVector(Rn, into: .empty),
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operands: [
                    simdfpVectorOperand(Rd, arrangement: arrangement),
                    simdfpVectorOperand(Rn, arrangement: arrangement),
                ],
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
        // FRECPE per ARM ARM is U=0, opcode=11101 with altBit=1.
        case (0, 0b11101, 1): m = .frecpe
        // URECPE per ARM ARM is U=0, opcode=11100 with altBit=1 (integer
        // reciprocal estimate, lives in this FP-family branch by encoding
        // bit 23 = 1).
        case (0, 0b11100, 1): m = .urecpe
        // FCMxx-zero, FABS, FNEG have bit[23] = 1 always (FP family marker
        // within the size field) ⇒ altBit = 1.
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
        // FRSQRTE per ARM ARM is U=1, opcode=11101 with altBit=1.
        case (1, 0b11101, 1): m = .frsqrte
        // URSQRTE per ARM ARM is U=1, opcode=11100 with altBit=1.
        case (1, 0b11100, 1): m = .ursqrte
        // FSQRT per ARM ARM is U=1, opcode=11111 with altBit=1.
        case (1, 0b11111, 1): m = .fsqrt
        case (1, 0b01100, 1): m = .fcmge
        case (1, 0b01101, 1): m = .fcmle
        case (1, 0b01111, 1): m = .fneg
        default:
            return .undefined(at: address, encoding: encoding)
        }
        // URECPE/URSQRTE are integer reciprocal estimates on .2s/.4s only
        // (sz=0); the .2d (sz=1) form is reserved.
        if m == .urecpe || m == .ursqrte, sz != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        // FCMx-zero forms render with a #0.0 second operand.
        let zeroForm = switch m {
        case .fcmgt, .fcmeq, .fcmlt, .fcmge, .fcmle:
            true
        default:
            false
        }
        var operands: [Operand] = []
        operands.reserveCapacity(zeroForm ? 3 : 2)
        operands.append(simdfpVectorOperand(Rd, arrangement: arrangement))
        operands.append(simdfpVectorOperand(Rn, arrangement: arrangement))
        if zeroForm {
            let fpKind: FloatImmediateKind = sz == 0 ? .single : .double
            operands.append(.floatImmediate(bits: 0, kind: fpKind))
        }
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: m,
            semanticReads: simdfpInsertingVector(Rn, into: .empty),
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operands: operands,
        )
    }
}
