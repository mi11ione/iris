// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// AdvSIMD vector three-same (and FP-family same-shape)
// per ARM ARM § C4.1.96.29 + .23 merged on opcode-range.
// Encoding: `0 Q U 0 1110 size 1 Rm opcode 1 Rn Rd`. Opcode is bits
// [15:11] (5 bits). Bit[10] is the class discriminator (== 1 here).
// FP-family opcodes are 11000..11111 with size[1] selecting variant
// (FMAXNM/FMINNM, FMLA/FMLS, FADD/FSUB, FMULX/(reserved), FCMEQ/
// FCMGE-FACGE-FCMGT-FACGT, FMAX/FMIN, FRECPS/FRSQRTS, FMUL/FDIV).
//
// MOV (vector, register) alias of `ORR Vd.T, Vn.T, Vm.T` when Rm == Rn.
// Mnemonic .mov is reused from DPI's slab.

enum AdvSIMDThreeSameDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let U = UInt8((encoding >> 29) & 0x1)
        let size = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let opcode = UInt8((encoding >> 11) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        // FP-family opcodes (24..31) live in this same class but use the
        // sz=size[0] bit (bit[22]) for precision and size[1]=bit[23] for
        // FMAXNM/FMINNM-style variant disambiguation.
        if opcode >= 0b11000 {
            return decodeFPFamily(
                encoding: encoding, address: address,
                Q: Q, U: U, size: size, opcode: opcode, Rm: Rm, Rn: Rn, Rd: Rd,
            )
        }
        return decodeIntFamily(
            encoding: encoding, address: address,
            Q: Q, U: U, size: size, opcode: opcode, Rm: Rm, Rn: Rn, Rd: Rd,
        )
    }

    @inline(__always)
    @_optimize(speed)
    private static func decodeIntFamily(
        encoding: UInt32, address: UInt64,
        Q: UInt8, U: UInt8, size: UInt8, opcode: UInt8,
        Rm: UInt8, Rn: UInt8, Rd: UInt8,
    ) -> DecodedDraft {
        let arrangement = arrangementFromSizeQ(size: size, Q: Q)
        // Bitwise logical opcodes (16..23 in U=0; bit-select in U=1).
        // These have a unique arrangement constraint: only .8B/.16B
        // (size=00). Higher size combinations are reserved.
        if opcode == 0b00011 {
            // Logical (AND/BIC/ORR/ORN by size). The "size" field selects
            // which logical op: 00=AND, 01=BIC, 10=ORR, 11=ORN (U=0); or
            // EOR/BSL/BIT/BIF (U=1). Arrangement is always .8B/.16B
            // (B-element); the size field is repurposed as op-selector
            // here per ARM ARM § C7.2 .
            let actualArrangement: VectorArrangement = Q == 1 ? .b16 : .b8
            let m = logicalMnemonicByteVec(U: U, size: size)
            // MOV (vector, register) = ORR Vd.T, Vn.T, Vn.T (Rm == Rn).
            let isOrr = (U == 0 && size == 0b10)
            if isOrr, Rm == Rn {
                return makeTwoOperandRecord(
                    address: address, encoding: encoding,
                    mnemonic: .mov, Rd: Rd, Rn: Rn,
                    arrangement: actualArrangement,
                )
            }
            return makeThreeOperandRecord(
                address: address, encoding: encoding,
                mnemonic: m, Rd: Rd, Rn: Rn, Rm: Rm,
                arrangement: actualArrangement,
                destReadsItself: U == 1 && (size == 0b01 || size == 0b10 || size == 0b11),
            )
        }
        // Int three-same proper. (U, opcode) determines mnemonic;
        // arrangement constraint by size+Q.
        let mnemonic = intMnemonic(U: U, opcode: opcode)
        guard let m = mnemonic else {
            return .undefined(at: address, encoding: encoding)
        }
        // Some opcodes don't accept all element sizes (e.g. .SHL family is
        // size != 11). ARM ARM enumerates per opcode; we apply a small
        // set of well-known constraints. The U bit further refines the
        // check — opcode=10011 is MUL (U=0, all non-.1D/.2D sizes) vs
        // PMUL (U=1, only .8B/.16B).
        if !arrangementValidForIntOpcode(U: U, opcode: opcode, arrangement: arrangement) {
            return .undefined(at: address, encoding: encoding)
        }
        let destReadsItself = SIMDFPSemanticAttributes.destinationReadsItself(for: m)
        return makeThreeOperandRecord(
            address: address, encoding: encoding,
            mnemonic: m, Rd: Rd, Rn: Rn, Rm: Rm,
            arrangement: arrangement,
            destReadsItself: destReadsItself,
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
        default: .bif // (U, size) = (1, 0b11) — only remaining combination.
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

    /// Per-opcode arrangement-validity check. Returns false for the
    /// architecturally-reserved (U, opcode, arrangement) combinations.
    @inline(__always)
    @_effects(readonly)
    private static func arrangementValidForIntOpcode(
        U: UInt8, opcode: UInt8, arrangement: VectorArrangement,
    ) -> Bool {
        // .1D (size=11, Q=0) is architecturally reserved for every integer
        // three-same opcode.
        if arrangement == .d1 { return false }
        // SQDMULH / SQRDMULH (opcode 10110): H and S elements only.
        if opcode == 0b10110 {
            return arrangement == .h4 || arrangement == .h8
                || arrangement == .s2 || arrangement == .s4
        }
        // PMUL (U=1, opcode=10011): .8B/.16B only. MUL (U=0): no D element.
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
            // SHADD/SRHADD/SHSUB/MLA/MLS/MAX/MIN/SABD/SABA — reserved at .2D.
            return arrangement != .d2
        default:
            // SQADD/SQSUB/SSHL/SQSHL/SRSHL/SQRSHL/CMGT/CMGE/ADD/CMTST/SUB/
            // CMEQ/ADDP accept all sizes (.2D allowed; .1D rejected above).
            return true
        }
    }

    @inline(__always)
    @_optimize(speed)
    private static func decodeFPFamily(
        encoding: UInt32, address: UInt64,
        Q: UInt8, U: UInt8, size: UInt8, opcode: UInt8,
        Rm: UInt8, Rn: UInt8, Rd: UInt8,
    ) -> DecodedDraft {
        // sz = size[0] (bit[22]): 0 = S, 1 = D.
        let sz = (size & 0b01)
        // bit[23] = size[1] discriminates the FMAXNM/FMINNM-style pairs.
        let altBit = (size >> 1) & 1
        let arrangement: VectorArrangement
        switch (sz, Q) {
        case (0, 0): arrangement = .s2
        case (0, 1): arrangement = .s4
        case (1, 1): arrangement = .d2
        default: return .undefined(at: address, encoding: encoding) // (1,0) = 1D reserved here
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
        // FEAT_FAMINMAX (altBit=1 of 11011) and FEAT_FP8 FSCALE (altBit=1 of 11111).
        case (0, 0b11011, 1): m = .famax
        case (1, 0b11011, 1): m = .famin
        case (1, 0b11111, 1): m = .fscale
        default: return .undefined(at: address, encoding: encoding)
        }
        let destReadsItself = SIMDFPSemanticAttributes.destinationReadsItself(for: m)
        return makeThreeOperandRecord(
            address: address, encoding: encoding,
            mnemonic: m, Rd: Rd, Rn: Rn, Rm: Rm,
            arrangement: arrangement,
            destReadsItself: destReadsItself,
        )
    }

    @inline(__always)
    @_effects(readonly)
    private static func makeThreeOperandRecord(
        address: UInt64, encoding: UInt32, mnemonic: Mnemonic,
        Rd: UInt8, Rn: UInt8, Rm: UInt8,
        arrangement: VectorArrangement,
        destReadsItself: Bool,
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
            operands: [
                simdfpVectorOperand(Rd, arrangement: arrangement),
                simdfpVectorOperand(Rn, arrangement: arrangement),
                simdfpVectorOperand(Rm, arrangement: arrangement),
            ],
        )
    }

    @inline(__always)
    @_effects(readonly)
    private static func makeTwoOperandRecord(
        address: UInt64, encoding: UInt32, mnemonic: Mnemonic,
        Rd: UInt8, Rn: UInt8, arrangement: VectorArrangement,
    ) -> DecodedDraft {
        DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: mnemonic,
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
}
