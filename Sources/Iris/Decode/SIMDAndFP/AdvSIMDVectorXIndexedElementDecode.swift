// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// AdvSIMD vector x-indexed-element per
// ARM ARM § C4.1.96.32. Encoding:
// `0 Q U 0 1111 size L M Rm opcode H 0 Rn Rd`.
// Element-indexed operations: SMLAL/SMLSL/MUL/SMULL/SQDMULL/FMLA/
// FMLS/FMUL/FMULX/SDOT/UDOT/etc. (Vector by-element form.)
//
// The element selector encodes the index into the source vector via
// (L, M, H, size). The exact mapping is per-mnemonic; this decoder
// handles the most common variants (FMLA/FMLS/FMUL/FMULX/MUL/MLA/MLS/
// SMLAL/UMLAL/SMULL/UMULL/SQDMULL/SQDMLAL/SQDMLSL/SQDMULH/SQRDMULH/
// SDOT/UDOT) and emits UNDEFINED for unrecognized (opcode, U) pairs.

enum AdvSIMDVectorXIndexedElementDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let U = UInt8((encoding >> 29) & 0x1)
        let size = UInt8((encoding >> 22) & 0x3)
        let L = UInt8((encoding >> 21) & 0x1)
        let M = UInt8((encoding >> 20) & 0x1)
        let Rm = UInt8((encoding >> 16) & 0xF)
        let opcode = UInt8((encoding >> 12) & 0xF)
        let H = UInt8((encoding >> 11) & 0x1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        // Dot-product by-element forms use a group-element operand
        // (vm.4b/2h[idx]) and their own dst/src shapes; handle them first.
        if let dot = decodeDot(encoding: encoding, address: address) {
            return dot
        }
        // FP8/BF16 FMLAL / FMLALL by-element (single .b/.h element + b/t variant).
        if let fmlal = decodeFmlal(encoding: encoding, address: address) {
            return fmlal
        }
        // FCMLA by-element carries a #rot immediate; handle before the generic
        // FP/int paths (which would route its opcodes to UNDEFINED).
        if let fcmla = decodeFcmla(encoding: encoding, address: address) {
            return fcmla
        }

        // M:Rm forms the full 5-bit register index for the element source.
        let elementReg = (M << 4) | Rm
        // FP-family opcodes per ARM ARM § C4.1.96.32 x-indexed:
        //   FMLA = 0001, FMLS = 0101, FMUL = 1001, FMULX = 1001 (U=1).
        // The shape constraint is size ∈ {00 (H), 10 (S), 11 (D)} where
        // size=00 requires FEAT_FP16 for the half-precision form.
        let isFPFamily = switch opcode {
        case 0b0001, 0b0101, 0b1001:
            true
        default:
            false
        }

        if isFPFamily {
            return decodeFPFamily(
                encoding: encoding, address: address,
                Q: Q, U: U, size: size, L: L, H: H,
                Rm: elementReg, opcode: opcode, Rn: Rn, Rd: Rd,
            )
        }
        return decodeIntFamily(
            encoding: encoding, address: address,
            Q: Q, U: U, size: size, L: L, H: H,
            Rm: elementReg, opcode: opcode, Rn: Rn, Rd: Rd,
        )
    }

    /// Dot-product by-element forms (SDOT/UDOT/USDOT/SUDOT/BFDOT). They use
    /// a group-element operand (`vm.4b[idx]` for the byte dots, `vm.2h[idx]`
    /// for BFDOT) and accumulate into the destination. Returns nil for
    /// non-dot (U, opcode, size) tuples so the caller falls through.
    @inline(__always)
    @_optimize(speed)
    private static func decodeDot(encoding: UInt32, address: UInt64) -> DecodedDraft? {
        let Q = UInt8((encoding >> 30) & 1)
        let U = UInt8((encoding >> 29) & 1)
        let size = UInt8((encoding >> 22) & 3)
        let L = UInt8((encoding >> 21) & 1)
        let M = UInt8((encoding >> 20) & 1)
        let Rm = UInt8((encoding >> 16) & 0xF)
        let opcode = UInt8((encoding >> 12) & 0xF)
        let H = UInt8((encoding >> 11) & 1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        let m: Mnemonic
        let srcElement: ScalarSize
        let groupCount: UInt8
        var dstHalf = false // true → dst .4h/.8h (FP8 fdot 2-way / FP8DOT2)
        switch (U, opcode, size) {
        case (0, 0b1110, 0b10): m = .sdot; srcElement = .b; groupCount = 4
        case (1, 0b1110, 0b10): m = .udot; srcElement = .b; groupCount = 4
        case (0, 0b1111, 0b10): m = .usdot; srcElement = .b; groupCount = 4
        case (0, 0b1111, 0b00): m = .sudot; srcElement = .b; groupCount = 4
        case (0, 0b1111, 0b01): m = .bfdot; srcElement = .h; groupCount = 2
        case (0, 0b0000, 0b00): m = .fdot; srcElement = .b; groupCount = 4 // FP8DOT4
        case (0, 0b0000, 0b01): m = .fdot; srcElement = .b; groupCount = 2; dstHalf = true // FP8DOT2
        default: return nil
        }
        let dstArrangement: VectorArrangement = dstHalf
            ? (Q == 1 ? .h8 : .h4)
            : (Q == 1 ? .s4 : .s2)
        let srcArrangement: VectorArrangement = srcElement == .b
            ? (Q == 1 ? .b16 : .b8)
            : (Q == 1 ? .h8 : .h4)
        // FP8DOT2 (.2b, 8 groups) uses a 3-bit index (H:L:M) and a v0-v15
        // register; the .4b/.2h forms (4 groups) use a 2-bit index (H:L) and
        // a v0-v31 (M:Rm) register.
        let rmReg: UInt8
        let index: UInt8
        if groupCount == 2, srcElement == .b {
            rmReg = Rm
            index = (H << 2) | (L << 1) | M
        } else {
            rmReg = (M << 4) | Rm
            index = (H << 1) | L
        }
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(rmReg, into: reads)
        reads = simdfpInsertingVector(Rd, into: reads) // dot accumulates into Rd
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: m,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operands: [
                simdfpVectorOperand(Rd, arrangement: dstArrangement),
                simdfpVectorOperand(Rn, arrangement: srcArrangement),
                simdfpElementGroupOperand(rmReg, elementSize: srcElement, count: groupCount, index: index),
            ],
        )
    }

    /// FP8/BF16 FMLAL/FMLALL by-element. FMLALB/T (FP8, .8h ← .16b, .b[i]),
    /// BFMLALB/T (BF16, .4s ← .8h, .h[i]), FMLALL{BB,BT,TB,TT} (FP8 4-way,
    /// .4s ← .16b, .b[i]). Q (and size, for FMLALL) selects the bottom/top
    /// variant; all accumulate into Rd. FP8 .b index = (H:L:M)<<1 (even
    /// lanes); BF16 .h index = H:L:M.
    @inline(__always)
    @_optimize(speed)
    private static func decodeFmlal(encoding: UInt32, address: UInt64) -> DecodedDraft? {
        let Q = UInt8((encoding >> 30) & 1)
        let U = UInt8((encoding >> 29) & 1)
        let size = UInt8((encoding >> 22) & 3)
        let L = UInt8((encoding >> 21) & 1)
        let M = UInt8((encoding >> 20) & 1)
        let Rm = UInt8((encoding >> 16) & 0xF)
        let opcode = UInt8((encoding >> 12) & 0xF)
        let H = UInt8((encoding >> 11) & 1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)
        let hlm = (H << 2) | (L << 1) | M // 0..7

        let m: Mnemonic
        let dstArr: VectorArrangement
        let srcArr: VectorArrangement
        let elemSize: ScalarSize
        switch (U, opcode, size) {
        case (0, 0b0000, 0b11): // FMLALB/T (FP8): .8h ← .16b, .b[i]
            m = Q == 1 ? .fmlalt : .fmlalb
            dstArr = .h8; srcArr = .b16; elemSize = .b
        case (0, 0b1111, 0b11): // BFMLALB/T (BF16): .4s ← .8h, .h[i]
            m = Q == 1 ? .bfmlalt : .bfmlalb
            dstArr = .s4; srcArr = .h8; elemSize = .h
        case (1, 0b1000, 0b00): // FMLALL BB/TB (FP8 4-way): .4s ← .16b, .b[i]
            m = Q == 1 ? .fmlalltb : .fmlallbb
            dstArr = .s4; srcArr = .b16; elemSize = .b
        case (1, 0b1000, 0b01): // FMLALL BT/TT
            m = Q == 1 ? .fmlalltt : .fmlallbt
            dstArr = .s4; srcArr = .b16; elemSize = .b
        default:
            return nil
        }
        // FP8 .b element: register v0-v7 (Rm[2:0]), 4-bit index H:L:M:Rm[3].
        // BF16 .h element: register v0-v15 (Rm[3:0]), 3-bit index H:L:M.
        let elemReg: UInt8
        let index: UInt8
        if elemSize == .b {
            elemReg = Rm & 0x7
            index = (hlm << 1) | ((Rm >> 3) & 1)
        } else {
            elemReg = Rm
            index = hlm
        }
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(elemReg, into: reads)
        reads = simdfpInsertingVector(Rd, into: reads) // FMLAL accumulates
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: m,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operands: [
                simdfpVectorOperand(Rd, arrangement: dstArr),
                simdfpVectorOperand(Rn, arrangement: srcArr),
                simdfpElementOperand(elemReg, elementSize: elemSize, index: index),
            ],
        )
    }

    @inline(__always)
    @_optimize(speed)
    private static func decodeFPFamily(
        encoding: UInt32, address: UInt64,
        Q: UInt8, U: UInt8, size: UInt8, L: UInt8, H: UInt8,
        Rm: UInt8, opcode: UInt8, Rn: UInt8, Rd: UInt8,
    ) -> DecodedDraft {
        let m: Mnemonic
        switch (U, opcode) {
        case (0, 0b0001): m = .fmla
        case (0, 0b0101): m = .fmls
        case (0, 0b1001): m = .fmul
        case (1, 0b1001): m = .fmulx
        default: return .undefined(at: address, encoding: encoding)
        }
        // FP by-element precision = size[1:0]: 00 = half (FEAT_FP16, element
        // index H:L:M into a v0-v15 register), 10 = single (index H:L), 11 =
        // double (index H, Q=1 only). 01 and (11 at Q=0 = 1D) are reserved.
        let mBit = (Rm >> 4) & 1
        let arrangement: VectorArrangement
        let elementSize: ScalarSize
        let index: UInt8
        let rmReg: UInt8
        switch (size, Q) {
        case (0b00, 0): arrangement = .h4; elementSize = .h; index = (H << 2) | (L << 1) | mBit; rmReg = Rm & 0xF
        case (0b00, 1): arrangement = .h8; elementSize = .h; index = (H << 2) | (L << 1) | mBit; rmReg = Rm & 0xF
        case (0b10, 0): arrangement = .s2; elementSize = .s; index = (H << 1) | L; rmReg = Rm
        case (0b10, 1): arrangement = .s4; elementSize = .s; index = (H << 1) | L; rmReg = Rm
        case (0b11, 1) where L == 0: arrangement = .d2; elementSize = .d; index = H; rmReg = Rm // D: L is reserved 0
        default: return .undefined(at: address, encoding: encoding)
        }
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
                simdfpVectorOperand(Rd, arrangement: arrangement),
                simdfpVectorOperand(Rn, arrangement: arrangement),
                simdfpElementOperand(rmReg, elementSize: elementSize, index: index),
            ],
        )
    }

    @inline(__always)
    @_optimize(speed)
    private static func decodeIntFamily(
        encoding: UInt32, address: UInt64,
        Q: UInt8, U: UInt8, size: UInt8, L: UInt8, H: UInt8,
        Rm: UInt8, opcode: UInt8, Rn: UInt8, Rd: UInt8,
    ) -> DecodedDraft {
        // Element size from size field (00 = reserved, 01 = H, 10 = S).
        let elementSize: ScalarSize
        let srcArrangement: VectorArrangement
        switch (size, Q) {
        case (0b01, 0): elementSize = .h; srcArrangement = .h4
        case (0b01, 1): elementSize = .h; srcArrangement = .h8
        case (0b10, 0): elementSize = .s; srcArrangement = .s2
        case (0b10, 1): elementSize = .s; srcArrangement = .s4
        default: return .undefined(at: address, encoding: encoding)
        }
        // ARM ARM x-indexed-element H index = M:L:H (bit ordering
        // M=bit[20], L=bit[21], H=bit[11]). Caller passed `Rm` as the
        // full 5-bit composite `(M << 4) | Rm[3:0]`; recover M as
        // `(Rm >> 4) & 1` for use in the index computation.
        let M_bit = (Rm >> 4) & 1
        let index: UInt8
            // elementSize is constrained to .h or .s by the upstream size switch.
            = switch elementSize
        {
        case .h: (H << 2) | (L << 1) | M_bit // 3-bit index H:L:M for H
        default: (H << 1) | L // elementSize == .s
        }
        // For H element, the Rm low 4 bits are the source register (Rm[3:0]).
        let rmReg = elementSize == .h ? Rm & 0xF : Rm

        // (U, opcode) -> mnemonic, ground-truthed against llvm-mc. mla/mls/
        // sqrdmlah/sqrdmlsh live at U=1 (U=0 op0/op4 are fdot/fmlal, handled
        // elsewhere); smlal..sqdmull are the U=0 long forms.
        let m: Mnemonic
        let isLengthening: Bool
        switch (U, opcode) {
        case (0, 0b0010): m = .smlal; isLengthening = true
        case (0, 0b0110): m = .smlsl; isLengthening = true
        case (0, 0b1010): m = .smull; isLengthening = true
        case (0, 0b1011): m = .sqdmull; isLengthening = true
        case (0, 0b0011): m = .sqdmlal; isLengthening = true
        case (0, 0b0111): m = .sqdmlsl; isLengthening = true
        case (0, 0b1000): m = .mul; isLengthening = false
        case (0, 0b1100): m = .sqdmulh; isLengthening = false
        case (0, 0b1101): m = .sqrdmulh; isLengthening = false
        case (1, 0b0000): m = .mla; isLengthening = false
        case (1, 0b0100): m = .mls; isLengthening = false
        case (1, 0b0010): m = .umlal; isLengthening = true
        case (1, 0b0110): m = .umlsl; isLengthening = true
        case (1, 0b1010): m = .umull; isLengthening = true
        case (1, 0b1101): m = .sqrdmlah; isLengthening = false
        case (1, 0b1111): m = .sqrdmlsh; isLengthening = false
        default: return .undefined(at: address, encoding: encoding)
        }

        let dstArrangement: VectorArrangement = if isLengthening {
            // Destination is 2× source element width. elementSize ∈
            // {.h, .s} by upstream constraint; default catches .s
            // (and structurally unreachable sentinels).
            switch elementSize {
            case .h: .s4
            default: .d2 // elementSize == .s (others impossible).
            }
        } else {
            srcArrangement
        }

        // Lengthening by-element forms use the "2" mnemonic for the
        // upper-half (Q=1) source (smlal -> smlal2, etc.).
        let finalMnemonic: Mnemonic = isLengthening && Q == 1 ? lengtheningUpperHalf(m) : m
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(rmReg, into: reads)
        if SIMDFPSemanticAttributes.destinationReadsItself(for: finalMnemonic) {
            reads = simdfpInsertingVector(Rd, into: reads)
        }
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: finalMnemonic,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operands: [
                simdfpVectorOperand(Rd, arrangement: dstArrangement),
                simdfpVectorOperand(Rn, arrangement: srcArrangement),
                simdfpElementOperand(rmReg, elementSize: elementSize, index: index),
            ],
        )
    }

    /// FCMLA by-element (U=1, opcode = 0:rot:0:1, so 0001/0011/0101/0111).
    /// The indexed operand is a single complex element (`vm.s[idx]` /
    /// `vm.h[idx]`) plus a `#rot` immediate (0/90/180/270). Returns nil for
    /// non-fcmla tuples so the caller falls through.
    @inline(__always)
    @_optimize(speed)
    private static func decodeFcmla(encoding: UInt32, address: UInt64) -> DecodedDraft? {
        guard (encoding >> 29) & 1 == 1 else { return nil } // U=1
        let opcode = UInt8((encoding >> 12) & 0xF)
        switch opcode {
        case 0b0001, 0b0011, 0b0101, 0b0111: break
        default: return nil
        }
        let Q = UInt8((encoding >> 30) & 1)
        let size = UInt8((encoding >> 22) & 3)
        let L = UInt8((encoding >> 21) & 1)
        let M = UInt8((encoding >> 20) & 1)
        let Rm = UInt8((encoding >> 16) & 0xF)
        let H = UInt8((encoding >> 11) & 1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)
        let rot = Int64((opcode >> 1) & 0b11) * 90

        let elementSize: ScalarSize
        let arrangement: VectorArrangement
        let index: UInt8
        // By-element FCMLA: .4h (size=01,Q=0; H reserved 0, index=L),
        // .8h (size=01,Q=1; index=H:L), .4s (size=10,Q=1; index=H). The
        // .2s form (size=10,Q=0) is reserved.
        switch (size, Q) {
        case (0b01, 0):
            if H != 0 { return nil }
            elementSize = .h; arrangement = .h4; index = L
        case (0b01, 1): elementSize = .h; arrangement = .h8; index = (H << 1) | L
        case (0b10, 1):
            if L != 0 { return nil } // .4s index is H only; L is reserved 0
            elementSize = .s; arrangement = .s4; index = H
        default: return nil
        }
        let rmReg = (M << 4) | Rm
        var reads = simdfpInsertingVector(Rn, into: .empty)
        reads = simdfpInsertingVector(rmReg, into: reads)
        reads = simdfpInsertingVector(Rd, into: reads) // accumulates into Rd
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: .fcmla,
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operands: [
                simdfpVectorOperand(Rd, arrangement: arrangement),
                simdfpVectorOperand(Rn, arrangement: arrangement),
                simdfpElementOperand(rmReg, elementSize: elementSize, index: index),
                .immediate(value: rot, width: 16),
            ],
        )
    }

    /// Maps a lengthening by-element base mnemonic to its upper-half
    /// ("2") form. Callers gate on `isLengthening`, so the argument is
    /// always one of the nine lengthening mnemonics.
    @inline(__always)
    @_effects(readonly)
    private static func lengtheningUpperHalf(_ m: Mnemonic) -> Mnemonic {
        switch m {
        case .smlal: .smlal2
        case .smlsl: .smlsl2
        case .smull: .smull2
        case .sqdmlal: .sqdmlal2
        case .sqdmlsl: .sqdmlsl2
        case .sqdmull: .sqdmull2
        case .umlal: .umlal2
        case .umlsl: .umlsl2
        default: .umull2 // .umull — the only remaining lengthening mnemonic.
        }
    }
}
