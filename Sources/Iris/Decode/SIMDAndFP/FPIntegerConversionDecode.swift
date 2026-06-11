// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// FP integer conversion per ARM ARM § C4.1.96.34.
// Encoding: `sf 0 0 11110 ftype 1 rmode opcode 000000 Rn Rd`.
// (rmode, opcode) selects the FCVT family + FMOV register-int
// transfers + FJCVTZS + SCVTF/UCVTF (int form).
//
// Mnemonic table (per ARM ARM § C7.2):
//   rmode opcode mnemonic                 direction      ftype constraints
//   00    000    FCVTNS    FP→GPR (signed, nearest-tie-even)
//   00    001    FCVTNU    FP→GPR (unsigned, nearest-tie-even)
//   01    000    FCVTPS    FP→GPR (signed, +∞)
//   01    001    FCVTPU    FP→GPR (unsigned, +∞)
//   10    000    FCVTMS    FP→GPR (signed, -∞)
//   10    001    FCVTMU    FP→GPR (unsigned, -∞)
//   11    000    FCVTZS    FP→GPR (signed, toward 0)
//   11    001    FCVTZU    FP→GPR (unsigned, toward 0)
//   00    100    FCVTAS    FP→GPR (signed, ties away)
//   00    101    FCVTAU    FP→GPR (unsigned, ties away)
//   11    110    FJCVTZS   FP→GPR (signed, JavaScript) — ftype=01 sf=0 only
//   00    010    SCVTF (int)  GPR→FP
//   00    011    UCVTF (int)  GPR→FP
//   00    110    FMOV (FP→GPR)
//   00    111    FMOV (GPR→FP)
//   01    110    FMOV (V.D[1]→X) — ftype=10 sf=1 only
//   01    111    FMOV (X→V.D[1]) — ftype=10 sf=1 only

enum FPIntegerConversionDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let ftype = UInt8((encoding >> 22) & 0x3)
        let rmode = UInt8((encoding >> 19) & 0x3)
        let opcode = UInt8((encoding >> 16) & 0x7)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        // Handle the FMOV V.D[1] ↔ X family first — they have ftype=10
        // (otherwise reserved) and a unique (rmode, opcode) ∈ {(01, 110),
        // (01, 111)}.
        if ftype == 0b10 {
            return decodeFMOVTopHalf(
                encoding: encoding, address: address,
                sf: sf, rmode: rmode, opcode: opcode, Rn: Rn, Rd: Rd,
            )
        }

        // ftype == 0b10 already routed above to decodeFMOVTopHalf; only
        // 00/01/11 reach here.
        let size = scalarSizeFromFtypeNonReserved(ftype)
        let intWidth: RegisterWidth = sf == 1 ? .x64 : .w32

        // FCVT family (FP → GPR int).
        if let mnemonic = fcvtMnemonic(rmode: rmode, opcode: opcode) {
            // FJCVTZS is constrained: sf=0, ftype=01.
            if mnemonic == .fjcvtzs, !(sf == 0 && ftype == 0b01) {
                return .undefined(at: address, encoding: encoding)
            }
            let dstGPR = simdfpGprOperand(encoding: Rd, width: intWidth, spOrGeneral: false)
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: simdfpInsertingVector(Rn, into: .empty),
                semanticWrites: simdfpInsertingNonZeroGPR(reg: dstGPR, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operands: [.register(dstGPR), simdfpScalarOperand(Rn, size: size)],
            )
        }

        // SCVTF/UCVTF int forms.
        if rmode == 0b00, opcode == 0b010 || opcode == 0b011 {
            let mnemonic: Mnemonic = opcode == 0b010 ? .scvtf : .ucvtf
            let srcGPR = simdfpGprOperand(encoding: Rn, width: intWidth, spOrGeneral: false)
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: simdfpInsertingNonZeroGPR(reg: srcGPR, into: .empty),
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operands: [simdfpScalarOperand(Rd, size: size), .register(srcGPR)],
            )
        }

        // FMOV FP→GPR and GPR→FP. ftype determines the FP-side scalar
        // width; sf must match the matching GPR width (H/S require sf=0,
        // D requires sf=1; otherwise reserved).
        if rmode == 0b00, opcode == 0b110 || opcode == 0b111 {
            let fpToGPR = (opcode == 0b110)
            // Width-pair constraint: S ⇒ Wd/Wn (sf=0); D ⇒ Xd/Xn (sf=1);
            // H (FEAT_FP16) has BOTH W↔H (sf=0) and X↔H (sf=1) forms.
            switch size {
            case .s where sf != 0: return .undefined(at: address, encoding: encoding)
            case .d where sf != 1: return .undefined(at: address, encoding: encoding)
            default: break
            }
            let gprWidth: RegisterWidth = sf == 1 ? .x64 : .w32
            if fpToGPR {
                let gpr = simdfpGprOperand(encoding: Rd, width: gprWidth, spOrGeneral: false)
                return DecodedDraft(
                    address: address, encoding: encoding,
                    mnemonic: .fmov,
                    semanticReads: simdfpInsertingVector(Rn, into: .empty),
                    semanticWrites: simdfpInsertingNonZeroGPR(reg: gpr, into: .empty),
                    branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                    flagEffect: .none, category: .simdAndFP,
                    operands: [.register(gpr), simdfpScalarOperand(Rn, size: size)],
                )
            }
            let gpr = simdfpGprOperand(encoding: Rn, width: gprWidth, spOrGeneral: false)
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: .fmov,
                semanticReads: simdfpInsertingNonZeroGPR(reg: gpr, into: .empty),
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operands: [simdfpScalarOperand(Rd, size: size), .register(gpr)],
            )
        }

        return .undefined(at: address, encoding: encoding)
    }

    /// FCVT family: maps (rmode, opcode) → mnemonic when the pair names
    /// an FCVT mnemonic; returns nil otherwise.
    @inline(__always)
    @_effects(readonly)
    private static func fcvtMnemonic(rmode: UInt8, opcode: UInt8) -> Mnemonic? {
        switch (rmode, opcode) {
        case (0b00, 0b000): .fcvtns
        case (0b00, 0b001): .fcvtnu
        case (0b01, 0b000): .fcvtps
        case (0b01, 0b001): .fcvtpu
        case (0b10, 0b000): .fcvtms
        case (0b10, 0b001): .fcvtmu
        case (0b11, 0b000): .fcvtzs
        case (0b11, 0b001): .fcvtzu
        case (0b00, 0b100): .fcvtas
        case (0b00, 0b101): .fcvtau
        case (0b11, 0b110): .fjcvtzs
        default: nil
        }
    }

    /// FMOV V.D[1] ↔ X — ftype=10 sf=1, (rmode, opcode) ∈ {(01,110), (01,111)}.
    @inline(__always)
    @_optimize(speed)
    private static func decodeFMOVTopHalf(
        encoding: UInt32, address: UInt64,
        sf: UInt8, rmode: UInt8, opcode: UInt8, Rn: UInt8, Rd: UInt8,
    ) -> DecodedDraft {
        // ftype=10 is reserved except for these two encodings (with sf=1
        // and rmode=01 and opcode ∈ {110, 111}).
        if sf != 1 || rmode != 0b01 {
            return .undefined(at: address, encoding: encoding)
        }
        switch opcode {
        case 0b110:
            // FMOV X, V.D[1]: dst = X-reg, src = V.D[1] element.
            let gpr = simdfpGprOperand(encoding: Rd, width: .x64, spOrGeneral: false)
            let velt = simdfpElementOperand(Rn, elementSize: .d, index: 1)
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: .fmov,
                semanticReads: simdfpInsertingVector(Rn, into: .empty),
                semanticWrites: simdfpInsertingNonZeroGPR(reg: gpr, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operands: [.register(gpr), velt],
            )
        case 0b111:
            // FMOV V.D[1], X: dst = V.D[1] element, src = X-reg. The
            // destination is destructive — other lane of Vd preserved —
            // so semanticReads contains Rd.
            let gpr = simdfpGprOperand(encoding: Rn, width: .x64, spOrGeneral: false)
            let velt = simdfpElementOperand(Rd, elementSize: .d, index: 1)
            var reads = simdfpInsertingNonZeroGPR(reg: gpr, into: .empty)
            reads = simdfpInsertingVector(Rd, into: reads)
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: .fmov,
                semanticReads: reads,
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operands: [velt, .register(gpr)],
            )
        default:
            return .undefined(at: address, encoding: encoding)
        }
    }
}
