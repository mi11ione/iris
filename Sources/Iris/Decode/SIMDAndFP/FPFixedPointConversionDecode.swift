// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// FP fixed-point conversion per ARM ARM § C4.1.96.33.
// Encoding: `sf 0 0 11110 ftype 0 rmode opcode scale Rn Rd`.
// rmode ∈ {00, 11} only (other reserved); opcode ∈ {010, 011,
// 000, 001} per (signed/unsigned × to-fp/from-fp); scale at bits[15:10]
// encodes the fractional bits (`fbits = 64 - scale` for sf=1; `fbits =
// 64 - scale` clamped to `<= 32` for sf=0 — formatted directly as the
// 6-bit immediate operand).
//
// Mnemonics: SCVTF (fixed → FP), UCVTF (fixed → FP), FCVTZS (FP → fixed),
// FCVTZU (FP → fixed).

enum FPFixedPointConversionDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        // Routing has already verified bit[30] = 0, bit[29] (S) = 0,
        // bits[28:24] = 11110 and bit[21] = 0. Fields: ftype = bits[23:22],
        // rmode = bits[20:19], opcode = bits[18:16], scale = bits[15:10].
        let ftype = UInt8((encoding >> 22) & 0x3)
        let rmode = UInt8((encoding >> 19) & 0x3)
        let opcode = UInt8((encoding >> 16) & 0x7)
        let scale = UInt8((encoding >> 10) & 0x3F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        guard let size = scalarSizeFromFtype(ftype) else {
            return .undefined(at: address, encoding: encoding)
        }

        // sf=0 (32-bit GPR): scale ∈ [32..63] (fbits ∈ [1..32]). sf=1
        // (64-bit GPR): scale ∈ [1..63]. ARM ARM fixed-point pseudocode:
        // `if sf == 0 && scale < '100000' then UNDEFINED` — i.e. reject
        // scale < 32 at sf=0 (fbits=32, scale=32, is valid).
        if sf == 0, scale < 32 {
            return .undefined(at: address, encoding: encoding)
        }

        let fbits = UInt64(64 - Int(scale))
        let intWidth: RegisterWidth = sf == 1 ? .x64 : .w32
        let intReg = simdfpGprOperand(encoding: 0, width: intWidth, spOrGeneral: false)
        _ = intReg // suppress unused-warning until real factory below

        // (rmode, opcode) → mnemonic + direction:
        //   00:010 SCVTF (int→FP) — GPR → V
        //   00:011 UCVTF (int→FP) — GPR → V
        //   11:000 FCVTZS (FP→int) — V → GPR
        //   11:001 FCVTZU (FP→int) — V → GPR
        let mnemonic: Mnemonic
        let direction: ConversionDirection
        switch (rmode, opcode) {
        case (0b00, 0b010): mnemonic = .scvtf; direction = .gprToFP
        case (0b00, 0b011): mnemonic = .ucvtf; direction = .gprToFP
        case (0b11, 0b000): mnemonic = .fcvtzs; direction = .fpToGPR
        case (0b11, 0b001): mnemonic = .fcvtzu; direction = .fpToGPR
        default:
            return .undefined(at: address, encoding: encoding)
        }

        let scaleOp = Operand.unsignedImmediate(value: fbits, width: 6)
        switch direction {
        case .gprToFP:
            let gpr = simdfpGprOperand(encoding: Rn, width: intWidth, spOrGeneral: false)
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: simdfpInsertingNonZeroGPR(reg: gpr, into: .empty),
                semanticWrites: simdfpInsertingVector(Rd, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operands: [simdfpScalarOperand(Rd, size: size), .register(gpr), scaleOp],
            )
        case .fpToGPR:
            let gpr = simdfpGprOperand(encoding: Rd, width: intWidth, spOrGeneral: false)
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: simdfpInsertingVector(Rn, into: .empty),
                semanticWrites: simdfpInsertingNonZeroGPR(reg: gpr, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operands: [.register(gpr), simdfpScalarOperand(Rn, size: size), scaleOp],
            )
        }
    }

    private enum ConversionDirection {
        case gprToFP
        case fpToGPR
    }
}
