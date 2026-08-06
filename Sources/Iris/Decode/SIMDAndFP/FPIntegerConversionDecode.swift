// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum FPIntegerConversionDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let ftype = UInt8((encoding >> 22) & 0x3)
        let rmode = UInt8((encoding >> 19) & 0x3)
        let opcode = UInt8((encoding >> 16) & 0x7)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        if ftype == 0b10 {
            return decodeFMOVTopHalf(
                encoding: encoding, address: address,
                sf: sf, rmode: rmode, opcode: opcode, Rn: Rn, Rd: Rd, &sink,
            )
        }

        let size = scalarSizeFromFtypeNonReserved(ftype)
        let intWidth: RegisterWidth = sf == 1 ? .x64 : .w32

        if let converted = decodeFPRCVT(
            encoding: encoding, address: address,
            sf: sf, size: size, rmode: rmode, opcode: opcode, Rn: Rn, Rd: Rd, &sink,
        ) {
            return converted
        }

        if let mnemonic = fcvtMnemonic(rmode: rmode, opcode: opcode) {
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
                operandCount: sink.emit(.register(dstGPR), simdfpScalarOperand(Rn, size: size)),
            )
        }

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
                operandCount: sink.emit(simdfpScalarOperand(Rd, size: size), .register(srcGPR)),
            )
        }

        if rmode == 0b00, opcode == 0b110 || opcode == 0b111 {
            let fpToGPR = (opcode == 0b110)
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
                    operandCount: sink.emit(.register(gpr), simdfpScalarOperand(Rn, size: size)),
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
                operandCount: sink.emit(simdfpScalarOperand(Rd, size: size), .register(gpr)),
            )
        }

        return .undefined(at: address, encoding: encoding)
    }

    /// FCVT family: maps (rmode, opcode) → mnemonic when the pair names an
    /// FCVT mnemonic; returns nil otherwise.
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

    /// FEAT_FPRCVT: both operands are SIMD&FP scalars, one size named by
    /// `ftype` and the other by `sf`, and the encoding is allocated only where
    /// the two differ.
    @inline(__always)
    @_optimize(speed)
    private static func decodeFPRCVT(
        encoding: UInt32, address: UInt64,
        sf: UInt8, size: ScalarSize, rmode: UInt8, opcode: UInt8, Rn: UInt8, Rd: UInt8,
        _ sink: inout OperandSink,
    ) -> DecodedDraft? {
        guard let (mnemonic, sourceIsFtype) = fprcvtMnemonic(rmode: rmode, opcode: opcode) else {
            return nil
        }
        let sfSize: ScalarSize = sf == 1 ? .d : .s
        let destination = sourceIsFtype ? sfSize : size
        let source = sourceIsFtype ? size : sfSize
        if destination == source {
            return .undefined(at: address, encoding: encoding)
        }
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: simdfpInsertingVector(Rn, into: .empty),
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.emit(simdfpScalarOperand(Rd, size: destination), simdfpScalarOperand(Rn, size: source)),
        )
    }

    /// FPRCVT (rmode, opcode) → mnemonic and whether `ftype` names the source
    /// rather than the destination.
    @inline(__always)
    @_effects(readonly)
    private static func fprcvtMnemonic(rmode: UInt8, opcode: UInt8) -> (Mnemonic, Bool)? {
        switch (rmode, opcode) {
        case (0b01, 0b010): (.fcvtns, true)
        case (0b01, 0b011): (.fcvtnu, true)
        case (0b10, 0b010): (.fcvtps, true)
        case (0b10, 0b011): (.fcvtpu, true)
        case (0b10, 0b100): (.fcvtms, true)
        case (0b10, 0b101): (.fcvtmu, true)
        case (0b10, 0b110): (.fcvtzs, true)
        case (0b10, 0b111): (.fcvtzu, true)
        case (0b11, 0b010): (.fcvtas, true)
        case (0b11, 0b011): (.fcvtau, true)
        case (0b11, 0b100): (.scvtf, false)
        case (0b11, 0b101): (.ucvtf, false)
        default: nil
        }
    }

    /// FMOV V.D[1] ↔ X.
    @inline(__always)
    @_optimize(speed)
    private static func decodeFMOVTopHalf(
        encoding: UInt32, address: UInt64,
        sf: UInt8, rmode: UInt8, opcode: UInt8, Rn: UInt8, Rd: UInt8, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        if sf != 1 || rmode != 0b01 {
            return .undefined(at: address, encoding: encoding)
        }
        switch opcode {
        case 0b110:
            let gpr = simdfpGprOperand(encoding: Rd, width: .x64, spOrGeneral: false)
            let velt = simdfpElementOperand(Rn, elementSize: .d, index: 1)
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: .fmov,
                semanticReads: simdfpInsertingVector(Rn, into: .empty),
                semanticWrites: simdfpInsertingNonZeroGPR(reg: gpr, into: .empty),
                branchClass: .none, memoryAccess: .none, memoryOrdering: [],
                flagEffect: .none, category: .simdAndFP,
                operandCount: sink.emit(.register(gpr), velt),
            )
        case 0b111:
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
                operandCount: sink.emit(velt, .register(gpr)),
            )
        default:
            return .undefined(at: address, encoding: encoding)
        }
    }
}
