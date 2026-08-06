// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// The SIMD & Floating-Point family decoder.
struct SIMDAndFPDecoder: FamilyDecoder {
    static let simdfpOp0Values: Set<UInt8> = [0x7, 0xF]

    init() {}

    var tag: FamilyTag {
        .simdAndFP
    }

    var op0Values: Set<UInt8> {
        Self.simdfpOp0Values
    }

    @_optimize(speed)
    func decode(
        encoding: UInt32, address: UInt64, features _: Features, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        if let cryptoDraft = CryptoExtensionDecode.decode(
            encoding: encoding, address: address, &sink,
        ) {
            return cryptoDraft
        }
        let bits31_24 = UInt8((encoding >> 24) & 0xFF)

        if (encoding >> 30) & 1 == 0, (encoding >> 25) & 0xF == 0b1111 {
            if (encoding >> 29) & 1 == 1 {
                return .undefined(at: address, encoding: encoding)
            }
            if (encoding >> 24) & 1 == 0 {
                return dispatchFPScalar0x1E(encoding: encoding, address: address, &sink)
            }
            return FPDataProcessing3SourceDecode.decode(encoding: encoding, address: address, &sink)
        }
        if bits31_24 & 0b1000_0000 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        switch bits31_24 & 0b1001_1111 {
        case 0b0000_1110:
            return dispatchAdvSIMDVector0xX_E(encoding: encoding, address: address, &sink)
        case 0b0000_1111:
            return dispatchAdvSIMDVector0xX_F(encoding: encoding, address: address, &sink)
        case 0b0001_1110:
            return dispatchAdvSIMDScalar0xX_E(encoding: encoding, address: address, &sink)
        default:
            return dispatchAdvSIMDScalar0xX_F(encoding: encoding, address: address, &sink)
        }
    }

    /// AdvSIMD vector dispatch within bits[31:24] high nibble = 0xX_E
    /// (bit[24]=0).
    @inline(__always)
    @_optimize(speed)
    private func dispatchAdvSIMDVector0xX_E(
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let bit21 = (encoding >> 21) & 1
        if bit21 == 1 {
            return dispatchVectorThreeArg(encoding: encoding, address: address, &sink)
        }
        return dispatchVectorNonThreeArg(encoding: encoding, address: address, &sink)
    }

    /// Three-arg vector classes (three-same / three-different / two-reg-misc /
    /// across-lanes).
    @inline(__always)
    @_optimize(speed)
    private func dispatchVectorThreeArg(
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let bit10 = (encoding >> 10) & 1
        let bit11 = (encoding >> 11) & 1
        if bit10 == 1 {
            return AdvSIMDThreeSameDecode.decode(encoding: encoding, address: address, &sink)
        }
        if bit11 == 0 {
            return AdvSIMDThreeDifferentDecode.decode(encoding: encoding, address: address, &sink)
        }
        let bits20_17 = UInt8((encoding >> 17) & 0xF)
        if bits20_17 == 0b0000 {
            return AdvSIMDTwoRegMiscDecode.decode(encoding: encoding, address: address, &sink)
        }
        if bits20_17 == 0b1000 {
            return AdvSIMDAcrossLanesDecode.decode(encoding: encoding, address: address, &sink)
        }
        if bits20_17 == 0b1100 {
            return AdvSIMDTwoRegMiscDecode.decodeFP16TwoRegMisc(encoding: encoding, address: address, &sink)
        }
        return .undefined(at: address, encoding: encoding)
    }

    /// Non-three-arg vector classes (copy / permute / extract / TBL /
    /// three-reg-extension).
    @inline(__always)
    @_optimize(speed)
    private func dispatchVectorNonThreeArg(
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let bit15 = (encoding >> 15) & 1
        let bit10 = (encoding >> 10) & 1
        let bit11 = (encoding >> 11) & 1
        if bit15 == 1, bit10 == 1 {
            return AdvSIMDThreeRegExtensionDecode.decode(
                encoding: encoding, address: address, &sink,
            )
        }
        if bit15 == 0, bit10 == 1 {
            let bit22 = (encoding >> 22) & 1
            if bit22 == 1 {
                return AdvSIMDThreeSameFP16Decode.decode(encoding: encoding, address: address, &sink)
            }
            if (encoding >> 23) & 1 == 0 {
                return AdvSIMDCopyDecode.decode(encoding: encoding, address: address, &sink)
            }
            return .undefined(at: address, encoding: encoding)
        }
        if bit15 == 0, bit10 == 0 {
            let bit29 = (encoding >> 29) & 1
            if bit29 == 1 {
                return AdvSIMDExtractDecode.decode(encoding: encoding, address: address, &sink)
            }
            if bit11 == 0 {
                if (encoding >> 22) & 0x3 == 0 {
                    return AdvSIMDTableLookupDecode.decode(encoding: encoding, address: address, &sink)
                }
                return AdvSIMDLUTDecode.decode(encoding: encoding, address: address, &sink)
            }
            return AdvSIMDPermuteDecode.decode(encoding: encoding, address: address, &sink)
        }
        return .undefined(at: address, encoding: encoding)
    }

    /// AdvSIMD vector dispatch within bits[31:24] high nibble = 0xX_F
    /// (bit[24]=1).
    @inline(__always)
    @_optimize(speed)
    private func dispatchAdvSIMDVector0xX_F(
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let bit10 = (encoding >> 10) & 1
        if bit10 == 0 {
            return AdvSIMDVectorXIndexedElementDecode.decode(
                encoding: encoding, address: address, &sink,
            )
        }
        let bits23_19 = (encoding >> 19) & 0x1F
        if bits23_19 == 0 {
            return AdvSIMDModifiedImmediateDecode.decode(encoding: encoding, address: address, &sink)
        }
        return AdvSIMDShiftByImmediateDecode.decode(
            encoding: encoding, address: address, &sink,
        )
    }

    /// AdvSIMD scalar tier dispatch.
    @inline(__always)
    @_optimize(speed)
    private func dispatchAdvSIMDScalar0xX_E(
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let bit21 = (encoding >> 21) & 1
        if bit21 == 0 {
            let bit15 = (encoding >> 15) & 1
            let bit14 = (encoding >> 14) & 1
            let bit10 = (encoding >> 10) & 1
            let bit22 = (encoding >> 22) & 1
            if bit10 == 1, bit22 == 1, bit15 == 0, bit14 == 0 {
                return AdvSIMDScalarThreeSameFP16Decode.decode(encoding: encoding, address: address, &sink)
            }
            if bit10 == 1, bit15 == 1 {
                return AdvSIMDScalarThreeSameFP16Decode.decodeRDM(encoding: encoding, address: address, &sink)
            }
            if (encoding >> 29) & 1 == 0, (encoding >> 21) & 0x7 == 0, bit15 == 0, bit10 == 1 {
                return AdvSIMDScalarCopyDecode.decode(encoding: encoding, address: address, &sink)
            }
            return .undefined(at: address, encoding: encoding)
        }
        let bit10 = (encoding >> 10) & 1
        let bit11 = (encoding >> 11) & 1
        if bit10 == 1 {
            return AdvSIMDScalarThreeSameDecode.decode(
                encoding: encoding, address: address, &sink,
            )
        }
        if bit11 == 0 {
            return AdvSIMDScalarThreeDifferentDecode.decode(
                encoding: encoding, address: address, &sink,
            )
        }
        let bits20_17 = (encoding >> 17) & 0xF
        if bits20_17 == 0b0000 {
            return AdvSIMDScalarTwoRegMiscDecode.decode(
                encoding: encoding, address: address, &sink,
            )
        }
        if bits20_17 == 0b1000 {
            return AdvSIMDScalarPairwiseDecode.decode(
                encoding: encoding, address: address, &sink,
            )
        }
        if bits20_17 == 0b1100 {
            return AdvSIMDScalarTwoRegMiscDecode.decodeFP16(encoding: encoding, address: address, &sink)
        }
        return .undefined(at: address, encoding: encoding)
    }

    /// AdvSIMD scalar dispatch at bits[31:24] = 0x5F / 0x7F.
    @inline(__always)
    @_optimize(speed)
    private func dispatchAdvSIMDScalar0xX_F(
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let bit10 = (encoding >> 10) & 1
        if bit10 == 1 {
            return AdvSIMDScalarShiftByImmediateDecode.decode(
                encoding: encoding, address: address, &sink,
            )
        }
        return AdvSIMDScalarXIndexedElementDecode.decode(
            encoding: encoding, address: address, &sink,
        )
    }

    /// Dispatch within the bits[31:24] == 0b00011110 sub-tree (FP scalar
    /// 1/2-source / compare / cond-/imm / fixed-point and integer conversion).
    @inline(__always)
    @_optimize(speed)
    private func dispatchFPScalar0x1E(
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let bit21 = (encoding >> 21) & 1
        if bit21 == 0 {
            return FPFixedPointConversionDecode.decode(
                encoding: encoding, address: address, &sink,
            )
        }
        let bits14_10 = UInt8((encoding >> 10) & 0x1F)
        if (encoding >> 10) & 0x3F == 0b000000 {
            return FPIntegerConversionDecode.decode(
                encoding: encoding, address: address, &sink,
            )
        }
        if (encoding >> 31) & 1 == 1 {
            return .undefined(at: address, encoding: encoding)
        }
        if bits14_10 == 0b10000 {
            return FPDataProcessing1SourceDecode.decode(
                encoding: encoding, address: address, &sink,
            )
        }
        let bits11_10 = UInt8(bits14_10 & 0x3)
        switch bits11_10 {
        case 0b00:
            let bit12 = (encoding >> 12) & 1
            if bit12 == 1 {
                return FPImmediateDecode.decode(encoding: encoding, address: address, &sink)
            }
            if (encoding >> 10) & 0x3F == 0b001000 {
                return FPCompareDecode.decode(encoding: encoding, address: address, &sink)
            }
            return .undefined(at: address, encoding: encoding)
        case 0b01:
            return FPConditionalCompareDecode.decode(
                encoding: encoding, address: address, &sink,
            )
        case 0b10:
            return FPDataProcessing2SourceDecode.decode(
                encoding: encoding, address: address, &sink,
            )
        default:
            return FPConditionalSelectDecode.decode(
                encoding: encoding, address: address, &sink,
            )
        }
    }

    /// V=1 SIMD/FP load/store delegation entry, called by the L/S decoder when
    /// it sees bit[26]=1 at op0 ∈ {0x4, 0x6, 0xC, 0xE}.
    @_optimize(speed)
    static func decodeVectorLoadStore(
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let bits29_24 = UInt8((encoding >> 24) & 0x3F)
        switch bits29_24 {
        case 0b001100:
            return AdvSIMDLoadStoreMultipleStructuresDecode.decode(
                encoding: encoding, address: address, &sink,
            )
        case 0b001101:
            return AdvSIMDLoadStoreSingleStructureDecode.decode(
                encoding: encoding, address: address, &sink,
            )
        case 0b011100:
            return ScalarSIMDLoadLiteralDecode.decode(
                encoding: encoding, address: address, &sink,
            )
        case 0b011101:
            return ScalarSIMDLRCPC2Decode.decode(encoding: encoding, address: address, &sink)
        case 0b101100, 0b101101:
            return ScalarSIMDLoadStorePairDecode.decode(
                encoding: encoding, address: address, &sink,
            )
        case 0b111100:
            if (encoding >> 21) & 1 == 1, (encoding >> 10) & 0x3 == 0b00 {
                return LSFEAtomicDecode.decode(encoding: encoding, address: address, &sink)
            }
            return ScalarSIMDLoadStoreIndexedDecode.decode(
                encoding: encoding, address: address, &sink,
            )
        default:
            return ScalarSIMDLoadStoreUnsignedOffsetDecode.decode(
                encoding: encoding, address: address, &sink,
            )
        }
    }
}
