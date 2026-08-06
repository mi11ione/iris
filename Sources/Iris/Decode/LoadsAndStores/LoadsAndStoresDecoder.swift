// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// The Loads & Stores family decoder.
struct LoadsAndStoresDecoder: FamilyDecoder {
    static let lsOp0Values: Set<UInt8> = [0x4, 0x6, 0xC, 0xE]

    init() {}

    var tag: FamilyTag {
        .loadsAndStores
    }

    var op0Values: Set<UInt8> {
        Self.lsOp0Values
    }

    @_optimize(speed)
    func decode(
        encoding: UInt32, address: UInt64, features: Features, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        if (encoding & 0x3B20_0C00) == 0x1900_0400 {
            return MOPSDecode.decode(encoding: encoding, address: address, &sink)
        }
        if (encoding & 0xFFFF_0C00) == 0x1DDF_0000 {
            return MOPSDecode.decodeSetGO(encoding: encoding, address: address, &sink)
        }

        let V = (encoding >> 26) & 1
        if V == 1 {
            return SIMDAndFPDecoder.decodeVectorLoadStore(
                encoding: encoding, address: address, &sink,
            )
        }

        let bits29_24 = UInt8((encoding >> 24) & 0x3F)
        switch bits29_24 {
        case 0b011000:
            return LoadLiteralDecode.decode(encoding: encoding, address: address, &sink)

        case 0b001000:
            let bit21 = (encoding >> 21) & 1
            if bit21 == 0 {
                return LoadStoreExclusiveAndOrderedDecode.decode(
                    encoding: encoding, address: address, &sink,
                )
            }
            let bit23 = (encoding >> 23) & 1
            let bit31 = (encoding >> 31) & 1
            if bit23 == 1 {
                return CompareAndSwapDecode.decode(encoding: encoding, address: address, &sink)
            }
            if bit31 == 0 {
                return CompareAndSwapDecode.decodeCASP(encoding: encoding, address: address, &sink)
            }
            return LoadStoreExclusivePairDecode.decode(encoding: encoding, address: address, &sink)

        case 0b001001:
            return LSUILoadStoreDecode.decode(encoding: encoding, address: address, &sink)

        case 0b101000, 0b101001:
            return LoadStorePairDecode.decode(encoding: encoding, address: address, &sink)

        case 0b111000:
            let bit21 = (encoding >> 21) & 1
            let bits11_10 = UInt8((encoding >> 10) & 0x3)
            if bit21 == 0 {
                switch bits11_10 {
                case 0b00:
                    return LoadStoreUnscaledDecode.decode(encoding: encoding, address: address, &sink)
                case 0b01:
                    return LoadStoreIndexedDecode.decode(
                        encoding: encoding, address: address, writebackKind: .postIndex, &sink,
                    )
                case 0b10:
                    return LoadStoreUnprivilegedDecode.decode(encoding: encoding, address: address, &sink)
                default:
                    return LoadStoreIndexedDecode.decode(
                        encoding: encoding, address: address, writebackKind: .preIndex, &sink,
                    )
                }
            }
            switch bits11_10 {
            case 0b00:
                let opHi = (encoding >> 12) & 0xF
                if opHi == 0b1001 || opHi == 0b1010 || opHi == 0b1011 || opHi == 0b1101 {
                    let size = (encoding >> 30) & 0x3
                    if size == 0b11, (encoding >> 22) & 0x3 == 0b00 {
                        return LS64Decode.decode(encoding: encoding, address: address, &sink)
                    }
                    if size <= 0b01, opHi != 0b1101 {
                        return AtomicExtensionsDecode.decodeRCWNonPair(
                            encoding: encoding, address: address, &sink,
                        )
                    }
                }
                let bit23 = (encoding >> 23) & 1
                let bit22 = (encoding >> 22) & 1
                let bits20_16 = (encoding >> 16) & 0x1F
                let bits15_12 = (encoding >> 12) & 0xF
                if bit23 == 1, bit22 == 0, bits20_16 == 0x1F, bits15_12 == 0b1100 {
                    return LDAPRDecode.decode(encoding: encoding, address: address, &sink)
                }
                return LSEAtomicDecode.decode(encoding: encoding, address: address, &sink)
            case 0b10:
                if (encoding >> 30) == 0b11,
                   (encoding >> 22) & 0x3 == 0b10,
                   (encoding >> 3) & 0x3 == 0b11
                {
                    return RangePrefetchDecode.decode(encoding: encoding, address: address, &sink)
                }
                return LoadStoreRegisterOffsetDecode.decode(encoding: encoding, address: address, &sink)
            default:
                if !features.contains(.pointerAuthentication) {
                    return .undefined(at: address, encoding: encoding)
                }
                return LDRADecode.decode(encoding: encoding, address: address, &sink)
            }

        case 0b111001:
            return LoadStoreUnsignedOffsetDecode.decode(encoding: encoding, address: address, &sink)

        default:
            let bit21 = (encoding >> 21) & 1
            let bits11_10b = (encoding >> 10) & 0x3
            if bit21 == 1 {
                switch bits11_10b {
                case 0b00:
                    let size = (encoding >> 30) & 0x3
                    if size <= 0b01 {
                        if let rcwPair = AtomicExtensionsDecode.decodeRCWPair(
                            encoding: encoding, address: address, &sink,
                        ) {
                            return rcwPair
                        }
                        if size == 0b00 {
                            return LSE128Decode.decode(encoding: encoding, address: address, &sink)
                        }
                        return .undefined(at: address, encoding: encoding)
                    }
                case 0b01:
                    if (encoding >> 30) & 0x3 <= 0b01 {
                        return AtomicExtensionsDecode.decodeLSUI(
                            encoding: encoding, address: address, &sink,
                        )
                    }
                case 0b10:
                    if (encoding >> 30) & 0x3 <= 0b01 {
                        return AtomicExtensionsDecode.decodeRCWCas(
                            encoding: encoding, address: address, &sink,
                        )
                    }
                default:
                    if (encoding >> 30) & 0x3 <= 0b01 {
                        return AtomicExtensionsDecode.decodeRCWCasp(
                            encoding: encoding, address: address, &sink,
                        )
                    }
                }
                if let mteLS = MemoryTaggingDecode.decodeLS(
                    encoding: encoding, address: address, &sink,
                ) {
                    return mteLS
                }
                return .undefined(at: address, encoding: encoding)
            }
            switch bits11_10b {
            case 0b10:
                if (encoding >> 22) & 0x3 <= 0b01 {
                    return AtomicExtensionsDecode.decodeRCPC3Pair(
                        encoding: encoding, address: address, &sink,
                    )
                }
                return AtomicExtensionsDecode.decodeRCPC3Single(
                    encoding: encoding, address: address, &sink,
                )
            case 0b11:
                return AtomicExtensionsDecode.decodeGCS(encoding: encoding, address: address, &sink)
            default:
                return LRCPC2Decode.decode(encoding: encoding, address: address, &sink)
            }
        }
    }
}
