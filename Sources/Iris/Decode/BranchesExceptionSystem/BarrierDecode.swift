// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Barrier instructions (CRmSystemI).
// Encoding: 1101 0101 0000 0011 0011 CRm op2 11111
// op2 routes to family:
//   010 → CLREX
//   100 → DSB (option / SSBB / PSSBB special-cased on CRm)
//   101 → DMB
//   110 → ISB
//   111 → SB (CRm must be 0)
//   001 → DSB nXS (CRm ∈ {2, 6, 10, 14})
// Other op2 → .undefined.

enum BarrierDecode {
    @inline(__always)
    static func decode(encoding: UInt32, address: UInt64, CRm: UInt8, op2: UInt8) -> DecodedDraft {
        switch op2 {
        case 0b010:
            decodeCLREX(encoding: encoding, address: address, CRm: CRm)
        case 0b100:
            decodeDSB(encoding: encoding, address: address, CRm: CRm)
        case 0b101:
            decodeDMB(encoding: encoding, address: address, CRm: CRm)
        case 0b110:
            decodeISB(encoding: encoding, address: address, CRm: CRm)
        case 0b111:
            decodeSB(encoding: encoding, address: address, CRm: CRm)
        case 0b001:
            decodeDSBnXS(encoding: encoding, address: address, CRm: CRm)
        default:
            .undefined(at: address, encoding: encoding)
        }
    }

    @inline(__always)
    private static func decodeCLREX(encoding: UInt32, address: UInt64, CRm: UInt8) -> DecodedDraft {
        // CLREX renders bare when CRm == 0xF; `clrex #N` otherwise.
        var operands: [Operand] = []
        if CRm != 0xF {
            operands.append(.unsignedImmediate(value: UInt64(CRm), width: 4))
        }
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .clrex,
            category: .branchesExceptionSystem,
            operands: operands,
        )
    }

    @inline(__always)
    private static func decodeDSB(encoding: UInt32, address: UInt64, CRm: UInt8) -> DecodedDraft {
        // SSBB / PSSBB special-cases.
        if CRm == 0 {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .ssbb,
                category: .branchesExceptionSystem,
            )
        }
        if CRm == 4 {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .pssbb,
                category: .branchesExceptionSystem,
            )
        }
        return decodeDSBOrDMB(encoding: encoding, address: address, CRm: CRm, mnemonic: .dsb)
    }

    @inline(__always)
    private static func decodeDMB(encoding: UInt32, address: UInt64, CRm: UInt8) -> DecodedDraft {
        decodeDSBOrDMB(encoding: encoding, address: address, CRm: CRm, mnemonic: .dmb)
    }

    @inline(__always)
    private static func decodeDSBOrDMB(
        encoding: UInt32, address: UInt64, CRm: UInt8, mnemonic: Mnemonic,
    ) -> DecodedDraft {
        // Named option if recognised; otherwise raw `#N`.
        if let option = BarrierOption(rawOptionBits: CRm) {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                category: .branchesExceptionSystem,
                operands: [.barrierOption(option)],
            )
        }
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            category: .branchesExceptionSystem,
            operands: [.unsignedImmediate(value: UInt64(CRm), width: 4)],
        )
    }

    @inline(__always)
    private static func decodeISB(encoding: UInt32, address: UInt64, CRm: UInt8) -> DecodedDraft {
        var operands: [Operand] = []
        if CRm != 0xF {
            operands.append(.unsignedImmediate(value: UInt64(CRm), width: 4))
        }
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .isb,
            category: .branchesExceptionSystem,
            operands: operands,
        )
    }

    @inline(__always)
    private static func decodeSB(encoding: UInt32, address: UInt64, CRm _: UInt8) -> DecodedDraft {
        // SB ignores CRm (the field is reserved for SB), rendering bare.
        DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .sb,
            category: .branchesExceptionSystem,
        )
    }

    @inline(__always)
    private static func decodeDSBnXS(encoding: UInt32, address: UInt64, CRm: UInt8) -> DecodedDraft {
        // FEAT_XS recognises CRm ∈ {2, 6, 10, 14} only — other values are
        // reserved within the op2=001 slot. The decoder still produces a
        // `.dsb` record carrying the raw CRm as an immediate operand so
        // the canonicalizer can render the named "oshnxs"/"nshnxs"/
        // "ishnxs"/"synxs" form for the four valid CRm values; unknown
        // values render as the underlying `msr S0_...` form per llvm-mc
        // fallback.
        // To keep the structural-field surface simple, emit
        // .dsb with `.unsignedImmediate(value: CRm | 0x10, width: 5)` for
        // the four valid CRm values (encoding the nXS hint), and
        // .undefined for the rest (matching llvm-mc's MSR-fallback would
        // require a sysreg synthesis path that isn't worth the complexity
        // for an instruction Apple silicon barely emits).
        switch CRm {
        case 2, 6, 10, 14:
            DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .dsb,
                category: .branchesExceptionSystem,
                operands: [.unsignedImmediate(value: UInt64(CRm) | 0x10, width: 5)],
            )
        default:
            .undefined(at: address, encoding: encoding)
        }
    }
}
