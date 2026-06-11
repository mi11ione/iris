// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Data-processing 2-source + 1-source + CRC32 decode.
// Encoding tier op0=0xD bit 24=0 bits 23:21=110. Bit 30 splits
// 2-source/CRC32 (0) vs 1-source (1). FEAT_CSSC SMAX/SMIN/UMAX/UMIN
// (2-source) and ABS/CTZ/CNT (1-source) live here too.
//
// Variable-shift mnemonics (LSLV/LSRV/ASRV/RORV) are NEVER emitted as
// canonical — llvm-mc unconditionally renders them as the DPI-owned
// .lsl/.lsr/.asr/.ror. The base mnemonics are reserved in the enum for
// downstream tooling.
//
// PAC standalone (PACIA…XPACD/PACGA) at opc6 ∈ 001100..001111 in the
// 1-source tier is decoded by the PAC decoder via the family decoder's
// top-of-method delegation; this path emits .undefined for those opc6
// values (the delegation intercepts them before reaching here).

enum DataProc2or1SourceDecode {
    @inline(__always)
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let S = UInt8((encoding >> 29) & 0x1)
        if S != 0 { return .undefined(at: address, encoding: encoding) }
        if (encoding >> 30) & 0x1 == 0 {
            return decode2SourceOrCRC32(encoding: encoding, address: address)
        }
        return decode1Source(encoding: encoding, address: address)
    }

    @inline(__always)
    @_optimize(speed)
    private static func decode2SourceOrCRC32(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let opc6 = UInt8((encoding >> 10) & 0x3F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        let width: RegisterWidth = sf == 1 ? .x64 : .w32
        let rdRef = gprOperand(encoding: Rd, width: width, form: .zrOrGeneral)
        let rnRef = gprOperand(encoding: Rn, width: width, form: .zrOrGeneral)
        let rmRef = gprOperand(encoding: Rm, width: width, form: .zrOrGeneral)

        switch opc6 {
        case 0b000010:
            return threeRegDraft(.udiv, rdRef: rdRef, rnRef: rnRef, rmRef: rmRef, encoding: encoding, address: address)
        case 0b000011:
            return threeRegDraft(.sdiv, rdRef: rdRef, rnRef: rnRef, rmRef: rmRef, encoding: encoding, address: address)
        case 0b001000:
            return threeRegDraft(.lsl, rdRef: rdRef, rnRef: rnRef, rmRef: rmRef, encoding: encoding, address: address)
        case 0b001001:
            return threeRegDraft(.lsr, rdRef: rdRef, rnRef: rnRef, rmRef: rmRef, encoding: encoding, address: address)
        case 0b001010:
            return threeRegDraft(.asr, rdRef: rdRef, rnRef: rnRef, rmRef: rmRef, encoding: encoding, address: address)
        case 0b001011:
            return threeRegDraft(.ror, rdRef: rdRef, rnRef: rnRef, rmRef: rmRef, encoding: encoding, address: address)
        case 0b010000:
            return crcDraft(.crc32b, sf: sf, requireSF: 0, Rd: Rd, Rn: Rn, Rm: Rm, encoding: encoding, address: address)
        case 0b010001:
            return crcDraft(.crc32h, sf: sf, requireSF: 0, Rd: Rd, Rn: Rn, Rm: Rm, encoding: encoding, address: address)
        case 0b010010:
            return crcDraft(.crc32w, sf: sf, requireSF: 0, Rd: Rd, Rn: Rn, Rm: Rm, encoding: encoding, address: address)
        case 0b010011:
            return crcDraft(.crc32x, sf: sf, requireSF: 1, Rd: Rd, Rn: Rn, Rm: Rm, encoding: encoding, address: address)
        case 0b010100:
            return crcDraft(.crc32cb, sf: sf, requireSF: 0, Rd: Rd, Rn: Rn, Rm: Rm, encoding: encoding, address: address)
        case 0b010101:
            return crcDraft(.crc32ch, sf: sf, requireSF: 0, Rd: Rd, Rn: Rn, Rm: Rm, encoding: encoding, address: address)
        case 0b010110:
            return crcDraft(.crc32cw, sf: sf, requireSF: 0, Rd: Rd, Rn: Rn, Rm: Rm, encoding: encoding, address: address)
        case 0b010111:
            return crcDraft(.crc32cx, sf: sf, requireSF: 1, Rd: Rd, Rn: Rn, Rm: Rm, encoding: encoding, address: address)
        // FEAT_CSSC signed/unsigned min/max (register form). SMAX/SMIN/UMAX/
        // UMIN share the three-register shape; .smax/.smin/.umax/.umin are
        // SIMD/FP-owned mnemonics, reused here (the GPR vs vector form is
        // disambiguated by category + operand kinds, as with .lsl etc.).
        case 0b011000:
            return threeRegDraft(.smax, rdRef: rdRef, rnRef: rnRef, rmRef: rmRef, encoding: encoding, address: address)
        case 0b011001:
            return threeRegDraft(.umax, rdRef: rdRef, rnRef: rnRef, rmRef: rmRef, encoding: encoding, address: address)
        case 0b011010:
            return threeRegDraft(.smin, rdRef: rdRef, rnRef: rnRef, rmRef: rmRef, encoding: encoding, address: address)
        case 0b011011:
            return threeRegDraft(.umin, rdRef: rdRef, rnRef: rnRef, rmRef: rmRef, encoding: encoding, address: address)
        default:
            return .undefined(at: address, encoding: encoding)
        }
    }

    /// Three-register DPR draft — semantic shape shared by UDIV/SDIV and
    /// the canonical variable-shift mnemonics (LSL/LSR/ASR/ROR register-form).
    @inline(__always)
    private static func threeRegDraft(
        _ mnemonic: Mnemonic, rdRef: RegisterRef, rnRef: RegisterRef, rmRef: RegisterRef,
        encoding: UInt32, address: UInt64,
    ) -> DecodedDraft {
        DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: .empty)),
            semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
            flagEffect: .none,
            category: .dataProcessingRegister,
            operands: [.register(rdRef), .register(rnRef), .register(rmRef)],
        )
    }

    /// CRC32 draft with the sf/opc6-driven Rm-width rule.
    @inline(__always)
    private static func crcDraft(
        _ mnemonic: Mnemonic, sf: UInt8, requireSF: UInt8, Rd: UInt8, Rn: UInt8, Rm: UInt8,
        encoding: UInt32, address: UInt64,
    ) -> DecodedDraft {
        if sf != requireSF { return .undefined(at: address, encoding: encoding) }
        // Rd, Rn are always Wn (32-bit accumulator + source).
        let rdRef = gprOperand(encoding: Rd, width: .w32, form: .zrOrGeneral)
        let rnRef = gprOperand(encoding: Rn, width: .w32, form: .zrOrGeneral)
        // Rm width depends on the CRC32 variant: 64-bit (CRC32X/CX) → Xn,
        // 32-bit variants → Wn.
        let rmWidth: RegisterWidth = requireSF == 1 ? .x64 : .w32
        let rmRef = gprOperand(encoding: Rm, width: rmWidth, form: .zrOrGeneral)
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: .empty)),
            semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
            flagEffect: .none,
            category: .dataProcessingRegister,
            operands: [.register(rdRef), .register(rnRef), .register(rmRef)],
        )
    }

    @inline(__always)
    @_optimize(speed)
    private static func decode1Source(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let opcode2 = UInt8((encoding >> 16) & 0x1F)
        if opcode2 != 0 { return .undefined(at: address, encoding: encoding) }

        let opc6 = UInt8((encoding >> 10) & 0x3F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        let width: RegisterWidth = sf == 1 ? .x64 : .w32
        let rdRef = gprOperand(encoding: Rd, width: width, form: .zrOrGeneral)
        let rnRef = gprOperand(encoding: Rn, width: width, form: .zrOrGeneral)

        let mnemonic: Mnemonic = switch opc6 {
        case 0b000000: .rbit
        case 0b000001: .rev16
        case 0b000010:
            // sf=0 → REV (full 32-bit byte-swap); sf=1 → REV32 (byte-swap
            // within each 32-bit lane of 64-bit).
            sf == 0 ? .rev : .rev32
        case 0b000011:
            // sf=0 reserved (no REV-double-word at 32-bit); sf=1 → REV
            // (full 64-bit byte-swap).
            sf == 0 ? .undefined : .rev
        case 0b000100: .clz
        case 0b000101: .cls
        // FEAT_CSSC 1-source: CTZ / CNT / ABS (valid at sf=0 and sf=1).
        // ABS/CNT are SIMD/FP-owned mnemonics reused here; CTZ is DPR's.
        case 0b000110: .ctz
        case 0b000111: .cnt
        case 0b001000: .abs
        // opc6 001100..001111: PAC standalone — out of scope here; the
        // top-of-family delegation routes those to the PAC decoder.
        default: .undefined
        }
        if mnemonic == .undefined {
            return .undefined(at: address, encoding: encoding)
        }
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: insertingNonZero(reg: rnRef, into: .empty),
            semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
            flagEffect: .none,
            category: .dataProcessingRegister,
            operands: [.register(rdRef), .register(rnRef)],
        )
    }
}
