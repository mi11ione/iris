// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Bitfield (BFM, SBFM, UBFM) decode.
// Encoding bits 28:23 = 100110, op0=0x9, op1=0b110. Alias precedence
// (first match wins): SXTB/SXTH/SXTW/UXTB/UXTH > ASR/LSR/LSL >
// SBFIZ/SBFX > UBFIZ/UBFX > BFC > BFI > BFXIL > base BFM/SBFM/UBFM.
//
// Reserved: opc=11; N != sf; 32-bit immr[5]=1 OR
// imms[5]=1. BFM/BFI/BFXIL/BFC are read-modify-write on Rd;
// SBFM/UBFM fully overwrite.

enum BitfieldDecode {
    @inline(__always)
    @_optimize(speed)
    @_effects(readonly)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let opc = UInt8((encoding >> 29) & 0x3)
        let n = UInt8((encoding >> 22) & 0x1)
        let immr = UInt8((encoding >> 16) & 0x3F)
        let imms = UInt8((encoding >> 10) & 0x3F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        // Reserved encodings.
        if opc == 0b11 { return .undefined(at: address, encoding: encoding) }
        if n != sf { return .undefined(at: address, encoding: encoding) }
        if sf == 0, (immr & 0x20) != 0 || (imms & 0x20) != 0 {
            return .undefined(at: address, encoding: encoding)
        }

        let regSize: UInt8 = sf == 1 ? 64 : 32
        let width: RegisterWidth = sf == 1 ? .x64 : .w32
        // Bitfield Rd and Rn are both ZR-form (ARM ARM `<Xd>` / `<Xn>`
        // operand syntax).
        let rdRef = gprOperand(encoding: Rd, width: width, form: .zrOrGeneral)
        let rnRef = gprOperand(encoding: Rn, width: width, form: .zrOrGeneral)

        // BFM family (opc=01) inserts into Rd and preserves the rest —
        // read-modify-write Rd; SBFM/UBFM fully overwrite (write-only).
        let isBFMFamily = opc == 0b01
        let isFullWidthBFM = isBFMFamily && immr == 0 && imms == (regSize &- 1)
        let baseReads = isBFMFamily && !isFullWidthBFM
            ? insertingNonZero(reg: rdRef, into: insertingNonZero(reg: rnRef, into: .empty))
            : insertingNonZero(reg: rnRef, into: .empty)
        let baseWrites = insertingNonZero(reg: rdRef, into: .empty)

        // Alias precedence follows llvm-mc's preferred-alias chain: the
        // most specific alias wins, tested in the order below (extension
        // aliases, then shift forms, then bitfield insert/extract).

        // SBFM extension aliases (opc=00, immr=0, imms ∈ {7,15,31}).
        // SXTB/SXTH apply at both widths (with sf=1 producing the mixed
        // `sxtb Xd, Wn` form); SXTW only when sf=1.
        if opc == 0b00, immr == 0 {
            if imms == 7 {
                // SXTB Rd, Wn (Rd width per sf; Rn rendered as Wn always).
                let rnWn = gprOperand(encoding: Rn, width: .w32, form: .zrOrGeneral)
                return DecodedDraft(
                    address: address,
                    encoding: encoding,
                    mnemonic: .sxtb,
                    semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                    semanticWrites: baseWrites,
                    flagEffect: .none,
                    category: .dataProcessingImmediate,
                    operands: [.register(rdRef), .register(rnWn)],
                )
            }
            if imms == 15 {
                let rnWn = gprOperand(encoding: Rn, width: .w32, form: .zrOrGeneral)
                return DecodedDraft(
                    address: address,
                    encoding: encoding,
                    mnemonic: .sxth,
                    semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                    semanticWrites: baseWrites,
                    flagEffect: .none,
                    category: .dataProcessingImmediate,
                    operands: [.register(rdRef), .register(rnWn)],
                )
            }
            if imms == 31, sf == 1 {
                // SXTW Xd, Wn — only valid with sf=1 (would otherwise be
                // SBFX w0,w1,#0,#32 which is reserved for sf=0 imms=31).
                let rnWn = gprOperand(encoding: Rn, width: .w32, form: .zrOrGeneral)
                return DecodedDraft(
                    address: address,
                    encoding: encoding,
                    mnemonic: .sxtw,
                    semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                    semanticWrites: baseWrites,
                    flagEffect: .none,
                    category: .dataProcessingImmediate,
                    operands: [.register(rdRef), .register(rnWn)],
                )
            }
        }

        // UBFM extension aliases (opc=10, immr=0, imms ∈ {7,15}, sf=0 ONLY).
        // 64-bit UBFM with imms=7/15 immr=0 disassembles as `ubfx x_, x_, #0, #N`
        // (no UXTB/UXTH at 64-bit per LLVM behavior; UXTW does not exist).
        if opc == 0b10, sf == 0, immr == 0 {
            if imms == 7 {
                return DecodedDraft(
                    address: address,
                    encoding: encoding,
                    mnemonic: .uxtb,
                    semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                    semanticWrites: baseWrites,
                    flagEffect: .none,
                    category: .dataProcessingImmediate,
                    operands: [.register(rdRef), .register(rnRef)],
                )
            }
            if imms == 15 {
                return DecodedDraft(
                    address: address,
                    encoding: encoding,
                    mnemonic: .uxth,
                    semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                    semanticWrites: baseWrites,
                    flagEffect: .none,
                    category: .dataProcessingImmediate,
                    operands: [.register(rdRef), .register(rnRef)],
                )
            }
        }

        // ASR alias (opc=00, imms=regsize-1): asr Rd, Rn, #immr.
        if opc == 0b00, imms == regSize &- 1 {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .asr,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: baseWrites,
                flagEffect: .none,
                category: .dataProcessingImmediate,
                operands: [
                    .register(rdRef), .register(rnRef),
                    .unsignedImmediate(value: UInt64(immr), width: 6),
                ],
            )
        }

        // LSR alias (opc=10, imms=regsize-1): lsr Rd, Rn, #immr.
        if opc == 0b10, imms == regSize &- 1 {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .lsr,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: baseWrites,
                flagEffect: .none,
                category: .dataProcessingImmediate,
                operands: [
                    .register(rdRef), .register(rnRef),
                    .unsignedImmediate(value: UInt64(immr), width: 6),
                ],
            )
        }

        // LSL alias (opc=10, imms != regsize-1, imms+1 == immr).
        if opc == 0b10, imms != (regSize &- 1), imms &+ 1 == immr {
            let shift: UInt8 = regSize &- 1 &- imms
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .lsl,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: baseWrites,
                flagEffect: .none,
                category: .dataProcessingImmediate,
                operands: [
                    .register(rdRef), .register(rnRef),
                    .unsignedImmediate(value: UInt64(shift), width: 6),
                ],
            )
        }

        // SBFIZ alias (opc=00, imms < immr).
        if opc == 0b00, imms < immr {
            let lsb: UInt8 = (regSize &- immr) & (regSize &- 1)
            let widthOp: UInt8 = imms &+ 1
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .sbfiz,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: baseWrites,
                flagEffect: .none,
                category: .dataProcessingImmediate,
                operands: [
                    .register(rdRef), .register(rnRef),
                    .unsignedImmediate(value: UInt64(lsb), width: 6),
                    .unsignedImmediate(value: UInt64(widthOp), width: 6),
                ],
            )
        }

        // SBFX alias (opc=00, imms >= immr; the imms=regsize-1 / immr=0
        // sub-cases already routed via ASR / SXTB/H/W above).
        if opc == 0b00, imms >= immr {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .sbfx,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: baseWrites,
                flagEffect: .none,
                category: .dataProcessingImmediate,
                operands: [
                    .register(rdRef), .register(rnRef),
                    .unsignedImmediate(value: UInt64(immr), width: 6),
                    .unsignedImmediate(value: UInt64(imms &- immr &+ 1), width: 6),
                ],
            )
        }

        // UBFIZ alias (opc=10, imms < immr; LSL sub-case already routed).
        if opc == 0b10, imms < immr {
            let lsb: UInt8 = (regSize &- immr) & (regSize &- 1)
            let widthOp: UInt8 = imms &+ 1
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .ubfiz,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: baseWrites,
                flagEffect: .none,
                category: .dataProcessingImmediate,
                operands: [
                    .register(rdRef), .register(rnRef),
                    .unsignedImmediate(value: UInt64(lsb), width: 6),
                    .unsignedImmediate(value: UInt64(widthOp), width: 6),
                ],
            )
        }

        // UBFX alias (opc=10, imms >= immr; LSR / UXTB / UXTH sub-cases
        // already routed).
        if opc == 0b10, imms >= immr {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .ubfx,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: baseWrites,
                flagEffect: .none,
                category: .dataProcessingImmediate,
                operands: [
                    .register(rdRef), .register(rnRef),
                    .unsignedImmediate(value: UInt64(immr), width: 6),
                    .unsignedImmediate(value: UInt64(imms &- immr &+ 1), width: 6),
                ],
            )
        }

        // BFC alias (opc=01, Rn=31, (immr==0 OR imms<immr)).
        // Apple-binary parity target is -mattr=+v8.2a which gates this
        // alias. Operand list drops Rn.
        if opc == 0b01, Rn == 31, immr == 0 || imms < immr {
            let lsb: UInt8 = (regSize &- immr) & (regSize &- 1)
            let widthOp: UInt8 = imms &+ 1
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .bfc,
                semanticReads: baseReads,
                semanticWrites: baseWrites,
                flagEffect: .none,
                category: .dataProcessingImmediate,
                operands: [
                    .register(rdRef),
                    .unsignedImmediate(value: UInt64(lsb), width: 6),
                    .unsignedImmediate(value: UInt64(widthOp), width: 6),
                ],
            )
        }

        // BFI alias (opc=01, imms < immr; not BFC).
        if opc == 0b01, imms < immr {
            let lsb: UInt8 = (regSize &- immr) & (regSize &- 1)
            let widthOp: UInt8 = imms &+ 1
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .bfi,
                semanticReads: baseReads,
                semanticWrites: baseWrites,
                flagEffect: .none,
                category: .dataProcessingImmediate,
                operands: [
                    .register(rdRef), .register(rnRef),
                    .unsignedImmediate(value: UInt64(lsb), width: 6),
                    .unsignedImmediate(value: UInt64(widthOp), width: 6),
                ],
            )
        }

        // BFXIL alias is the catch-all for everything that reached this
        // point. By construction:
        //   - opc=11 was rejected as reserved at the top.
        //   - opc=00 paths returned via SBFIZ/SBFX/SXTB/SXTH/SXTW/ASR.
        //   - opc=10 paths returned via UBFIZ/UBFX/UXTB/UXTH/LSR/LSL.
        //   - opc=01 paths returned via BFC/BFI for imms<immr (or Rn=XZR).
        // The only opc=01 remainder is `imms >= immr`, which is BFXIL.
        // The guard is dropped (the condition is structurally guaranteed)
        // so there is no dead final-fallback branch.
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .bfxil,
            semanticReads: baseReads,
            semanticWrites: baseWrites,
            flagEffect: .none,
            category: .dataProcessingImmediate,
            operands: [
                .register(rdRef), .register(rnRef),
                .unsignedImmediate(value: UInt64(immr), width: 6),
                .unsignedImmediate(value: UInt64(imms &- immr &+ 1), width: 6),
            ],
        )
    }
}
