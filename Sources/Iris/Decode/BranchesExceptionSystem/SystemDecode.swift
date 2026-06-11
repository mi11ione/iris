// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Top-level System dispatch (bits 31:24 = 0xD5).
// Verify bits 23:22 = 00, then route by (bit 21, bits 20:19,
// bits 15:12) to HINT / barrier / MSR-imm / WFXT / SYS / SYSL / MSR-reg / MRS.
// Fixed-field checks enforce that reserved encodings within the tier produce
// `.undefined` rather than plausible-looking mis-decodes.

enum SystemDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let bits23_22 = UInt8((encoding >> 22) & 0x3)
        // bits 23:22 = 01 marks the FEAT_D128 128-bit forms (MRRS / MSRR /
        // SYSP). bits 23:22 = 00 is the regular System tier. 10/11 reserved.
        if bits23_22 == 0b01 {
            return decodeD128(encoding: encoding, address: address)
        }
        if bits23_22 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let L = UInt8((encoding >> 21) & 1)
        // op0 = bits 20:19 (a full 2-bit field). op0 == 1 is the SYS / SYSL
        // class; op0 ∈ {0, 2, 3} are MSR (register) / MRS to a system
        // register. The op0 == 0 control sub-tier (HINT / barrier / MSR-imm /
        // WFXT) shares the op0 == 0 space with register access: it applies
        // only when L == 0 and the instruction's fixed fields match;
        // otherwise op0 == 0 is a plain MSR/MRS to a `S0_…` register.
        let op0 = UInt8((encoding >> 19) & 0x3)
        if op0 == 0b01 {
            // SYS / SYSL — Rt at bits 4:0 (no fixed-field constraint on Rt).
            let Rt = UInt8(encoding & 0x1F)
            return SystemInstructionDecode.decode(
                encoding: encoding, address: address, L: L, Rt: Rt,
            )
        }
        if op0 == 0, L == 0 {
            // Candidate control instruction (HINT / barrier / MSR-imm need
            // Rt == 11111; WFET/WFIT carry a settable Rt). decodeControl
            // enforces each instruction's fixed fields and returns
            // .undefined when none match — then fall through to the op0 == 0
            // MSR form.
            let control = decodeControl(encoding: encoding, address: address)
            if control.mnemonic != .undefined {
                return control
            }
        }
        // MSR (register) / MRS — op0 ∈ {0, 2, 3} taken from bits 20:19.
        return SystemMoveDecode.decode(encoding: encoding, address: address, L: L)
    }

    /// FEAT_D128 forms (bits 23:22 = 01): MRRS / MSRR (128-bit register move
    /// pair) and SYSP (128-bit SYS pair). Mirrors the regular tier: op0 (bits
    /// 20:19) == 1 with L == 0 is SYSP; all other (op0, L) are the move pair.
    @inline(__always)
    private static func decodeD128(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let L = UInt8((encoding >> 21) & 1)
        // op0 = bits 20:19, mirroring the regular tier. op0 == 1 with L == 0
        // is SYSP; all other (op0, L) are MSRR (L=0) / MRRS (L=1) with op0
        // taken from bits 20:19.
        let op0 = UInt8((encoding >> 19) & 0x3)
        if op0 == 0b01, L == 0 {
            return SystemInstructionDecode.decodeSysp(encoding: encoding, address: address)
        }
        return SystemMoveDecode.decodeD128(encoding: encoding, address: address, L: L)
    }

    @inline(__always)
    private static func decodeControl(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let bits15_12 = UInt8((encoding >> 12) & 0xF)
        switch bits15_12 {
        case 0b0010:
            // HINT — op1 (bits 18:16) must be 011 and Rt must be 11111;
            // otherwise this is an op0 == 0 MSR/MRS, handled by the caller.
            if (encoding >> 16) & 0x7 != 0b011 || encoding & 0x1F != 0x1F {
                return .undefined(at: address, encoding: encoding)
            }
            let imm7 = UInt8((encoding >> 5) & 0x7F)
            return HintDecode.decode(encoding: encoding, address: address, imm7: imm7)
        case 0b0011:
            // Barrier (CRmSystemI) — op1 (bits 18:16) must be 011 and Rt
            // must be 11111; otherwise an op0 == 0 MSR/MRS.
            if (encoding >> 16) & 0x7 != 0b011 || encoding & 0x1F != 0x1F {
                return .undefined(at: address, encoding: encoding)
            }
            let CRm = UInt8((encoding >> 8) & 0xF)
            let op2 = UInt8((encoding >> 5) & 0x7)
            return BarrierDecode.decode(
                encoding: encoding, address: address, CRm: CRm, op2: op2,
            )
        case 0b0100:
            // MSR-immediate — Rt must be 11111.
            if encoding & 0x1F != 0x1F {
                return .undefined(at: address, encoding: encoding)
            }
            let op1 = UInt8((encoding >> 16) & 0x7)
            let CRm = UInt8((encoding >> 8) & 0xF)
            let op2 = UInt8((encoding >> 5) & 0x7)
            return MSRImmediateDecode.decode(
                encoding: encoding, address: address, op1: op1, CRm: CRm, op2: op2,
            )
        case 0b0001:
            // WFET / WFIT (RegInputSystemI) — bits 18:16 must be 011 AND
            // CRm must be 0000 (architectural fixed fields per ARM ARM
            // C5.6 RegInputSystemI). Without the bits-18:16 check,
            // encodings with op1 != 011 would mis-decode as WFET/WFIT
            // instead of falling through to .undefined.
            if (encoding >> 16) & 0x7 != 0b011 {
                return .undefined(at: address, encoding: encoding)
            }
            if (encoding >> 8) & 0xF != 0 {
                return .undefined(at: address, encoding: encoding)
            }
            let op2 = UInt8((encoding >> 5) & 0x7)
            let Rt = UInt8(encoding & 0x1F)
            return WFXTDecode.decode(
                encoding: encoding, address: address, op2: op2, Rt: Rt,
            )
        default:
            return .undefined(at: address, encoding: encoding)
        }
    }
}
