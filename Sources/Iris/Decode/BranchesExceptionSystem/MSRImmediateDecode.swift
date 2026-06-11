// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// MSR (immediate) — write a 4-bit immediate to a PSTATE
// field.
// Encoding: 1101 0101 0000 0 00 op1 0100 CRm op2 11111
// Where (op1, op2) selects the PSTATE field and CRm is the imm4 value.
// Special-case standalone instructions (encoded as MSR-imm but rendered
// with their own mnemonic):
//   (op1=000, op2=000, CRm=0): CFINV
//   (op1=000, op2=001, CRm=0): XAFLAG
//   (op1=000, op2=010, CRm=0): AXFLAG
// Recognised PSTATE fields → mnemonic `.msrImm` + (.pstateField, immediate).
// Unrecognised (op1, op2) → mnemonic `.msr` + (.systemRegister(op0=0, ...),
// .register(.xzr())) matching llvm-mc's MSR-register fallback rendering.

enum MSRImmediateDecode {
    @inline(__always)
    static func decode(
        encoding: UInt32, address: UInt64, op1: UInt8, CRm: UInt8, op2: UInt8,
    ) -> DecodedDraft {
        // CFINV / XAFLAG / AXFLAG — standalone, CRm (the imm field) is
        // ignored by the architecture for these.
        if op1 == 0 {
            switch op2 {
            case 0b000:
                return DecodedDraft(
                    address: address, encoding: encoding, mnemonic: .cfinv,
                    flagEffect: [.writesC, .readsC],
                    category: .branchesExceptionSystem,
                )
            case 0b001:
                return DecodedDraft(
                    address: address, encoding: encoding, mnemonic: .xaflag,
                    flagEffect: [.nzcv, .readsNZCV],
                    category: .branchesExceptionSystem,
                )
            case 0b010:
                return DecodedDraft(
                    address: address, encoding: encoding, mnemonic: .axflag,
                    flagEffect: [.nzcv, .readsNZCV],
                    category: .branchesExceptionSystem,
                )
            default:
                break
            }
        }
        // SMSTART / SMSTOP (FEAT_SME) — op1=011, op2=011, CRm selects the
        // PSTATE.SM/ZA target and the start/stop direction:
        //   010 smstop sm   011 smstart sm
        //   100 smstop za   101 smstart za
        //   110 smstop      111 smstart
        if op1 == 0b011, op2 == 0b011, CRm >= 0b010, CRm <= 0b0111 {
            let startStop = CRm & 1 // 1 → start, 0 → stop
            let target = CRm >> 1 // 01 → sm, 10 → za, 11 → both
            let mnemonic: Mnemonic = (startStop == 1) ? .smstart : .smstop
            // target carried as a small unsigned immediate the canonicalizer
            // maps to the "sm" / "za" suffix (3 = both → no suffix).
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                category: .branchesExceptionSystem,
                operands: [.unsignedImmediate(value: UInt64(target), width: 2)],
            )
        }
        // ALLINT (FEAT_NMI): op1=001, op2=000, CRm = 000x (imm = x).
        // PM (FEAT_SEBEP):   op1=001, op2=000, CRm = 001x (imm = x).
        if op1 == 0b001, op2 == 0b000, CRm < 0b0100 {
            let field: PSTATEField = (CRm < 0b010) ? .allInt : .pm
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .msrImm,
                category: .branchesExceptionSystem,
                operands: [
                    .pstateField(field),
                    .unsignedImmediate(value: UInt64(CRm & 1), width: 4),
                ],
            )
        }
        // Named PSTATE fields selected by (op1, op2). The imm4 is CRm.
        let field: PSTATEField? = switch (op1, op2) {
        case (0b000, 0b101): .spSel
        case (0b011, 0b110): .daifSet
        case (0b011, 0b111): .daifClr
        case (0b000, 0b011): .uao
        case (0b000, 0b100): .pan
        case (0b011, 0b010): .dit
        case (0b011, 0b100): .tco
        case (0b011, 0b001): .ssbs
        default: nil
        }
        if let field {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .msrImm,
                category: .branchesExceptionSystem,
                operands: [
                    .pstateField(field),
                    .unsignedImmediate(value: UInt64(CRm), width: 4),
                ],
            )
        }
        // Unknown field — fall back to MSR-register form with synthesised
        // op0=0, CRn=4 sysreg tuple. Rt is XZR (the imm4 is recorded in
        // CRm position of the sysreg synthesised here).
        let sysreg = SystemRegisterEncoding(
            op0: 0, op1: op1, crn: 4, crm: CRm, op2: op2,
        )
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .msr,
            semanticReads: RegisterSet.empty.inserting(.xzr()),
            category: .branchesExceptionSystem,
            operands: [.systemRegister(sysreg), .register(.xzr())],
        )
    }
}
