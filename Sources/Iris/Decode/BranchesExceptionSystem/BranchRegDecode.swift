// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Unconditional branch (register), regular + ARM64E auth.
// Encoding prefix bits 31:25 = 1101011. Sub-dispatch order:
//   1) verify bits 20:16 == 11111
//   2) bit 24 = 0 + bits 15:11 = 00000 → regular BR/BLR/RET/ERET/DRPS
//   3) bit 24 = 0 + bits 15:11 = 00001 → one-operand-zero auth or return-auth
//   4) bit 24 = 1 + bits 15:11 = 00001 → two-operand auth
// Auth-branch key (A vs B) is at bit 10 (M); 0 → key A, 1 → key B.
// ARM64E gating: auth-branches decode regardless of `context.isARM64E` so
// that decoding is deterministic from bit pattern alone — matching
// llvm-mc behaviour when +pauth is in mattr.

enum BranchRegDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        // Common fixed-field check: bits 20:16 must be 11111.
        if (encoding >> 16) & 0x1F != 0x1F {
            return .undefined(at: address, encoding: encoding)
        }
        let bit24 = (encoding >> 24) & 1
        let bits15_11 = (encoding >> 11) & 0x1F
        if bit24 == 1 {
            // Two-operand auth-branch family.
            if bits15_11 != 0b00001 {
                return .undefined(at: address, encoding: encoding)
            }
            return decodeAuthTwoOperand(encoding: encoding, address: address)
        }
        // bit24 == 0
        if bits15_11 == 0b00000 {
            return decodeRegular(encoding: encoding, address: address)
        }
        if bits15_11 == 0b00001 {
            return decodeAuthZeroOrReturn(encoding: encoding, address: address)
        }
        return .undefined(at: address, encoding: encoding)
    }

    // MARK: regular BR/BLR/RET/ERET/DRPS

    @inline(__always)
    private static func decodeRegular(encoding: UInt32, address: UInt64) -> DecodedDraft {
        // Fixed-field checks:
        //   bit 10 == 0
        //   bits 4:0 == 00000
        if (encoding >> 10) & 1 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        if encoding & 0x1F != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let opc = UInt8((encoding >> 21) & 0xF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let rnRef: RegisterRef = (Rn == 31) ? .xzr() : .x(Rn)
        switch opc {
        case 0b0000: // BR
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .br,
                semanticReads: RegisterSet.empty.inserting(rnRef),
                branchClass: .indirect,
                category: .branchesExceptionSystem,
                operands: [.register(rnRef)],
            )
        case 0b0001: // BLR
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .blr,
                semanticReads: RegisterSet.empty.inserting(rnRef),
                semanticWrites: RegisterSet.empty.inserting(.x(30)),
                branchClass: .call,
                category: .branchesExceptionSystem,
                operands: [.register(rnRef)],
            )
        case 0b0010: // RET
            // RET with Rn=30 (LR) has
            // empty operands at decode time. Other Rn values keep the
            // operand so the canonicalizer renders `ret xN`. The
            // semantic-read of Rn is preserved either way.
            let retOperands: [Operand] = (Rn == 30) ? [] : [.register(rnRef)]
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .ret,
                semanticReads: RegisterSet.empty.inserting(rnRef),
                branchClass: .return,
                category: .branchesExceptionSystem,
                operands: retOperands,
            )
        case 0b0100: // ERET — Rn must be 11111
            if Rn != 31 {
                return .undefined(at: address, encoding: encoding)
            }
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .eret,
                branchClass: .return,
                category: .branchesExceptionSystem,
                operands: [],
            )
        case 0b0101: // DRPS — Rn must be 11111
            if Rn != 31 {
                return .undefined(at: address, encoding: encoding)
            }
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .drps,
                branchClass: .return,
                category: .branchesExceptionSystem,
                operands: [],
            )
        default:
            return .undefined(at: address, encoding: encoding)
        }
    }

    // MARK: auth two-operand (BRAA/BRAB/BLRAA/BLRAB)

    @inline(__always)
    private static func decodeAuthTwoOperand(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let opcLow3 = UInt8((encoding >> 21) & 0x7)
        let M = UInt8((encoding >> 10) & 1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rm = UInt8(encoding & 0x1F)
        // Rn / Rm settable; no constraint beyond the family-wide fixed bits.
        let rnRef: RegisterRef = (Rn == 31) ? .xzr() : .x(Rn)
        // Rm = 31 in the two-operand form is rendered `sp` by llvm-mc, NOT
        // xzr.
        let rmRef: RegisterRef = (Rm == 31) ? .sp() : .x(Rm)
        let mnemonic: Mnemonic
        let isCall: Bool
        switch (opcLow3, M) {
        case (0b000, 0): mnemonic = .braa; isCall = false
        case (0b000, 1): mnemonic = .brab; isCall = false
        case (0b001, 0): mnemonic = .blraa; isCall = true
        case (0b001, 1): mnemonic = .blrab; isCall = true
        default:
            return .undefined(at: address, encoding: encoding)
        }
        let reads = RegisterSet.empty.inserting(rnRef).inserting(rmRef)
        let writes: RegisterSet = isCall ? RegisterSet.empty.inserting(.x(30)) : .empty
        let branchClass: BranchClass = isCall ? .call : .indirect
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: writes,
            branchClass: branchClass,
            category: .branchesExceptionSystem,
            operands: [.register(rnRef), .register(rmRef)],
        )
    }

    // MARK: auth one-operand-zero (BRAAZ/BRABZ/BLRAAZ/BLRABZ) and

    // return-auth (RETAA/RETAB/ERETAA/ERETAB).

    @inline(__always)
    private static func decodeAuthZeroOrReturn(encoding: UInt32, address: UInt64) -> DecodedDraft {
        // Rm field (bits 4:0) must be 11111 for every encoding in this branch.
        if encoding & 0x1F != 0x1F {
            return .undefined(at: address, encoding: encoding)
        }
        let opcLow3 = UInt8((encoding >> 21) & 0x7)
        let M = UInt8((encoding >> 10) & 1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        switch opcLow3 {
        case 0b000, 0b001:
            // BRAAZ/BRABZ (0b000) or BLRAAZ/BLRABZ (0b001) — one-operand zero.
            // Rn settable.
            let rnRef: RegisterRef = (Rn == 31) ? .xzr() : .x(Rn)
            let isCall = opcLow3 == 0b001
            let mnemonic: Mnemonic = if isCall {
                M == 0 ? .blraaz : .blrabz
            } else {
                M == 0 ? .braaz : .brabz
            }
            let writes: RegisterSet = isCall ? RegisterSet.empty.inserting(.x(30)) : .empty
            let branchClass: BranchClass = isCall ? .call : .indirect
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: RegisterSet.empty.inserting(rnRef),
                semanticWrites: writes,
                branchClass: branchClass,
                category: .branchesExceptionSystem,
                operands: [.register(rnRef)],
            )
        case 0b010:
            // RETAA / RETAB — no operand; Rn must be 11111.
            if Rn != 31 {
                return .undefined(at: address, encoding: encoding)
            }
            let mnemonic: Mnemonic = (M == 0) ? .retaa : .retab
            // RETAA / RETAB authenticate LR using SP as modifier.
            let reads = RegisterSet.empty.inserting(.x(30)).inserting(.sp())
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: reads,
                branchClass: .return,
                category: .branchesExceptionSystem,
                operands: [],
            )
        case 0b100:
            // ERETAA / ERETAB — kernel only; no operand; Rn must be 11111.
            if Rn != 31 {
                return .undefined(at: address, encoding: encoding)
            }
            let mnemonic: Mnemonic = (M == 0) ? .eretaa : .eretab
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                branchClass: .return,
                category: .branchesExceptionSystem,
                operands: [],
            )
        default:
            return .undefined(at: address, encoding: encoding)
        }
    }
}
