// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// ARM64E PAC authenticated loads (LDRAA / LDRAB).
// Encoding: bits[31:24] = 11111000, bit[23] = M (0=LDRAA/DA, 1=LDRAB/DB),
// bit[22] = S (sign bit of pre-scaled offset), bit[21] = 1 FIXED,
// bits[20:12] = imm9 (offset scaled by 8 with sign bit S), bit[11] = W
// (0=signed-offset, 1=pre-index writeback), bit[10] = 1 FIXED,
// bits[9:5] = Rn, bits[4:0] = Rt.
//
// Verified against `llvm-mc -show-encoding`:
//   ldraa x0, [x0]         = 0xF8200400
//   ldraa x0, [x0, #8]     = 0xF8201400
//   ldraa x0, [x0, #0]!    = 0xF8200C00
//   ldrab x0, [x0]         = 0xF8A00400
//   ldrab x0, [x0, #8]!    = 0xF8A01C00
//
// Operand shape: `Xt, [Xn|SP{, #simm}{!}]`. Offset is signed in range
// [-4096, +4088] in 8-byte multiples. Pre-index writeback when W=1 writes
// back to Xn. ARM64E gating is enforced in the top-level dispatcher (the
// caller checks `context.isARM64E`).

enum LDRADecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        // LDRAA/LDRAB is 64-bit doubleword only — bits[31:30] = 11 FIXED.
        // Other sizes are unallocated/reserved; llvm-mc rejects them.
        let size = UInt8((encoding >> 30) & 0x3)
        if size != 0b11 {
            return .undefined(at: address, encoding: encoding)
        }
        let M = UInt8((encoding >> 23) & 1)
        let S = UInt8((encoding >> 22) & 1)
        let imm9 = (encoding >> 12) & 0x1FF
        let W = UInt8((encoding >> 11) & 1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        // 10-bit signed offset: the sign bit S (bit[22]) concatenated with
        // imm9 (bits[20:12]) — bit[21] is a fixed 1, not part of the field.
        // Pack (S << 9) | imm9, sign-extend the 10-bit value, then scale by 8.
        let imm10 = (UInt32(S) << 9) | (imm9 & 0x1FF)
        let displacement = lsSignExtendImm10(imm10) * 8

        let mnemonic: Mnemonic = M == 0 ? .ldraa : .ldrab
        let rtRef = lsGprOperand(encoding: Rt, width: .x64, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)

        let writeback: Writeback = W == 1 ? .preIndex : .none
        var writes = lsInsertingNonZero(reg: rtRef, into: .empty)
        if writeback == .preIndex {
            writes = lsInsertingNonZero(reg: rnRef, into: writes)
        }

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: lsInsertingNonZero(reg: rnRef, into: .empty),
            semanticWrites: writes,
            branchClass: .none,
            memoryAccess: .load,
            memoryOrdering: [],
            flagEffect: .none,
            category: .loadsAndStores,
            operands: [
                .register(rtRef),
                .memory(MemoryOperand(
                    base: .register(rnRef),
                    index: nil,
                    displacement: displacement,
                    extend: .none,
                    shift: 0,
                    writeback: writeback,
                )),
            ],
        )
    }
}
