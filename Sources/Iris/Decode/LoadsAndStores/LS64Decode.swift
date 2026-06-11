// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// FEAT_LS64 single-copy atomic 64-byte load/store. Shares the LSE-atomic
// shell (bits[29:24] = 111000, V=0, bit[21]=1, bits[11:10]=00) at the
// plain ordering bits[23:22] = 00, distinguished by bits[15:12]:
//   1101 = ld64b   (Xt, [Xn])
//   1001 = st64b   (Xt, [Xn])
//   1011 = st64bv  (Xs, Xt, [Xn])
//   1010 = st64bv0 (Xs, Xt, [Xn])
//
//   bits[4:0] = Rt — first register of the 8-register group Xt..Xt+7, so
//                    Rt must be even and Rt+7 <= 30 (Rt in {0,2,..,22});
//                    other values UNDEFINED.
//   bits[9:5] = Rn (base, SP-role at 31).
//   bits[20:16] = Rs — status/data register; the ld64b/st64b forms require
//                 Rs = 11111 (an unused fixed field, UNDEFINED otherwise),
//                 the st64bv/st64bv0 forms use it as a real register.

enum LS64Decode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        // The dispatcher routes only size == 11 with op ∈
        // {1001, 1010, 1011, 1101} here (size 00/01 in this op slot is
        // FEAT_THE RCW; size 10 falls to UNDEFINED there).
        let op = UInt8((encoding >> 12) & 0xF)
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        // Rt names the base of an 8-register group: even and <= 22.
        if (Rt & 1) != 0 || Rt > 22 {
            return .undefined(at: address, encoding: encoding)
        }

        let rtRef = RegisterRef.x(Rt)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        let rnOperand = Operand.memory(MemoryOperand(base: .register(rnRef)))

        switch op {
        case 0b1101:
            // ld64b Xt, [Xn] — Rs is a fixed 11111 field.
            if Rs != 0x1F {
                return .undefined(at: address, encoding: encoding)
            }
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .ld64b,
                semanticReads: lsInsertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: .empty.inserting(rtRef),
                branchClass: .none,
                memoryAccess: .load,
                memoryOrdering: [],
                flagEffect: .none,
                category: .loadsAndStores,
                operands: [.register(rtRef), rnOperand],
            )
        case 0b1001:
            // st64b Xt, [Xn] — Rs is a fixed 11111 field.
            if Rs != 0x1F {
                return .undefined(at: address, encoding: encoding)
            }
            var reads = lsInsertingNonZero(reg: rnRef, into: .empty)
            reads = reads.inserting(rtRef)
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .st64b,
                semanticReads: reads,
                semanticWrites: .empty,
                branchClass: .none,
                memoryAccess: .store,
                memoryOrdering: [],
                flagEffect: .none,
                category: .loadsAndStores,
                operands: [.register(rtRef), rnOperand],
            )
        default:
            // 0b1011 / 0b1010 — the dispatcher routes no other op here.
            // st64bv / st64bv0 Xs, Xt, [Xn] — Rs is the status result.
            let mnemonic: Mnemonic = (op == 0b1011) ? .st64bv : .st64bv0
            let rsRef = lsGprOperand(encoding: Rs, width: .x64, form: .zrOrGeneral)
            var reads = lsInsertingNonZero(reg: rnRef, into: .empty)
            reads = reads.inserting(rtRef)
            let writes = lsInsertingNonZero(reg: rsRef, into: .empty)
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: reads,
                semanticWrites: writes,
                branchClass: .none,
                memoryAccess: .store,
                memoryOrdering: [],
                flagEffect: .none,
                category: .loadsAndStores,
                operands: [.register(rsRef), .register(rtRef), rnOperand],
            )
        }
    }
}
