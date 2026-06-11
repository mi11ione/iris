// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// LRCPC2 (Armv8.4 FEAT_LRCPC2) load-acquire / store-
// release unscaled-immediate. LDAPUR/STLUR family. Encoding shell
// bits[29:24] = 011001, V=0. imm9 at bits[20:12], bits[11:10]=00.
//
// size × opc selects:
//   size=00 opc=00 STLURB
//   size=00 opc=01 LDAPURB
//   size=00 opc=10 LDAPURSB (sign-extend to Xt)
//   size=00 opc=11 LDAPURSB (sign-extend to Wt)
//   size=01 opc=00 STLURH
//   size=01 opc=01 LDAPURH
//   size=01 opc=10 LDAPURSH (sign-extend to Xt)
//   size=01 opc=11 LDAPURSH (sign-extend to Wt)
//   size=10 opc=00 STLUR (Wt)
//   size=10 opc=01 LDAPUR (Wt)
//   size=10 opc=10 LDAPURSW (sign-extend to Xt)
//   size=11 opc=00 STLUR (Xt)
//   size=11 opc=01 LDAPUR (Xt)
//
// Memory ordering: stores get `.release`, loads get `.acquire`. RCpc
// semantics are weaker than full acquire/release; the
// mnemonic carries that distinction for downstream consumers.

enum LRCPC2Decode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        // bits[11:10] are 00 for every word that arrives here: the
        // dispatcher routes 10 to RCPC3/GCS and 11 to GCS, and any
        // bit10 = 1 word in this shell matches the MOPS discriminant
        // (bits 28,27,24,10 set; 29,25,21 clear) and is consumed by the
        // MOPS decoder before the shell dispatch.
        // bit[21] = 0 is required for valid LRCPC2. The L/S top-level
        // dispatcher already discriminates by bit 21 inside the
        // `case 0b011001` branch — bit 21 = 1 routes to MTE-LS, bit 21 =
        // 0 reaches this function — so an internal bit-21 check would
        // be unreachable for the only call site (LoadsAndStoresDecoder).
        let size = UInt8((encoding >> 30) & 0x3)
        let opc = UInt8((encoding >> 22) & 0x3)
        let imm9 = (encoding >> 12) & 0x1FF
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        let displacement = lsSignExtendImm9(imm9)

        let mnemonic: Mnemonic
        let rtWidth: RegisterWidth
        let memoryAccess: MemoryAccess
        let memoryOrdering: MemoryOrdering
        let isLoad: Bool

        switch (size, opc) {
        case (0b00, 0b00):
            mnemonic = .stlurb; rtWidth = .w32; memoryAccess = .store
            memoryOrdering = [.release]; isLoad = false
        case (0b00, 0b01):
            mnemonic = .ldapurb; rtWidth = .w32; memoryAccess = .load
            memoryOrdering = [.acquire]; isLoad = true
        case (0b00, 0b10):
            mnemonic = .ldapursb; rtWidth = .x64; memoryAccess = .load
            memoryOrdering = [.acquire]; isLoad = true
        case (0b00, 0b11):
            mnemonic = .ldapursb; rtWidth = .w32; memoryAccess = .load
            memoryOrdering = [.acquire]; isLoad = true
        case (0b01, 0b00):
            mnemonic = .stlurh; rtWidth = .w32; memoryAccess = .store
            memoryOrdering = [.release]; isLoad = false
        case (0b01, 0b01):
            mnemonic = .ldapurh; rtWidth = .w32; memoryAccess = .load
            memoryOrdering = [.acquire]; isLoad = true
        case (0b01, 0b10):
            mnemonic = .ldapursh; rtWidth = .x64; memoryAccess = .load
            memoryOrdering = [.acquire]; isLoad = true
        case (0b01, 0b11):
            mnemonic = .ldapursh; rtWidth = .w32; memoryAccess = .load
            memoryOrdering = [.acquire]; isLoad = true
        case (0b10, 0b00):
            mnemonic = .stlur; rtWidth = .w32; memoryAccess = .store
            memoryOrdering = [.release]; isLoad = false
        case (0b10, 0b01):
            mnemonic = .ldapur; rtWidth = .w32; memoryAccess = .load
            memoryOrdering = [.acquire]; isLoad = true
        case (0b10, 0b10):
            mnemonic = .ldapursw; rtWidth = .x64; memoryAccess = .load
            memoryOrdering = [.acquire]; isLoad = true
        case (0b11, 0b00):
            mnemonic = .stlur; rtWidth = .x64; memoryAccess = .store
            memoryOrdering = [.release]; isLoad = false
        case (0b11, 0b01):
            mnemonic = .ldapur; rtWidth = .x64; memoryAccess = .load
            memoryOrdering = [.acquire]; isLoad = true
        default:
            return .undefined(at: address, encoding: encoding)
        }

        let rtRef = lsGprOperand(encoding: Rt, width: rtWidth, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)

        let reads: RegisterSet
        let writes: RegisterSet
        if isLoad {
            reads = lsInsertingNonZero(reg: rnRef, into: .empty)
            writes = lsInsertingNonZero(reg: rtRef, into: .empty)
        } else {
            var r = lsInsertingNonZero(reg: rnRef, into: .empty)
            r = lsInsertingNonZero(reg: rtRef, into: r)
            reads = r
            writes = .empty
        }

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: writes,
            branchClass: .none,
            memoryAccess: memoryAccess,
            memoryOrdering: memoryOrdering,
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
                    writeback: .none,
                )),
            ],
        )
    }
}
