// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Load/store register, register offset (with extend).
// Encoding shell bits[29:24] = 111000, V=0, bit[21]=1, bits[11:10] = 10.
//
//   size × opc selects the load/store kind (same table as LDUR/LDR).
//   bits[20:16] = Rm (index register).
//   bits[15:13] = option (extend kind, restricted to {010,011,110,111}):
//     010 = UXTW  (Rm = Wm, zero-extend)
//     011 = LSL   (Rm = Xm; only if S enables; otherwise UXTX equivalent)
//     110 = SXTW  (Rm = Wm, sign-extend)
//     111 = SXTX  (Rm = Xm, sign-extend)
//   Options 000/001/100/101 are reserved → UNDEFINED.
//
//   bit[12] = S — if 1, shift the index by log2(size).
//
// PRFM (register) is the opc=10 + size=11 case here.

enum LoadStoreRegisterOffsetDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let size = UInt8((encoding >> 30) & 0x3)
        let opc = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let option = UInt8((encoding >> 13) & 0x7)
        let S = UInt8((encoding >> 12) & 1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        // Reserved extend options.
        if option & 0b010 == 0 {
            // option ∈ {000, 001, 100, 101} → reserved
            return .undefined(at: address, encoding: encoding)
        }

        // Decode extend kind from the option field. We then pick the
        // rendered extend + shift based on the S bit, per the llvm-mc
        // convention:
        //   S=0 + LSL (option=011) → bare `[Rn, Xm]` (extend collapsed)
        //   S=0 + UXTW/SXTW/SXTX → `[Rn, <reg>, <ext>]` (keyword, no #amount)
        //   S=1 + anything → `[Rn, <reg>, <ext> #amount]` (always with #amount)
        // The canonicalizer reads `MemoryOperand.shift = 0xFF` as the
        // "no amount displayed" sentinel.
        let optionExtendKind: ExtendKind
        let rmWidth: RegisterWidth
        switch option {
        case 0b010: optionExtendKind = .uxtw; rmWidth = .w32
        case 0b011: optionExtendKind = .lsl; rmWidth = .x64
        case 0b110: optionExtendKind = .sxtw; rmWidth = .w32
        // The `option & 0b010 == 0` guard above already rejected options
        // {000,001,100,101}; the remaining set is {010,011,110,111} and
        // 0b111 (SXTX) is `default`.
        default: optionExtendKind = .sxtx; rmWidth = .x64
        }
        let extendKind: ExtendKind
        let displayShift: UInt8
        if S == 1 {
            extendKind = optionExtendKind
            displayShift = size
        } else if optionExtendKind == .lsl {
            // S=0 + LSL → collapse the extend; render bare `[Rn, Xm]`.
            extendKind = .none
            displayShift = 0
        } else {
            // S=0 + UXTW/SXTW/SXTX → keyword shown, no #amount.
            extendKind = optionExtendKind
            displayShift = 0xFF
        }

        // Determine mnemonic, target register width, access type.
        let mnemonic: Mnemonic
        let rtWidth: RegisterWidth
        let memoryAccess: MemoryAccess
        let isLoad: Bool

        switch (size, opc) {
        case (0b00, 0b00): mnemonic = .strb; rtWidth = .w32; memoryAccess = .store; isLoad = false
        case (0b00, 0b01): mnemonic = .ldrb; rtWidth = .w32; memoryAccess = .load; isLoad = true
        case (0b00, 0b10): mnemonic = .ldrsb; rtWidth = .x64; memoryAccess = .load; isLoad = true
        case (0b00, 0b11): mnemonic = .ldrsb; rtWidth = .w32; memoryAccess = .load; isLoad = true
        case (0b01, 0b00): mnemonic = .strh; rtWidth = .w32; memoryAccess = .store; isLoad = false
        case (0b01, 0b01): mnemonic = .ldrh; rtWidth = .w32; memoryAccess = .load; isLoad = true
        case (0b01, 0b10): mnemonic = .ldrsh; rtWidth = .x64; memoryAccess = .load; isLoad = true
        case (0b01, 0b11): mnemonic = .ldrsh; rtWidth = .w32; memoryAccess = .load; isLoad = true
        case (0b10, 0b00): mnemonic = .str; rtWidth = .w32; memoryAccess = .store; isLoad = false
        case (0b10, 0b01): mnemonic = .ldr; rtWidth = .w32; memoryAccess = .load; isLoad = true
        case (0b10, 0b10): mnemonic = .ldrsw; rtWidth = .x64; memoryAccess = .load; isLoad = true
        case (0b11, 0b00): mnemonic = .str; rtWidth = .x64; memoryAccess = .store; isLoad = false
        case (0b11, 0b01): mnemonic = .ldr; rtWidth = .x64; memoryAccess = .load; isLoad = true
        case (0b11, 0b10):
            // PRFM <prfop>, [Rn, Rm{, extend{ #amount}}]
            let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
            let rmRef = lsGprOperand(encoding: Rm, width: rmWidth, form: .zrOrGeneral)
            var reads = lsInsertingNonZero(reg: rnRef, into: .empty)
            reads = lsInsertingNonZero(reg: rmRef, into: reads)
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .prfm,
                semanticReads: reads,
                semanticWrites: .empty,
                branchClass: .none,
                memoryAccess: .prefetch,
                memoryOrdering: [],
                flagEffect: .none,
                category: .loadsAndStores,
                operands: [
                    .prefetchOperation(PrefetchOperation(rawValue: Rt)),
                    .memory(MemoryOperand(
                        base: .register(rnRef),
                        index: rmRef,
                        displacement: 0,
                        extend: extendKind,
                        shift: displayShift,
                        writeback: .none,
                    )),
                ],
            )
        default:
            return .undefined(at: address, encoding: encoding)
        }

        let rtRef = lsGprOperand(encoding: Rt, width: rtWidth, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        let rmRef = lsGprOperand(encoding: Rm, width: rmWidth, form: .zrOrGeneral)

        let reads: RegisterSet
        let writes: RegisterSet
        if isLoad {
            var r = lsInsertingNonZero(reg: rnRef, into: .empty)
            r = lsInsertingNonZero(reg: rmRef, into: r)
            reads = r
            writes = lsInsertingNonZero(reg: rtRef, into: .empty)
        } else {
            var r = lsInsertingNonZero(reg: rnRef, into: .empty)
            r = lsInsertingNonZero(reg: rmRef, into: r)
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
            memoryOrdering: [],
            flagEffect: .none,
            category: .loadsAndStores,
            operands: [
                .register(rtRef),
                .memory(MemoryOperand(
                    base: .register(rnRef),
                    index: rmRef,
                    displacement: 0,
                    extend: extendKind,
                    shift: displayShift,
                    writeback: .none,
                )),
            ],
        )
    }
}
