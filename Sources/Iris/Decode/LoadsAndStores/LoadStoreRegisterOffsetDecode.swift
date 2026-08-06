// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum LoadStoreRegisterOffsetDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let size = UInt8((encoding >> 30) & 0x3)
        let opc = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let option = UInt8((encoding >> 13) & 0x7)
        let S = UInt8((encoding >> 12) & 1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        if option & 0b010 == 0 {
            return .undefined(at: address, encoding: encoding)
        }

        let optionExtendKind: ExtendKind
        let rmWidth: RegisterWidth
        switch option {
        case 0b010: optionExtendKind = .uxtw; rmWidth = .w32
        case 0b011: optionExtendKind = .lsl; rmWidth = .x64
        case 0b110: optionExtendKind = .sxtw; rmWidth = .w32
        default: optionExtendKind = .sxtx; rmWidth = .x64
        }
        let extendKind: ExtendKind
        let displayShift: UInt8
        if S == 1 {
            extendKind = optionExtendKind
            displayShift = size
        } else if optionExtendKind == .lsl {
            extendKind = .none
            displayShift = 0
        } else {
            extendKind = optionExtendKind
            displayShift = 0xFF
        }

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
                operandCount: sink.emit(.prefetchOperation(PrefetchOperation(rawValue: Rt)), .memory(MemoryOperand(
                    base: .register(rnRef),
                    index: rmRef,
                    displacement: 0,
                    extend: extendKind,
                    shift: displayShift,
                    writeback: .none,
                ))),
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
            operandCount: sink.emit(.register(rtRef), .memory(MemoryOperand(
                base: .register(rnRef),
                index: rmRef,
                displacement: 0,
                extend: extendKind,
                shift: displayShift,
                writeback: .none,
            ))),
        )
    }
}
