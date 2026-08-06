// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum BranchRegDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (encoding >> 16) & 0x1F != 0x1F {
            return .undefined(at: address, encoding: encoding)
        }
        let bit24 = (encoding >> 24) & 1
        let bits15_11 = (encoding >> 11) & 0x1F
        if bit24 == 1 {
            if bits15_11 != 0b00001 {
                return .undefined(at: address, encoding: encoding)
            }
            return decodeAuthTwoOperand(encoding: encoding, address: address, &sink)
        }
        if bits15_11 == 0b00000 {
            return decodeRegular(encoding: encoding, address: address, &sink)
        }
        if bits15_11 == 0b00001 {
            return decodeAuthZeroOrReturn(encoding: encoding, address: address, &sink)
        }
        return .undefined(at: address, encoding: encoding)
    }

    @inline(__always)
    private static func decodeRegular(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if encoding & 0x1F != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let opc = UInt8((encoding >> 21) & 0xF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        if opc == 0b0111 {
            if Rn != 31 {
                return .undefined(at: address, encoding: encoding)
            }
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: ((encoding >> 10) & 1 == 0) ? .texit : .texitNb,
                branchClass: .return,
                category: .branchesExceptionSystem,
                operandCount: 0,
            )
        }
        if (encoding >> 10) & 1 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let rnRef: RegisterRef = (Rn == 31) ? .xzr() : .x(Rn)
        switch opc {
        case 0b0000:
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .br,
                semanticReads: RegisterSet.empty.inserting(rnRef),
                branchClass: .indirect,
                category: .branchesExceptionSystem,
                operandCount: sink.emit(.register(rnRef)),
            )
        case 0b0001:
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .blr,
                semanticReads: RegisterSet.empty.inserting(rnRef),
                semanticWrites: RegisterSet.empty.inserting(.x(30)),
                branchClass: .call,
                category: .branchesExceptionSystem,
                operandCount: sink.emit(.register(rnRef)),
            )
        case 0b0010:
            let retOperandCount: UInt8 = (Rn == 30) ? 0 : sink.emit(.register(rnRef))
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .ret,
                semanticReads: RegisterSet.empty.inserting(rnRef),
                branchClass: .return,
                category: .branchesExceptionSystem,
                operandCount: retOperandCount,
            )
        case 0b0100:
            if Rn != 31 {
                return .undefined(at: address, encoding: encoding)
            }
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .eret,
                branchClass: .return,
                category: .branchesExceptionSystem,
                operandCount: 0,
            )
        case 0b0101:
            if Rn != 31 {
                return .undefined(at: address, encoding: encoding)
            }
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .drps,
                branchClass: .return,
                category: .branchesExceptionSystem,
                operandCount: 0,
            )
        default:
            return .undefined(at: address, encoding: encoding)
        }
    }

    @inline(__always)
    private static func decodeAuthTwoOperand(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let opcLow3 = UInt8((encoding >> 21) & 0x7)
        let M = UInt8((encoding >> 10) & 1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rm = UInt8(encoding & 0x1F)
        let rnRef: RegisterRef = (Rn == 31) ? .xzr() : .x(Rn)
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
            operandCount: sink.emit(.register(rnRef), .register(rmRef)),
        )
    }

    @inline(__always)
    private static func decodeAuthZeroOrReturn(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let opcLow3 = UInt8((encoding >> 21) & 0x7)
        let M = UInt8((encoding >> 10) & 1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let op4 = UInt8(encoding & 0x1F)
        if op4 != 0x1F {
            if opcLow3 != 0b010 || Rn != 31 {
                return .undefined(at: address, encoding: encoding)
            }
            let rmRef: RegisterRef = .x(op4)
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: (M == 0) ? .retaasppcr : .retabsppcr,
                semanticReads: RegisterSet.empty.inserting(.x(30)).inserting(rmRef),
                branchClass: .return,
                category: .branchesExceptionSystem,
                operandCount: sink.emit(.register(rmRef)),
            )
        }
        switch opcLow3 {
        case 0b000, 0b001:
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
                operandCount: sink.emit(.register(rnRef)),
            )
        case 0b010:
            if Rn != 31 {
                return .undefined(at: address, encoding: encoding)
            }
            let mnemonic: Mnemonic = (M == 0) ? .retaa : .retab
            let reads = RegisterSet.empty.inserting(.x(30)).inserting(.sp())
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: reads,
                branchClass: .return,
                category: .branchesExceptionSystem,
                operandCount: 0,
            )
        case 0b100:
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
                operandCount: 0,
            )
        default:
            return .undefined(at: address, encoding: encoding)
        }
    }
}
