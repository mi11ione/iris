// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum MSRImmediateDecode {
    @inline(__always)
    static func decode(
        encoding: UInt32, address: UInt64, op1: UInt8, CRm: UInt8, op2: UInt8, _ sink: inout OperandSink,
    ) -> DecodedDraft {
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
        if op1 == 0b011, op2 == 0b011, CRm >= 0b010, CRm <= 0b0111 {
            let startStop = CRm & 1
            let target = CRm >> 1
            let mnemonic: Mnemonic = (startStop == 1) ? .smstart : .smstop
            var effect: ScalableEffect = []
            if target & 0b01 != 0 { effect.insert(.writesStreamingMode) }
            if target & 0b10 != 0 { effect.insert(.writesZAEnable) }
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                category: .branchesExceptionSystem,
                operandCount: sink.emit(
                    .unsignedImmediate(value: UInt64(target), width: 2),
                ),
                scalableEffect: effect,
            )
        }
        if op1 == 0b001, op2 == 0b000, CRm < 0b0100 {
            let field: PSTATEField = (CRm < 0b010) ? .allInt : .pm
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .msrImm,
                category: .branchesExceptionSystem,
                operandCount: sink.emit(.pstateField(field), .unsignedImmediate(value: UInt64(CRm & 1), width: 4)),
            )
        }
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
                operandCount: sink.emit(.pstateField(field), .unsignedImmediate(value: UInt64(CRm), width: 4)),
            )
        }
        let sysreg = SystemRegisterEncoding(
            op0: 0, op1: op1, crn: 4, crm: CRm, op2: op2,
        )
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .msr,
            semanticReads: RegisterSet.empty.inserting(.xzr()),
            category: .branchesExceptionSystem,
            operandCount: sink.emit(.systemRegister(sysreg), .register(.xzr())),
        )
    }
}
