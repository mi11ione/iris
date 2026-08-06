// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum MemoryTaggingDecode {
    /// ADDG / SUBG in the DPI add-with-tags row.
    @_optimize(speed)
    static func decodeDPI(
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft? {
        if (encoding & 0xBFC0_0000) != 0x9180_0000 { return nil }
        let isSub = ((encoding >> 30) & 1) == 1
        let uimm6 = UInt8((encoding >> 16) & 0x3F)
        let uimm4 = UInt8((encoding >> 10) & 0xF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)
        let rdRef = gprOperand(encoding: Rd, width: .x64, form: .spOrGeneral)
        let rnRef = gprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        let mnemonic: Mnemonic = isSub ? .subg : .addg
        let reads = insertingNonZero(reg: rnRef, into: .empty)
        let writes = insertingNonZero(reg: rdRef, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            flagEffect: .none, category: .memoryTagging,
            operandCount: sink.emit(.register(rdRef), .register(rnRef), .unsignedImmediate(value: UInt64(uimm6) * 16, width: 10), .unsignedImmediate(value: UInt64(uimm4), width: 4)),
        )
    }

    /// IRG / GMI / SUBP / SUBPS in the DPR 2-source row.
    @_optimize(speed)
    static func decodeDPR(
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft? {
        if (encoding & 0xDFE0_0000) != 0x9AC0_0000 { return nil }
        let S = (encoding >> 29) & 1
        let opc6 = UInt8((encoding >> 10) & 0x3F)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)
        switch opc6 {
        case 0b000000:
            let mnemonic: Mnemonic = (S == 1) ? .subps : .subp
            let rdRef = gprOperand(encoding: Rd, width: .x64, form: .zrOrGeneral)
            let rnRef = gprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
            let rmRef = gprOperand(encoding: Rm, width: .x64, form: .spOrGeneral)
            var reads = insertingNonZero(reg: rnRef, into: .empty)
            reads = insertingNonZero(reg: rmRef, into: reads)
            let writes = insertingNonZero(reg: rdRef, into: .empty)
            return DecodedDraft(
                address: address, encoding: encoding, mnemonic: mnemonic,
                semanticReads: reads, semanticWrites: writes,
                flagEffect: (S == 1) ? .nzcv : .none,
                category: .memoryTagging,
                operandCount: sink.emit(.register(rdRef), .register(rnRef), .register(rmRef)),
            )

        case 0b000100:
            if S != 0 { return nil }
            let rdRef = gprOperand(encoding: Rd, width: .x64, form: .spOrGeneral)
            let rnRef = gprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
            let rmRef = gprOperand(encoding: Rm, width: .x64, form: .zrOrGeneral)
            var reads = insertingNonZero(reg: rnRef, into: .empty)
            reads = insertingNonZero(reg: rmRef, into: reads)
            let writes = insertingNonZero(reg: rdRef, into: .empty)
            return DecodedDraft(
                address: address, encoding: encoding, mnemonic: .irg,
                semanticReads: reads, semanticWrites: writes,
                flagEffect: .none, category: .memoryTagging,
                operandCount: sink.emit(.register(rdRef), .register(rnRef), .register(rmRef)),
            )

        case 0b000101:
            if S != 0 { return nil }
            let rdRef = gprOperand(encoding: Rd, width: .x64, form: .zrOrGeneral)
            let rnRef = gprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
            let rmRef = gprOperand(encoding: Rm, width: .x64, form: .zrOrGeneral)
            var reads = insertingNonZero(reg: rnRef, into: .empty)
            reads = insertingNonZero(reg: rmRef, into: reads)
            let writes = insertingNonZero(reg: rdRef, into: .empty)
            return DecodedDraft(
                address: address, encoding: encoding, mnemonic: .gmi,
                semanticReads: reads, semanticWrites: writes,
                flagEffect: .none, category: .memoryTagging,
                operandCount: sink.emit(.register(rdRef), .register(rnRef), .register(rmRef)),
            )

        default:
            return nil
        }
    }

    /// L/S MTE: LDG / STG / ST2G / STZG / STZ2G / LDGM / STGM / STZGM. Returns
    /// nil if (opc1, op2) is reserved.
    @_optimize(speed)
    static func decodeLS(
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft? {
        if (encoding & 0xFF20_0000) != 0xD920_0000 { return nil }
        let opc1 = UInt8((encoding >> 22) & 0x3)
        let op2 = UInt8((encoding >> 10) & 0x3)
        let imm9 = (encoding >> 12) & 0x1FF
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        switch (opc1, op2) {
        case (0b00, 0b00):
            if imm9 != 0 { return nil }
            return bulkLSDraft(.stzgm, isLoad: false, Rn: Rn, Rt: Rt, encoding: encoding, address: address, &sink)
        case (0b10, 0b00):
            if imm9 != 0 { return nil }
            return bulkLSDraft(.stgm, isLoad: false, Rn: Rn, Rt: Rt, encoding: encoding, address: address, &sink)
        case (0b11, 0b00):
            if imm9 != 0 { return nil }
            return bulkLSDraft(.ldgm, isLoad: true, Rn: Rn, Rt: Rt, encoding: encoding, address: address, &sink)
        case (0b01, 0b00):
            return addressFormDraft(
                mnemonic: .ldg, op2: op2, imm9: imm9, Rn: Rn, Rt: Rt,
                isLoad: true, rtIsSPAllowed: false,
                encoding: encoding, address: address, &sink,
            )
        case (0b00, 0b01), (0b00, 0b10), (0b00, 0b11):
            return addressFormDraft(
                mnemonic: .stg, op2: op2, imm9: imm9, Rn: Rn, Rt: Rt,
                isLoad: false, rtIsSPAllowed: true,
                encoding: encoding, address: address, &sink,
            )
        case (0b01, 0b01), (0b01, 0b10), (0b01, 0b11):
            return addressFormDraft(
                mnemonic: .stzg, op2: op2, imm9: imm9, Rn: Rn, Rt: Rt,
                isLoad: false, rtIsSPAllowed: true,
                encoding: encoding, address: address, &sink,
            )
        case (0b10, 0b01), (0b10, 0b10), (0b10, 0b11):
            return addressFormDraft(
                mnemonic: .st2g, op2: op2, imm9: imm9, Rn: Rn, Rt: Rt,
                isLoad: false, rtIsSPAllowed: true,
                encoding: encoding, address: address, &sink,
            )
        case (0b11, 0b01), (0b11, 0b10):
            return addressFormDraft(
                mnemonic: .stz2g, op2: op2, imm9: imm9, Rn: Rn, Rt: Rt,
                isLoad: false, rtIsSPAllowed: true,
                encoding: encoding, address: address, &sink,
            )
        default:
            return addressFormDraft(
                mnemonic: .stz2g, op2: op2, imm9: imm9, Rn: Rn, Rt: Rt,
                isLoad: false, rtIsSPAllowed: true,
                encoding: encoding, address: address, &sink,
            )
        }
    }

    @inline(__always)
    private static func bulkLSDraft(
        _ mnemonic: Mnemonic, isLoad: Bool, Rn: UInt8, Rt: UInt8,
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let rtRef = gprOperand(encoding: Rt, width: .x64, form: .zrOrGeneral)
        let rnRef = gprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        let mem = MemoryOperand(base: .register(rnRef))
        var reads = insertingNonZero(reg: rnRef, into: .empty)
        var writes: RegisterSet = .empty
        if isLoad {
            writes = insertingNonZero(reg: rtRef, into: writes)
        } else {
            reads = insertingNonZero(reg: rtRef, into: reads)
        }
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            memoryAccess: isLoad ? .load : .store,
            flagEffect: .none, category: .memoryTagging,
            operandCount: sink.emit(.register(rtRef), .memory(mem)),
        )
    }

    @inline(__always)
    private static func addressFormDraft(
        mnemonic: Mnemonic, op2: UInt8, imm9: UInt32, Rn: UInt8, Rt: UInt8,
        isLoad: Bool, rtIsSPAllowed: Bool,
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let writebackKind: Writeback = switch op2 {
        case 0b01: .postIndex
        case 0b10: .none
        case 0b11: .preIndex
        default: .none
        }
        let displacementBytes = signExtend9(imm9) * 16
        let rtForm: RegisterEncodingForm = rtIsSPAllowed ? .spOrGeneral : .zrOrGeneral
        let rtRef = gprOperand(encoding: Rt, width: .x64, form: rtForm)
        let rnRef = gprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        let mem = MemoryOperand(
            base: .register(rnRef),
            displacement: displacementBytes,
            writeback: writebackKind,
        )
        var reads = insertingNonZero(reg: rnRef, into: .empty)
        var writes: RegisterSet = .empty
        if isLoad {
            writes = insertingNonZero(reg: rtRef, into: writes)
            if mnemonic == .ldg {
                reads = insertingNonZero(reg: rtRef, into: reads)
            }
        } else {
            reads = insertingNonZero(reg: rtRef, into: reads)
        }
        if writebackKind != .none {
            writes = insertingNonZero(reg: rnRef, into: writes)
        }
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            memoryAccess: isLoad ? .load : .store,
            flagEffect: .none, category: .memoryTagging,
            operandCount: sink.emit(.register(rtRef), .memory(mem)),
        )
    }
}
