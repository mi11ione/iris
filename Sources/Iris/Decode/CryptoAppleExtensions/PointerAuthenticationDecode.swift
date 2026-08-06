// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum PointerAuthenticationDecode {
    /// PAC standalone in the DPR 1-source slab.
    @_optimize(speed)
    static func decodeOneSource(
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft? {
        if (encoding & 0xFFFF_0000) != 0xDAC1_0000 { return nil }
        let opc6 = UInt8((encoding >> 10) & 0x3F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        switch opc6 {
        case 0b000000 ... 0b000111:
            return registerSourceDraft(
                opcLow3: opc6 & 0b111, Rn: Rn, Rd: Rd,
                encoding: encoding, address: address, &sink,
            )

        case 0b001000 ... 0b001111:
            if Rn != 0b11111 { return nil }
            return zeroSourceDraft(
                opcLow3: opc6 & 0b111, Rd: Rd,
                encoding: encoding, address: address, &sink,
            )

        case 0b010000:
            if Rn != 0b11111 { return nil }
            return xpacDraft(.xpaci, Rd: Rd, encoding: encoding, address: address, &sink)

        case 0b010001:
            if Rn != 0b11111 { return nil }
            return xpacDraft(.xpacd, Rd: Rd, encoding: encoding, address: address, &sink)

        case 0b100000 ... 0b101111:
            return linkRegisterDraft(
                opc6: opc6, Rn: Rn, Rd: Rd, encoding: encoding, address: address, &sink,
            )

        default:
            return nil
        }
    }

    /// FEAT_PAuth_LR `AUTIASPPC` / `AUTIBSPPC` — the PC-relative immediate
    /// forms in the DPI slab. bit 21 selects the key and bits[20:5] carry the
    /// magnitude of a non-positive byte offset.
    @_optimize(speed)
    static func decodeImmediate(
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft? {
        if (encoding & 0xFFC0_001F) != 0xF380_001F { return nil }
        let imm16: UInt32 = (encoding >> 5) & 0xFFFF
        let key: UInt32 = (encoding >> 21) & 1
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: key == 0 ? .autiasppc : .autibsppc,
            semanticReads: RegisterSet.empty.inserting(.x(30)).inserting(.sp()),
            semanticWrites: RegisterSet.empty.inserting(.x(30)),
            flagEffect: .none,
            category: .pointerAuthentication,
            operandCount: sink.emit(.immediate(value: -(Int64(imm16) &* 4), width: 18)),
        )
    }

    /// FEAT_PAuth_LR forms that sign or authenticate LR in place. All require
    /// Rd = LR; only `AUTIASPPCR` / `AUTIBSPPCR` take an Rn operand.
    @inline(__always)
    private static func linkRegisterDraft(
        opc6: UInt8, Rn: UInt8, Rd: UInt8,
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft? {
        if Rd != 0b11110 { return nil }
        let lr = RegisterRef.x(30)
        if opc6 == 0b100100 || opc6 == 0b100101 {
            let rnRef = gprOperand(encoding: Rn, width: .x64, form: .zrOrGeneral)
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: opc6 == 0b100100 ? .autiasppcr : .autibsppcr,
                semanticReads: insertingNonZero(reg: rnRef, into: RegisterSet.empty.inserting(lr)),
                semanticWrites: RegisterSet.empty.inserting(lr),
                flagEffect: .none,
                category: .pointerAuthentication,
                operandCount: sink.emit(.register(rnRef)),
            )
        }
        if Rn != 0b11111 { return nil }
        let mnemonic: Mnemonic = switch opc6 {
        case 0b100000: .pacnbiasppc
        case 0b100001: .pacnbibsppc
        case 0b100010: .pacia171615
        case 0b100011: .pacib171615
        case 0b101000: .paciasppc
        case 0b101001: .pacibsppc
        case 0b101110: .autia171615
        case 0b101111: .autib171615
        default: .undefined
        }
        if mnemonic == .undefined { return nil }
        let usesModifierTriple = opc6 == 0b100010 || opc6 == 0b100011
            || opc6 == 0b101110 || opc6 == 0b101111
        let reads: RegisterSet = usesModifierTriple
            ? RegisterSet.empty.inserting(.x(15)).inserting(.x(16)).inserting(.x(17))
            : RegisterSet.empty.inserting(lr).inserting(.sp())
        let writes: RegisterSet = usesModifierTriple
            ? RegisterSet.empty.inserting(.x(17))
            : RegisterSet.empty.inserting(lr)
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: writes,
            flagEffect: .none,
            category: .pointerAuthentication,
            operandCount: 0,
        )
    }

    /// PACGA in the DPR 2-source slab.
    @_optimize(speed)
    static func decodeTwoSource(
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft? {
        if (encoding & 0xFFE0_FC00) != 0x9AC0_3000 { return nil }
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)
        let rdRef = gprOperand(encoding: Rd, width: .x64, form: .zrOrGeneral)
        let rnRef = gprOperand(encoding: Rn, width: .x64, form: .zrOrGeneral)
        let rmRef = gprOperand(encoding: Rm, width: .x64, form: .spOrGeneral)
        var reads = insertingNonZero(reg: rnRef, into: .empty)
        reads = insertingNonZero(reg: rmRef, into: reads)
        let writes = insertingNonZero(reg: rdRef, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: .pacga,
            semanticReads: reads, semanticWrites: writes,
            flagEffect: .none, category: .pointerAuthentication,
            operandCount: sink.emit(.register(rdRef), .register(rnRef), .register(rmRef)),
        )
    }

    @inline(__always)
    private static func registerSourceDraft(
        opcLow3: UInt8, Rn: UInt8, Rd: UInt8,
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let mnemonic: Mnemonic = switch opcLow3 {
        case 0b000: .pacia
        case 0b001: .pacib
        case 0b010: .pacda
        case 0b011: .pacdb
        case 0b100: .autia
        case 0b101: .autib
        case 0b110: .autda
        default:
            .autdb
        }
        let rdRef = gprOperand(encoding: Rd, width: .x64, form: .zrOrGeneral)
        let rnRef = gprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        var reads = insertingNonZero(reg: rnRef, into: .empty)
        reads = insertingNonZero(reg: rdRef, into: reads)
        let writes = insertingNonZero(reg: rdRef, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            flagEffect: .none, category: .pointerAuthentication,
            operandCount: sink.emit(.register(rdRef), .register(rnRef)),
        )
    }

    @inline(__always)
    private static func zeroSourceDraft(
        opcLow3: UInt8, Rd: UInt8,
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let mnemonic: Mnemonic = switch opcLow3 {
        case 0b000: .paciza
        case 0b001: .pacizb
        case 0b010: .pacdza
        case 0b011: .pacdzb
        case 0b100: .autiza
        case 0b101: .autizb
        case 0b110: .autdza
        default:
            .autdzb
        }
        let rdRef = gprOperand(encoding: Rd, width: .x64, form: .zrOrGeneral)
        let reads = insertingNonZero(reg: rdRef, into: .empty)
        let writes = insertingNonZero(reg: rdRef, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            flagEffect: .none, category: .pointerAuthentication,
            operandCount: sink.emit(.register(rdRef)),
        )
    }

    @inline(__always)
    private static func xpacDraft(
        _ mnemonic: Mnemonic, Rd: UInt8,
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let rdRef = gprOperand(encoding: Rd, width: .x64, form: .zrOrGeneral)
        let reads = insertingNonZero(reg: rdRef, into: .empty)
        let writes = insertingNonZero(reg: rdRef, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            flagEffect: .none, category: .pointerAuthentication,
            operandCount: sink.emit(.register(rdRef)),
        )
    }
}
